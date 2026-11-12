// =============================================================================
// PHANTOM-X :: Phase 5 -- the capability library test
// =============================================================================
// caps_test.go -- Drives the capability library against the Go server.
//
// WHAT IS TESTED
//
//     1. The server can ask a session to run a technique, and the answer
//        comes back correlated with the request.
//     2. The answer says WHICH technique ran, so the audit log is
//        readable months later.
//     3. The capability list is retrievable, so an operator can find out
//        what a build can do before asking it to do anything.
//
// WHY THE CORRELATION MATTERS
//
//     The capability verb carries a command id and the payload echoes it
//     back. Without it the server could only record "a capability ran",
//     which is not enough to tell two capabilities apart when they run
//     at the same time. This test checks the id survives the round trip.
//
// -----------------------------------------------------------------------------

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findCapabilityBuild locates a payload build with the capability library.
func findCapabilityBuild(t *testing.T) string {
	t.Helper()
	if p := *flagVariant; p != "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatalf("cannot resolve %q: %v", p, err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("variant payload not found: %s", abs)
		}
		return abs
	}
	for _, rel := range []string{
		"..\\dist\\variants\\px_payload_caps.exe",
		"..\\dist\\variants\\px_payload_full.exe",
	} {
		abs, _ := filepath.Abs(rel)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("no capability-capable payload found; build the caps arm")
	return ""
}

// TestCapabilityCommand runs one technique and checks the answer.
func TestCapabilityCommand(t *testing.T) {
	payload := findCapabilityBuild(t)
	if payload == "" {
		return
	}

	port := 9441
	work := t.TempDir()
	logpath := filepath.Join(work, "audit.jsonl")

	srv := newServer("127.0.0.1", port, logpath, false, 0)
	ln, err := listenLocal(port)
	if err != nil {
		t.Fatalf("cannot bind: %v", err)
	}
	go srv.acceptLoop(ln)
	defer srv.shutdown()
	time.Sleep(300 * time.Millisecond)

	cmd := exec.Command(payload)
	cmd.Env = append(os.Environ(),
		"PX_C2_HOST=127.0.0.1",
		fmt.Sprintf("PX_C2_PORT=%d", port),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start payload: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	sess := waitForSession(srv, 20*time.Second)
	if sess == nil {
		t.Fatal("the payload never connected")
	}

	// The list. It is the one capability that touches nothing, so it is
	// the safest one to ask for first.
	res := srv.capability(sess, "list", "", 20*time.Second)
	if res == nil {
		t.Fatal("the capability list did not come back")
	}
	if !strings.Contains(res.Output, "inject") {
		t.Fatalf("the capability list does not mention the techniques:\n%s",
			res.Output)
	}
	t.Logf("capability list: %s", firstLine(res.Output))

	// A technique that runs and reports something.
	//
	// The reconnaissance one is used because it reads the machine the
	// payload is running on, which always works, and it does not
	// change anything.
	res = srv.capability(sess, "recon", "sysinfo", 30*time.Second)
	if res == nil {
		t.Fatal("the recon capability did not come back")
	}
	if !strings.Contains(res.Output, "host=") {
		t.Fatalf("the recon capability did not report the host:\n%s",
			res.Output)
	}
	t.Logf("recon: %s", firstLine(res.Output))

	// The audit log must name the technique, or the run is unreadable
	// later.
	rec := findAuditRecordWhere(t, logpath, "capability", "technique", "recon")
	if rec == nil {
		t.Fatal("no capability record for the recon technique was written")
	}
	if args, _ := rec["args"].(string); args != "sysinfo" {
		t.Fatalf("the audit log says the arguments were %q, expected \"sysinfo\"",
			args)
	}
}

// TestCapabilityUnknown checks that an unknown technique is answered
// rather than ignored.
//
// A capability command that got no answer at all would look like a
// timeout, and a timeout looks like a broken payload. The answer has to
// say "I do not know that technique" so the operator can tell the
// difference.
func TestCapabilityUnknown(t *testing.T) {
	payload := findCapabilityBuild(t)
	if payload == "" {
		return
	}

	port := 9442
	work := t.TempDir()

	srv := newServer("127.0.0.1", port, filepath.Join(work, "audit.jsonl"),
		false, 0)
	ln, err := listenLocal(port)
	if err != nil {
		t.Fatalf("cannot bind: %v", err)
	}
	go srv.acceptLoop(ln)
	defer srv.shutdown()
	time.Sleep(300 * time.Millisecond)

	cmd := exec.Command(payload)
	cmd.Env = append(os.Environ(),
		"PX_C2_HOST=127.0.0.1",
		fmt.Sprintf("PX_C2_PORT=%d", port),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start payload: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	sess := waitForSession(srv, 20*time.Second)
	if sess == nil {
		t.Fatal("the payload never connected")
	}

	res := srv.capability(sess, "no_such_technique", "", 20*time.Second)
	if res == nil {
		t.Fatal("an unknown technique produced no answer at all")
	}
	if !strings.Contains(strings.ToLower(res.Output), "unknown") {
		t.Fatalf("an unknown technique was not reported as unknown:\n%s",
			res.Output)
	}
	t.Logf("unknown technique answered: %s", firstLine(res.Output))
}

// firstLine is a tiny helper, so the test output stays readable.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
