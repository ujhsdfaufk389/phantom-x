// =============================================================================
// PHANTOM-X :: Phase 5 -- variant support for the lab C2 server
// =============================================================================
// variants.go -- The server side of the lab's variant capabilities.
//
// WHY THE SERVER HAS TO KNOW
//     The payload sends a CAPS line immediately after HELLO, reporting
//     which variant build it is. The server records that in the audit log,
//     and it is what makes the comparison between a baseline run and a
//     variant run possible at all.
//
//     Without it, every session in the audit log looks identical and there
//     is no way to say "this detection fired on the baseline arm and not
//     on the obfuscated arm" -- which is the entire experiment.
//
// WHAT THE SERVER DOES WITH EACH CAPABILITY
//
//     CAPS_ENCRYPTED   the server expects framed, encrypted traffic. The
//                      keystream is derived from the shared key exactly
//                      as the payload derives it, so the server can
//                      still read the traffic. That is deliberate: a
//                      channel that the operator cannot read produces no
//                      measurement. The server also records that the
//                      traffic on the wire was opaque, so the audit log
//                      shows both what was said and that it was said
//                      opaquely.
//
//     CAPS_DGA         the server records the resolved address, so the
//                      lab can confirm that the DGA variant really did
//                      connect to a different name rather than to the
//                      compiled-in address.
//
//     CAPS_CRED        a credential collection request is logged with
//                      the REDACTED report the payload sends. The report
//                      contains counts and a masked sample; it does not
//                      contain secret material, and the server does not
//                      need it to.
//
//     CAPS_LATERAL     a movement request is logged with its target.
//
// -----------------------------------------------------------------------------

package main

import (
	"fmt"
	"strings"
)

// The capability bits. These must match px_config.h in the payload.
const (
	CapObfuscated = 0x01
	CapAMSI       = 0x02
	CapETW        = 0x04
	CapEncrypted  = 0x08
	CapDGA        = 0x10
	CapCred       = 0x20
	CapLateral    = 0x40
)

// CapabilityNames renders the mask as a readable list, for the audit log.
//
// A mask on its own is unreadable months later. "0x4f" in a log file
// tells a future reader nothing; "obfuscated+amsi+etw+encrypted+dga"
// tells them exactly which arm produced the session.
func CapabilityNames(mask uint32) []string {
	out := []string{}
	add := func(bit uint32, name string) {
		if mask&bit != 0 {
			out = append(out, name)
		}
	}
	add(CapObfuscated, "obfuscated")
	add(CapAMSI, "amsi_bypass")
	add(CapETW, "etw_unhooked")
	add(CapEncrypted, "encrypted_channel")
	add(CapDGA, "domain_generation")
	add(CapCred, "credential_access")
	add(CapLateral, "lateral_movement")
	return out
}

// CapabilitySummary renders the mask for the console.
func CapabilitySummary(mask uint32) string {
	names := CapabilityNames(mask)
	if len(names) == 0 {
		return "baseline"
	}
	return strings.Join(names, ",")
}

// ParseCapabilities reads a CAPS line and returns the mask.
//
// A malformed CAPS line is treated as "baseline" rather than as an
// error: the point of the CAPS line is to describe the arm, and an
// arm that cannot describe itself should be assumed to be the
// comparison arm until proven otherwise.
func ParseCapabilities(line string) uint32 {
	parts := strings.SplitN(line, "|", 2)
	if len(parts) < 2 {
		return 0
	}
	var mask uint32
	fmt.Sscanf(strings.TrimSpace(parts[1]), "%x", &mask)
	return mask
}
