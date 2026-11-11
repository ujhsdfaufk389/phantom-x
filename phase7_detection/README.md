# PHANTOM-X -- Phase 7/8 :: Variants and their detections

This directory holds the variant builds of the payload and the rules that
detect them.

The two go together. A variant that is not detected is a hole; a detection
that is never exercised is a guess. Building both is what makes the pair
worth something.

---

## The experiment

The lab's question is never "does this technique work". It is always:

> **what changes, in what the endpoint sees, when this technique is used?**

That can only be answered by running both arms and comparing. So the lab
builds a **matrix** of arms, one per capability:

| Arm | What it adds |
|---|---|
| `baseline` | nothing. Plain payload, everything visible |
| `obfuscate` | the sensitive strings are encoded, so they are not in the binary |
| `amsi` | AMSI is patched so it reports clean without scanning |
| `etw` | ETW is patched so it returns without tracing |
| `encrypt` | the C2 channel is encrypted, so the protocol is not on the wire |
| `dga` | the C2 address is a generated hostname that changes daily |
| `cred` | credential access against the lab VM |
| `lateral` | movement to a second lab host |
| `full` | everything at once |

**The `full` arm is the one that matters most.** It is the worst case a
defender has to be able to catch, and it is the arm the detection rules are
finally validated against.

---

## Build

```powershell
cd phase3_fileless\loader
.\build_variants.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

The build also **verifies the obfuscation arm**: it scans the compiled
binary for every sensitive literal and reports whether any survived. A
partially obfuscated payload is one where a defender greps for the string
that was missed and finds it immediately.

```
baseline : 11/19 needles visible
obfuscate: no needle found -- the arm is clean
```

---

## The measurements

Each variant answers a specific question. This is what the lab is for.

### Obfuscated strings

> **How much of my detection depends on a plaintext string being present?**

Before the variant, the binary contains `HELLO|`, `RESULT|`, `cmd /c `,
`ws2_32.dll`, `AmsiScanBuffer`, `EtwEventWrite`, `lsass.exe`,
`schtasks.exe` and the environment variable names.

After the variant, none of them are there. The encoding is a per-string
XOR with a key derived from the string's own name, applied at build time
by `tools/gen_strings.py`.

**What survives:** everything that is not a string. The process still
creates a thread, still maps memory, still opens a socket, still writes a
marker file. Rule `px-001` and rule `px-014` still fire.

**What stops:** every rule that matched a string. That is the finding.

### AMSI bypass

> **Does Defender's script scanning contribute to fileless detection?**

`amsi.dll!AmsiScanBuffer` gets a two-byte stub: `xor eax, eax; ret`. It
reports S_OK without scanning anything.

**What survives:** the patch itself. The page becomes writable and
executable, which is rule `px-013`. And the payload's own behaviour is
unchanged, so every behavioural rule still fires.

### ETW unhooking

> **If my detection only works because ETW is intact, how fragile is it?**

`ntdll!EtwEventWrite` gets the same two-byte stub.

This is the most important variant in the lab, and the reason is
uncomfortable: **the detection that depends on ETW is a detection that
depends on the adversary not patching two bytes.** A rule that rides on
ETW is not a rule.

**What survives:** rules that do not depend on ETW -- process creation,
memory access, the network connection. **What stops:** everything ETW
carries.

### Encrypted channel

> **Which of my network detections are keyed on the plaintext of the
> protocol?**

The C2 traffic is XORed against a keystream derived from a shared key.
Each direction has its own stream. Frames are length-prefixed, and the
length is in the clear -- deliberately, because a defender can still see
the size of every message, and the lab can measure how much that alone
gives away.

**What survives:** rules keyed on the traffic's shape -- timing, size,
direction changes. Rule `px-011`. **What stops:** every rule that
matched the plaintext protocol.

The cipher is not cryptography in the security sense, and it is not meant
to be. It has to be simple enough that the lab's own traffic analyser can
decode it, because an opaque channel that nobody can decode produces no
measurement.

### Domain generation

> **Does my C2 detection depend on a single fixed address?**

The hostname is derived from the day number, so it changes daily:
`pxlab-20768-5a17c0de.lab.test`.

The lab's DNS helper (`phase5_network/dga_dns.py`) resolves those names
inside the isolated segment and returns NXDOMAIN for everything else --
because the interesting signal of a DGA is the pattern of many unique
subdomains being queried, most of which resolve to nothing.

**What survives:** rules keyed on DNS behaviour. Rule `px-012`.

### Credential access

> **What does credential access look like in telemetry?**

The payload opens `lsass.exe` with `PROCESS_VM_READ` and reads a window of
its address space.

**It does not send the credential material to the C2 server.** The report
it returns is a redacted summary: how many credential-shaped blocks were
found, and a masked sample. The reason is specific and worth stating:

> The lab's C2 server is a plain TCP listener. If the operator runs it on
> a routable address -- and running a C2 somewhere reachable is the entire
> point of a C2 -- then a payload that ships real credential material
> there has handed those credentials to whoever can reach that address
> too. The operator has not stolen anything, but the credentials have
> effectively been published to the network.

The detection question does not need the contents. "Does opening LSASS
with VM_READ generate the telemetry I expect?" is answered by the access
itself -- Sysmon EventID 10, the handle, the memory reads. It is not
answered by what was in there.

**What survives:** everything. This is the most detectable capability in
the lab, which is the point of including it. Rule `px-009`.

### Lateral movement

> **What does movement look like on the TARGET host?**

The payload creates a service on one explicitly named host, supplied by
the operator. One host. No scanning, no target list, no propagation.

A payload that moves itself is a worm. A worm on a lab segment reaches
every lab host the moment the operator forgets to clean up, and the
lab's telemetry becomes unrepeatable.

**The interesting telemetry is on the target, not on the host that
initiated it.** A single-host lab cannot see this at all, which is why
the lab needs a second VM.

**What survives:** the service-creation event (7045) and the SMB write to
ADMIN$. Rule `px-010`.

---

## The capability report

Every payload sends a CAPS line immediately after HELLO:

```
CAPS|0x5f
```

The server records it in the audit log with a readable form, because a
mask on its own tells a future reader nothing months later:

```json
{"kind": "capabilities", "mask": "0x5f",
 "capabilities": "obfuscated,amsi_bypass,etw_unhooked,encrypted_channel,domain_generation"}
```

Without this, every session in the audit log looks identical and the
comparison between arms is impossible.

The bits:

| Bit | Capability |
|---|---|
| 0x01 | obfuscated strings |
| 0x02 | AMSI bypass applied |
| 0x04 | ETW unhooked |
| 0x08 | encrypted channel |
| 0x10 | domain generation |
| 0x20 | credential access capability present |
| 0x40 | lateral movement capability present |

---

## The detections

| ID | Rule | Detects |
|---|---|---|
| px-009 | Process access to LSASS with VM_READ | the credential arm |
| px-010 | Remote service created over SMB | the lateral arm |
| px-011 | Encrypted C2 channel | the encrypted arm |
| px-012 | High ratio of unique subdomains with NXDOMAIN | the DGA arm |
| px-013 | Writable and executable page in a signed module | the AMSI and ETW arms |
| px-014 | Packed or encrypted payload | the obfuscated arm |

The rules are written so that they key on **behaviour**, not on a
string. That is deliberate: a rule that keys on a string stops working
the moment the string is encoded, and a rule that keys on behaviour keeps
working.

---

## Running the comparison

```powershell
python run_all_tests.py
```

The suite builds nothing; it checks what is already built. To rebuild the
arms first:

```powershell
cd phase3_fileless\loader
.\build_variants.ps1
```

---

## What the lab is measuring, one more time

The variants exist to find out where the DETECTIONS are weak. A rule that
fires on every arm is a rule worth having. A rule that fires only on the
baseline arm was riding on something the variant removed, and it is a
finding about the rule -- not about the payload.

That is the whole method. The payload is the instrument. The rules are
the output.
