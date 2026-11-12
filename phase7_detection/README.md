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
| `resilient` | reconnects with backoff when the network changes under it |
| `xfer` | file download and screen capture |
| `caps` | the capability library -- fourteen techniques, one at a time |
| `full` | everything at once |

**The `full` arm is the one that matters most.** It is the worst case a
defender has to be able to catch, and it is the arm the detection rules are
finally validated against.

---

## The technique catalogue

The rules are the half of the story that says what can be **detected**. The
catalogue is the half that says what the lab can **do** -- and, more
usefully, what it does not do.

```powershell
phase7_detection\target\release\px_detect.exe --catalog-summary
```

```
  techniques in scope : 93
  measured            : 65
  ruled only          : 6
  not exercised       : 22
  of which campaigns  : 4
```

Three statuses:

| Status | What it means |
|---|---|
| `measured` | The lab exercises the technique, so the telemetry is real and the rule has been tested against it. |
| `ruled` | A rule exists, but nobody has watched it fire. A rule that has never fired is a hypothesis. |
| `not_exercised` | Neither. The lab says nothing about it, and the catalogue says so. |

The **campaigns** -- ransomware, wiper, cryptojacking, botnet -- are listed
as campaigns rather than techniques. A ransomware run is a hundred
techniques executed in an order; no single capability in a single binary is
"ransomware", and pretending otherwise would have made the denominator a
lie.

The catalogue is structured data in `src/catalog.rs`, and the evaluator's
test suite checks that every rule it names actually exists and that every
technique a rule claims to cover is in the catalogue. A catalogue entry that
names a rule which does not exist would make the coverage matrix claim a
technique is covered when nothing detects it.

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
| 0x80 | the technique capability library is compiled in |

The mask is sent as **hex**. It used to be sent as decimal while the server
read it as hex, and nothing noticed: the baseline reports 0, which is the
same in both, and the credit arm reported 32, which the server read as
`0x32`. The variant test now compares the reported mask against what the
build should have said, so the next one cannot pass unnoticed.

---

## The capability library

Twenty-two techniques, one table, one verb.

```
CAP|<cmd_id>|<technique>|<arguments>
```

The server sends the command, the payload looks the name up in the table,
runs it, and answers with a `RESULT` line carrying the command id back. The
id is what lets the server correlate the answer with the request -- without
it, two capabilities in flight are indistinguishable.

```
  c2> cap 1 list
  <- session 1: the capabilities compiled into this build: inject, token,
     keylog, clip, persist, antifor, recon, lolbin, script, dnstun, steg,
     spoof, delay, antivm, service, schtask, com, elev, proxy, ps, stage,
     browser

  c2> cap 1 recon sysinfo
  <- session 1: host=DESKTOP-TD3A3HK os=6.2.9200 build=9200 arch=9 cpus=24
```

The bounds are in the source, next to each technique, and they are the same
bounds the rest of the lab has: the injection targets a process the operator
names, the port scan touches one named host, the persistence writes a key or
a subscription on the lab machine and reports the command that removes it,
and the keylogger records keys typed into the lab VM.

The techniques that change the machine **put it back**: the service, the
scheduled task, the COM class, the auto-elevate key and the proxy setting
are all removed again, and the report says how. The browser capability
opens a credential store and does **not** read it -- the file open is the
telemetry, and the contents stay on the machine.

The library is a **separate build flag**, so the `caps` arm exists alongside
the baseline and the delta in telemetry is measurable. A capability that is
not compiled in cannot be detected, and "present but disabled" is not the
same thing as "not present".

**One limitation, stated rather than hidden:** the string table covers the
*protocol* vocabulary. The literals inside the capability library -- the
registry paths, the service name, the command lines -- are not in it, so
they are visible in the binary. The obfuscation arm therefore measures what
the string table can do, and the capability arm is **not** a clean
measurement of a payload with no readable strings.

---

## The detections

Fifty rules. The first fourteen cover the chain and the original variant
arms; the rest cover the capability library.

| ID | Rule | Detects |
|---|---|---|
| px-009 | Process access to LSASS with VM_READ | the credential arm |
| px-010 | Remote service created over SMB | the lateral arm |
| px-011 | Encrypted C2 channel | the encrypted arm |
| px-012 | High ratio of unique subdomains with NXDOMAIN | the DGA arm |
| px-013 | Writable and executable page in a signed module | the AMSI and ETW arms |
| px-014 | Packed or encrypted payload | the obfuscated arm |
| px-015 | Process opened with all access and thread rights | process injection |
| px-016 | Memory written in another process | process injection |
| px-017 | Token of another process duplicated or used | token theft |
| px-018 | Running image renamed to a known system binary | masquerading |
| px-019 | Command line does not match the image on disk | argument spoofing |
| px-020 | Parent process changed after the process started | PPID spoofing |
| px-021 | Registry Run key written | Run-key persistence |
| px-022 | WMI event subscription created | fileless persistence |
| px-023 | Scheduled task created with an inline command | scheduled-task persistence |
| px-024 | Service created with a binary in a user-writable directory | service persistence |
| px-025 | Windows event log cleared | log clearing |
| px-026 | Running image deleted or renamed away | self-deletion |
| px-027 | File timestamps set far in the past | timestomp |
| px-028 | Clipboard read or replaced | clipboard monitoring |
| px-029 | Screen capture bitmap written by a non-shell process | screen capture |
| px-030 | Camera or microphone opened by an unusual process | webcam and microphone |
| px-031 | System information gathered by a non-administrative tool | reconnaissance |
| px-032 | Connections to many ports on one host | port scanning |
| px-033 | Signed script host running a script from a user directory | script host abuse |
| px-034 | System binary proxy execution | living off the land |
| px-035 | Encoded command line | encoding |
| px-036 | DNS query carrying data in the subdomain | DNS tunnelling |
| px-037 | File staged and sent to a remote listener | file transfer |
| px-038 | Data appended after the end of an image file | steganography |
| px-039 | Process checks for a debugger before doing its work | anti-analysis |
| px-040 | Process waits before it does anything | delayed execution |
| px-041 | Process checks whether the machine is domain joined | environment-aware execution |
| px-042 | Security account manager hive opened | credential access, hive method |
| px-043 | Credential material read out of the LSASS process | credential access, memory method |
| px-044 | Data staged and compressed before it leaves | data staging |
| px-045 | AmsiScanBuffer overwritten in memory | the AMSI bypass, by name |
| px-046 | EtwEventWrite patched to return immediately | the ETW unhook, by name |
| px-047 | Office application spawning a script host or a shell | macro execution |
| px-048 | Malicious object linked from a document | malicious OLE |
| px-049 | Keyboard input state polled by a non-shell process | keylogging |
| px-050 | Remote service created over the network | remote execution |
| px-051 | COM class registered to an unusual server path | COM hijacking |
| px-052 | Auto-elevate registry key written | UAC bypass |
| px-053 | System proxy changed by an unusual process | proxying |
| px-054 | Browser credential store opened | browser credentials |

The rules are written so that they key on **behaviour**, not on a
string. That is deliberate: a rule that keys on a string stops working
the moment the string is encoded, and a rule that keys on behaviour keeps
working.

### Two blocks

A selection block ORs its matchers, so it can only ever say "one of these
fields matched". A rule that needs "a remote write *into a process* rather
than a remote write somewhere" needs two blocks, and the second one is
`selection_and`, which is ANDed with the first.

Most rules need only one block, because the most characteristic field is
enough on its own -- and that is the better rule, since every extra
condition is another chance for the rule to miss.

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
