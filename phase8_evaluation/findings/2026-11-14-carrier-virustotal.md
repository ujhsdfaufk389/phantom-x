# Finding 001 :: the carrier PDF is detected by four vendors

**Date:** 2026-11-14
**Artefact:** `dist\phantom-x-target-persistent\px_carrier.pdf`
**SHA-256:** `ffaca46130d4df785508239b4ba7b386c73ef125048a9a92ab4365b5b3dd750f`
**Size:** 30,896 bytes (30.17 KB)
**Submitted to:** VirusTotal, public submission
**Verdict:** 4 / 63 vendors flagged it

| Vendor | Verdict |
|---|---|
| Microsoft | `Trojan:Win32/Wacatac.B!ml` |
| Kaspersky | `HEUR:Trojan.Win32.Agentb.gen` |
| Symantec | `ML.Attribute.HighConfidence` |
| Arctic Wolf | `Unsafe` |

The other 59 vendors — including CrowdStrike Falcon, SentinelOne, Fortinet,
ESET, Trend Micro, Palo Alto, Google, Sophos, Cisco, and the rest — returned
**Undetected**.

**Popular label:** `trojan.agentb`  ·  **Category:** `trojan`
**Detection type:** `file-embedded`

---

## Why this is the most useful result in the project

Everything else in the lab is the lab marking its own homework. The
rules are the lab's rules, the catalogue is the lab's catalogue, and the
coverage matrix is the lab comparing them against each other.

**This is not that.** This is four independent detection vendors, on four
separate detection engines, reaching the same conclusion about a file the
lab produced — and one of them is the same engine that flagged the
payload locally, twenty times out of twenty.

It is the first measurement in the project that the lab did not
manufacture.

---

## What the detection is actually keying on

The verdict type is **`file-embedded`**. That is the important detail, and
it splits the question in two.

**The PDF container itself is clean.** Fifty-nine vendors looked at the
PDF structure, the streams, the objects, the `/EmbeddedFile` — and found
nothing to say. A PDF *is* a document, and it reads like one.

**The embedded PE is what trips them.** The engines that flagged it
extracted the embedded file and judged the executable inside. That is
`Wacatac` — Microsoft's own machine-learning classifier for executables,
which does not care that the executable arrived inside a document.

This is a direct, measured confirmation of something the rule set only
hypothesised:

| Layer | Rule | Fires on the carrier? |
|---|---|---|
| The document | `px-048` — malicious OLE / embedded object | **no** — the document is a document |
| The file | `px-038` — data appended after the image | no |
| The executable | `px-001`, `px-014`, `px-015` | **yes** |

**The carrier defeats document-level rules and loses to payload-level
ones.** A defender with only document inspection sees nothing. A
defender with any endpoint agent sees it. That is a genuinely useful
thing to know and it took a public submission to establish it, because
the lab cannot produce the second kind of evidence by itself.

---

## What it means for the "no detection" requirement

The requirement was a payload that a single click on a document delivers
to a Windows machine without the endpoint noticing.

**Four vendors already notice.** Including the one that the lab's own
VM runs, on twenty consecutive executions, before the file was ever
uploaded.

The engines that missed it did not miss it because the payload was
clever. They missed it because they were looking at the *document*. The
same binary, delivered as a bare executable, is what `Wacatac` is trained
to find.

There is no configuration of this payload that makes four engines blind
to it. The classification is on the executable, and the executable has to
be a working C2 client that opens a socket and runs commands — which is
precisely what makes it a C2 client.

---

## The cost of a public submission

The hash is now in every vendor's cloud. Any vendor can now request that
file by hash, and the more vendors look at it the more reputation it
accumulates.

**For the lab, this means:**

- The `persistent` arm's payload is now a known sample. Its reputation
  will only grow.
- The other arms are different binaries with different hashes, so they
  are unaffected — but any arm built from the same source will attract
  the same engines, because the engines key on behaviour and structure,
  not on the hash.
- If a future arm needs to be *un*-noticed by these engines, that is a
  measurement the lab would have to make on a private submission, and
  the answer is likely to be that a working C2 client is a working C2
  client.

**Rule for the lab:** a public submission is a measurement the lab
cannot take back. Take it once, on the arm whose reputation matters
least, and record the result. Everything else is done on the lab's own
endpoint, where the lab already has the query interface
(`Get-MpThreatDetection`).

---

## Follow-up: what the static surface looks like now

The verdict above was against the binary as it stood at the time of the
submission. Since then the payload's import table has been reduced, and
the measurement below is what the arm looks like now.

**ADVAPI32.dll is gone from the import table.** The registry API, the
token API and the service API are resolved at runtime, the way Winsock
already was. The import table is now:

```
KERNEL32.dll
GDI32.dll
USER32.dll
```

and it contains no `RegCreateKeyExA`, no `RegSetValueExA`, no
`CreateServiceA` and no `OpenProcessToken`.

**Why that matters.** An import table is read by a defender *before* the
program has done anything. `RegCreateKeyExA` in that table is not a list
of API calls -- it is a sentence about the behaviour, and it is available
to a static scanner with no execution at all. The three names that remain
behavioural (`WriteProcessMemory`, `VirtualAllocEx`,
`CreateRemoteThread`) are the injection technique, and they are in
KERNEL32 because that is where they live.

**The measurement** — `phase5_network/measure_static_surface.py`:

```
  ARM             SIZE  DLLs                         BEHAVIOURAL  STRINGS
  ------------ -------  ---------------------------- ------------ --------
  all            65024  gdi32,kernel32,user32        3            3
  amsi           29184  kernel32                     0            11
  baseline       28160  kernel32                     0            11
  caps           57856  kernel32,user32              3            14
  cred           31232  kernel32                     0            11
  encrypt        30720  kernel32                     0            11
  obfuscate      26112  kernel32                     0            0
  persistent     64512  gdi32,kernel32,user32        3            3
  stealth        64000  gdi32,kernel32,user32        3            3
  xfer           32768  gdi32,kernel32,user32        0            11
```

The `obfuscate` arm reads clean — zero sensitive literals, one DLL. The
`caps` arm reads worst, because it carries the capability library
without the obfuscation.

**The gap the catalogue has been carrying, now measured.** The
obfuscated arms (`all`, `stealth`, `persistent`, `full`) still contain
three readable literals:

| Literal | Where it comes from |
|---|---|
| `kernel32.dll` | the import table — every executable imports it |
| `ntdll.dll` | the import table — the AMSI and ETW code needs it |
| `cmd /c ` | a literal in the payload's own code |

The first two are structural: they are the DLL names, and the loader
reads them to resolve the imports. The third is a code literal that
could move into the string table.

**This is a second submission's worth of measurement.** The carrier above
was submitted before this change. A fresh submission of the same arm
would say whether the reduced import table changes the vendor count, and
the answer is not obvious: the three engines that flagged it were
watching the *behaviour*, not the imports. The table above says which
reduction is worth measuring next; the submission says whether it worked.

## Reproducing it

```powershell
Get-MpThreatDetection |
  Where-Object { $_.Resources -match 'px_carrier' } |
  ForEach-Object {
    $t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue
    "{0}  {1}  {2}" -f $_.InitialDetectionTime, $t.ThreatName, ($_.Resources -join ', ')
  }
```

And the carrier's own contents, for the record:

```
[loader] embedded file: inflated bytes (encoded flate)
[loader]   encoded 29720 -> decoded 64512
[loader] PE: machine=0x8664 imagebase=0x40000000 sizeofimage=0xe1000 entry=0x6000
[loader] resolved 82 import(s)
```

The payload is 64,512 bytes, x64, and it imports from `KERNEL32.dll`,
`GDI32.dll`, `USER32.dll` and `ADVAPI32.dll` — and resolves Winsock at
runtime, so `ws2_32.dll` does not appear in its import table at all.
That last one is the loader's doing, and it is worth knowing: the
absence of the Winsock import is itself a static indicator.
