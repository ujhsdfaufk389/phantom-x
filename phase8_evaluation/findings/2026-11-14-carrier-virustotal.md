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

## Reproducing it

The local endpoint's verdict, which is the same engine and predates the
submission:

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
