#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: the endpoint's own defences, from the defender's side
===============================================================================
check_endpoint_hooks.py -- Looks for the traces that three well-known
evasion techniques leave, on the machine they are supposed to hide from.

WHY THIS EXISTS
    Three techniques are famous for hiding a program from an endpoint:

        1. kernel callbacks      ObRegisterCallbacks, which filters the
                                  process, thread and image events that
                                  an EDR agent subscribes to
        2. direct syscalls       hand-built syscall stubs, which skip
                                  the usermode hooks in ntdll
        3. ntdll unhooking       remapping ntdll from disk, which
                                  removes the hooks the EDR installed

    The lab does not implement any of them, and the reason is worth
    stating: there is no EDR on the lab machine to evade. A technique
    that hides nothing is a technique the lab cannot measure, and a
    capability whose only value is on someone else's machine is not a
    research instrument.

    What IS worth having is the other half of the problem: the checks a
    defender runs to find out that one of these techniques has been
    used. That is the mirror image, and it is the half that belongs in a
    detection lab.

WHAT IT CHECKS

    1. Is ntdll hooked?
       The bytes of a set of ntdll exports are compared between the
       file on disk and the copy in memory. A difference means somebody
       patched the function -- which is what both the direct-syscall
       and the unhooking techniques depend on, and what a legitimate
       product does not do.

    2. Are there hand-built syscall stubs?
       A pattern search over a process's committed memory for
       "mov eax, <number>; syscall". A stub like that is a direct
       syscall, and there is no legitimate reason for one to exist in
       a process.

    3. Which kernel-mode filters are registered?
       The service registry gives the kernel drivers and the file
       system filter drivers, and FltMgr's instance list gives the
       minifilters with their altitudes. A filter from an EDR vendor
       is the thing that would see a callback-filtered process.

    4. Is there a way to know about kernel callbacks at all?
       Not from user mode. Enumerating the registered callbacks needs
       a kernel driver, and this script says so rather than pretending.

USAGE
    python3 check_endpoint_hooks.py
    python3 check_endpoint_hooks.py --pid 1234 --json report.json
    python3 check_endpoint_hooks.py --pid 1234 --scan-mb 512
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import sys
from ctypes import wintypes

# ---------------------------------------------------------------------------
# The Windows API, resolved the way the lab's other tools do it
# ---------------------------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                      wintypes.LPVOID, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                    ctypes.c_void_p, ctypes.c_size_t]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.GetSystemInfo.restype = wintypes.BOOL
kernel32.GetSystemInfo.argtypes = [ctypes.c_void_p]

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

# The exports compared between the disk copy and the loaded copy. These
# are the ones a security product patches most often, and they are
# stable across Windows versions.
#
# NtSetInformationProcess and NtProtectVirtualMemory are the ones an
# EDR hooks for process and memory operations; NtWriteVirtualMemory and
# NtCreateThreadEx for injection; NtOpenProcess and
# NtAllocateVirtualMemory for the handle and the allocation.
WATCHED_EXPORTS = [
    "NtAllocateVirtualMemory",
    "NtOpenProcess",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtProtectVirtualMemory",
    "NtSetInformationProcess",
]

# The modules and the exports worth comparing.
#
# EtwEventWrite is in ntdll, and it is the one the lab's OWN ETW arm
# patches -- so a scan that does not watch it cannot find the lab's own
# evasion. AmsiScanBuffer is in amsi, and it is the one the AMSI arm
# patches.
WATCHED_MODULES = [
    ("ntdll.dll", WATCHED_EXPORTS),
    ("ntdll.dll", ["EtwEventWrite"]),
    ("amsi.dll", ["AmsiScanBuffer"]),
]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# ---------------------------------------------------------------------------
# 1. Is ntdll hooked?
# ---------------------------------------------------------------------------

def _read_disk(path):
    with open(path, "rb") as fh:
        return fh.read()


def _pe_sections(blob):
    """(name, virtual_address, virtual_size, raw_offset, raw_size) each."""
    e_lfanew = int.from_bytes(blob[0x3C:0x40], "little")
    pe = e_lfanew
    num_sections = int.from_bytes(blob[pe + 6:pe + 8], "little")
    opt_size = int.from_bytes(blob[pe + 20:pe + 22], "little")
    sec = pe + 24 + opt_size
    out = []
    for i in range(num_sections):
        off = sec + i * 40
        name = blob[off:off + 8].rstrip(b"\x00").decode("latin-1")
        vsize = int.from_bytes(blob[off + 8:off + 12], "little")
        va = int.from_bytes(blob[off + 12:off + 16], "little")
        rsize = int.from_bytes(blob[off + 16:off + 20], "little")
        roff = int.from_bytes(blob[off + 20:off + 24], "little")
        out.append((name, va, vsize, roff, rsize))
    return out


def _rva_to_offset(sections, rva):
    for _name, va, vsize, roff, rsize in sections:
        if va <= rva < va + max(vsize, rsize):
            return roff + (rva - va)
    return None


def _export_rvas(blob):
    """name -> RVA, for the exported functions."""
    e_lfanew = int.from_bytes(blob[0x3C:0x40], "little")
    pe = e_lfanew
    opt = pe + 24
    magic = int.from_bytes(blob[opt:opt + 2], "little")
    dd = opt + (112 if magic == 0x20B else 96)
    exp_rva = int.from_bytes(blob[dd:dd + 4], "little")
    if not exp_rva:
        return {}
    exp_off = _rva_to_offset(_pe_sections(blob), exp_rva)
    if exp_off is None:
        return {}
    nfuncs = int.from_bytes(blob[exp_off + 20:exp_off + 24], "little")
    nnames = int.from_bytes(blob[exp_off + 24:exp_off + 28], "little")
    afunc = int.from_bytes(blob[exp_off + 28:exp_off + 32], "little")
    anames = int.from_bytes(blob[exp_off + 32:exp_off + 36], "little")
    aords = int.from_bytes(blob[exp_off + 36:exp_off + 40], "little")

    def arr(base, idx, size):
        o = base + idx * size
        return int.from_bytes(blob[o:o + size], "little")

    out = {}
    for i in range(nnames):
        name_rva = arr(anames, i, 4)
        name_off = _rva_to_offset(_pe_sections(blob), name_rva)
        if name_off is None:
            continue
        end = blob.index(b"\x00", name_off)
        name = blob[name_off:end].decode("latin-1")
        ordinal = arr(aords, i, 2)
        func_rva = arr(afunc, ordinal, 4)
        out[name] = func_rva
    return out


def check_module_hooks(dll_name, export_names, system_dir=None):
    """Compare one module on disk with the copy in memory.

    The module does not have to be loaded in this process: the point is
    to compare the FILE with what is loaded SOMEWHERE, so the check
    looks at the running process it is given, and this process's own
    copy is used only when it is the one being asked about.
    """
    system_dir = system_dir or os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(system_dir, "System32", dll_name)
    result = {"module": dll_name, "path": path, "exports": {},
              "hooked": [], "loaded": False}

    try:
        blob = _read_disk(path)
    except OSError as exc:
        result["error"] = str(exc)
        return result

    sections = _pe_sections(blob)
    exports = _export_rvas(blob)

    for name in export_names:
        rva = exports.get(name)
        if not rva:
            result["exports"][name] = {"status": "not exported"}
            continue
        disk_off = _rva_to_offset(sections, rva)
        if disk_off is None:
            result["exports"][name] = {"status": "no file offset"}
            continue
        disk_bytes = blob[disk_off:disk_off + 16]

        try:
            mod = ctypes.WinDLL(dll_name)
            live = ctypes.cast(getattr(mod, name), ctypes.c_void_p).value
        except (AttributeError, OSError):
            result["exports"][name] = {"status": "module not loaded here"}
            continue

        result["loaded"] = True
        mem_bytes = ctypes.string_at(live, 16)
        same = disk_bytes == mem_bytes
        result["exports"][name] = {
            "rva": hex(rva),
            "disk": disk_bytes[:8].hex(),
            "memory": mem_bytes[:8].hex(),
            "same": same,
        }
        if not same:
            result["hooked"].append(name)
    return result


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE,
                                    ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE,
                                   ctypes.POINTER(MODULEENTRY32W)]


def _module_bases(pid):
    """The base address of every module in a process."""
    bases = {}
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap == -1:
        return bases
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
    if kernel32.Module32FirstW(snap, ctypes.byref(entry)):
        while True:
            name = entry.szModule.lower()
            if name and name not in bases:
                bases[name] = int(ctypes.cast(entry.modBaseAddr,
                                             ctypes.c_void_p).value or 0)
            if not kernel32.Module32NextW(snap, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snap)
    return bases


def check_target_modules(pid, system_dir=None):
    """Compare the modules of ANOTHER process against the files on disk.

    This is the check that finds the lab's OWN evasion. Comparing the
    disk file against this process's own copy proves nothing about a
    target: the target's copy is what was patched.

    The export's address in the target is the module base plus the
    export's RVA, which is the same offset the file uses.
    """
    system_dir = system_dir or os.environ.get("SystemRoot", r"C:\Windows")
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  False, pid)
    if not handle:
        return {"pid": pid, "error": "OpenProcess failed"}

    bases = _module_bases(pid)
    out = {"pid": pid, "modules": [], "patched": []}

    for dll_name, export_names in WATCHED_MODULES:
        path = os.path.join(system_dir, "System32", dll_name)
        try:
            blob = _read_disk(path)
        except OSError as exc:
            out["modules"].append({"module": dll_name, "error": str(exc)})
            continue

        sections = _pe_sections(blob)
        exports = _export_rvas(blob)
        base = bases.get(dll_name.lower())
        entry = {"module": dll_name, "base": hex(base) if base else None,
                 "exports": {}}

        if not base:
            entry["exports"] = {n: {"status": "not loaded in the target"}
                                for n in export_names}
            out["modules"].append(entry)
            continue

        for name in export_names:
            rva = exports.get(name)
            if not rva:
                entry["exports"][name] = {"status": "not exported"}
                continue
            disk_off = _rva_to_offset(sections, rva)
            if disk_off is None:
                entry["exports"][name] = {"status": "no file offset"}
                continue
            disk_bytes = blob[disk_off:disk_off + 16]

            addr = base + rva
            buf = ctypes.create_string_buffer(16)
            got = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr),
                                           buf, 16, ctypes.byref(got))
            if not ok or got.value < 8:
                entry["exports"][name] = {"status": "could not be read"}
                continue
            mem_bytes = buf.raw[:got.value]
            same = mem_bytes[:16] == disk_bytes
            entry["exports"][name] = {
                "rva": hex(rva),
                "address": hex(addr),
                "disk": disk_bytes[:8].hex(),
                "memory": mem_bytes[:8].hex(),
                "same": same,
            }
            if not same:
                out["patched"].append(f"{dll_name}!{name}")

        out["modules"].append(entry)

    kernel32.CloseHandle(handle)
    return out


def check_ntdll_hooks(system_dir=None):
    """The modules worth comparing, as one report."""
    out = {"modules": [], "hooked": []}
    seen = set()
    for dll_name, names in WATCHED_MODULES:
        key = (dll_name, tuple(names))
        if key in seen:
            continue
        seen.add(key)
        m = check_module_hooks(dll_name, names, system_dir)
        out["modules"].append(m)
        for h in m.get("hooked", []):
            out["hooked"].append(f"{dll_name}!{h}")
    return out


# ---------------------------------------------------------------------------
# 2. Are there hand-built syscall stubs?
# ---------------------------------------------------------------------------

# "mov eax, imm32" followed by "syscall".  B8 xx xx xx xx 0F 05
SYSCALL_STUB = re.compile(rb"\xb8(.{4})\x0f\x05", re.S)

# The largest syscall number Windows has. Anything above this is the
# byte pattern occurring by chance, not a syscall.
MAX_SYSCALL_NUMBER = 0x1000


def scan_syscall_stubs(pid, max_mb=256):
    """Look for direct-syscall stubs in a process's memory."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  False, pid)
    if not handle:
        return {"pid": pid, "error": f"OpenProcess failed "
                                     f"({ctypes.get_last_error()})"}

    limit = max_mb * 1024 * 1024
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    scanned = 0
    hits = []
    regions = 0

    while scanned < limit:
        n = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                    ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not n:
            break
        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        if not size:
            break
        regions += 1

        if (mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_GUARD)
                and not (mbi.Protect & PAGE_NOACCESS)):
            chunk = min(size, 4 * 1024 * 1024)
            buf = ctypes.create_string_buffer(chunk)
            got = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                         buf, chunk, ctypes.byref(got)):
                blob = buf.raw[:got.value]
                for m in SYSCALL_STUB.finditer(blob):
                    number = int.from_bytes(m.group(1), "little")
                    # A real syscall number is small -- a few hundred at
                    # most. A match with a number in the millions is the
                    # byte pattern occurring by chance in a large
                    # region, and counting those would make the check
                    # report noise on every process on earth.
                    if number > MAX_SYSCALL_NUMBER:
                        continue
                    hits.append({
                        "address": hex(base + m.start()),
                        "syscall_number": number,
                        "region": hex(base),
                        "region_type": ("private" if mbi.Type == 0x20000
                                        else "image" if mbi.Type == 0x1000000
                                        else hex(mbi.Type)),
                    })
                    if len(hits) >= 64:
                        break
            scanned += got.value
        addr = base + size
        regions += 1
        if regions > 8192:
            break
        if addr <= 0:
            break

    kernel32.CloseHandle(handle)
    return {
        "pid": pid,
        "regions": regions,
        "bytes_scanned": scanned,
        "stubs": hits,
        "count": len(hits),
    }


# ---------------------------------------------------------------------------
# 3. Which kernel-mode filters are registered?
# ---------------------------------------------------------------------------

# The service types that matter: 2 = kernel driver, 6 = file system
# driver, 8 = file system filter driver.
FILTER_SERVICE_TYPES = {"2", "6", "8"}


def check_filter_drivers():
    """The kernel drivers and the registered minifilters."""
    import winreg

    out = {"drivers": [], "minifilters": []}

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services") as k:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(k, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(k, name) as sk:
                        stype, _ = winreg.QueryValueEx(sk, "Type")
                        if str(stype) in FILTER_SERVICE_TYPES:
                            out["drivers"].append({"name": name,
                                                  "type": str(stype)})
                except OSError:
                    continue
    except OSError as exc:
        out["error"] = str(exc)
        return out

    # The minifilter instances, with their altitudes.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\FltMgr\Instances") as k:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(k, index)
                except OSError:
                    break
                index += 1
                alt = None
                try:
                    with winreg.OpenKey(k, name) as ik:
                        alt, _ = winreg.QueryValueEx(ik, "Altitude")
                except OSError:
                    pass
                out["minifilters"].append({"instance": name,
                                           "altitude": alt})
    except OSError:
        pass

    return out


# ---------------------------------------------------------------------------
# 4. Kernel callbacks
# ---------------------------------------------------------------------------

def kernel_callback_note():
    """The honest answer about ObRegisterCallbacks."""
    return {
        "answer": "not visible from user mode",
        "why": "the callbacks live in the kernel and the registry that "
               "lists them is only readable by kernel mode",
        "what_a_defender_does": "a driver enumerates ObRegisterCallbacks, "
                                "or the EDR's own telemetry shows the "
                                "process it was never told about",
        "what_the_lab_can_do": "nothing, and saying so is more useful "
                               "than a check that always returns zero",
    }


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Look for the traces of endpoint-evasion techniques")
    ap.add_argument("--pid", type=int, default=None,
                    help="a process to scan for direct-syscall stubs")
    ap.add_argument("--scan-mb", type=int, default=256,
                    help="how much memory to scan")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    report = {
        "ntdll": check_ntdll_hooks(),
        "filters": check_filter_drivers(),
        "kernel_callbacks": kernel_callback_note(),
    }
    if args.pid:
        report["target_modules"] = check_target_modules(args.pid)
        report["syscall_stubs"] = scan_syscall_stubs(args.pid, args.scan_mb)

    print("=" * 74)
    print("PHANTOM-X :: WHAT THE ENDPOINT'S DEFENCES LOOK LIKE FROM HERE")
    print("=" * 74)
    print()

    ntd = report["ntdll"]
    print("  IS A MODULE HOOKED OR PATCHED?")
    print("  (the bytes on disk against the bytes in memory, for the")
    print("   functions a security product patches -- and the two the")
    print("   lab's OWN evasion arms patch)")
    for m in ntd.get("modules", []):
        print(f"    {m['module']}")
        for name, info in m.get("exports", {}).items():
            if "same" in info:
                mark = "same" if info["same"] else "DIFFERENT"
                print(f"      {name:<26} {mark}")
            else:
                print(f"      {name:<26} ({info.get('status')})")
    if ntd.get("hooked"):
        print(f"    -> PATCHED: {', '.join(ntd['hooked'])}")
    else:
        print("    -> nothing differs from disk")
    print()

    f = report["filters"]
    print("  KERNEL-MODE FILTERS")
    for d in f.get("drivers", [])[:12]:
        print(f"    {d['name']:<40} type={d['type']}")
    if len(f.get("drivers", [])) > 12:
        print(f"    ... and {len(f['drivers']) - 12} more")
    for mf in f.get("minifilters", []):
        print(f"    minifilter: {mf['instance']:<28} altitude={mf['altitude']}")
    print()

    kc = report["kernel_callbacks"]
    print("  KERNEL CALLBACKS (ObRegisterCallbacks)")
    print(f"    {kc['answer']}")
    print(f"    why: {kc['why']}")
    print(f"    a defender: {kc['what_a_defender_does']}")
    print()

    if "target_modules" in report:
        tm = report["target_modules"]
        print("  THE TARGET PROCESS'S OWN MODULES")
        print("  (the target's copy of the module, against the file on disk)")
        if "error" in tm:
            print(f"    {tm['error']}")
        else:
            for m in tm.get("modules", []):
                print(f"    {m['module']}  base={m.get('base')}")
                for name, info in m.get("exports", {}).items():
                    if "same" in info:
                        mark = "same" if info["same"] else "PATCHED"
                        print(f"      {name:<26} {mark}")
                    else:
                        print(f"      {name:<26} ({info.get('status')})")
            if tm.get("patched"):
                print(f"    -> PATCHED IN THE TARGET: "
                      f"{', '.join(tm['patched'])}")
            else:
                print("    -> nothing in the target differs from disk")
        print()

    if "syscall_stubs" in report:
        s = report["syscall_stubs"]
        print("  DIRECT-SYSCALL STUBS")
        if "error" in s:
            print(f"    {s['error']}")
        else:
            print(f"    scanned {s['bytes_scanned']} bytes over "
                  f"{s['regions']} regions")
            print(f"    {s['count']} stub(s) found")
            for h in s["stubs"][:8]:
                print(f"      {h['address']}  syscall {h['syscall_number']}")
        print()

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"  -> {os.path.abspath(args.json)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
