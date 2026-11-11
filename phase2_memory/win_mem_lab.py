#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 2 -- Windows memory research lab
================================================================================
win_mem_lab.py -- Documented Windows memory API experiments against the
researcher's OWN process.

WHAT THIS DOES
    Exercises the memory subsystem the way the Phase 2 brief describes, and
    records addresses, sizes, protections and API results:

      1. VirtualAlloc   -- reserve and commit regions, RW and RWX
      2. VirtualProtect -- transition RW -> RX, and back
      3. VirtualQuery   -- enumerate the region's state, type and protection
      4. VirtualFree    -- release the region and confirm it is gone
      5. ReadProcessMemory -- read our own address space
      6. Executable vs non-executable memory -- prove the difference
      7. Process memory layout -- walk the module list and the region map
      8. PE loading architecture -- inspect a PE header structure in memory

    It also runs a minimal in-memory code execution proof: a small machine
    code stub is written into an allocated region, the region is transitioned
    to executable, and the stub is executed on a thread. The observable
    result is the thread's exit code, which proves the bytes really ran.

    The stub is fixed and harmless. It performs no I/O, opens no handles and
    touches no other process. It exists to demonstrate the API sequence, not
    to provide a general-purpose code-execution primitive.

IMPORTANT DISTINCTION
    Allocating memory is NOT executing code. This lab reports both steps
    separately and states which one it performed, because collapsing the two
    is the most common error in fileless-malware analysis.

DEPENDENCIES
    Windows only. Python 3.9+. ctypes only -- no third-party packages.

USAGE
    python3 win_mem_lab.py
    python3 win_mem_lab.py --json mem_lab_report.json
    python3 win_mem_lab.py --verbose
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import struct
import sys
import time
from ctypes import wintypes
from datetime import datetime, timezone

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                      wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualProtect.restype = wintypes.BOOL
    kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                         wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    kernel32.VirtualQuery.restype = ctypes.c_size_t
    kernel32.VirtualQuery.argtypes = [ctypes.c_void_p,
                                      ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                      ctypes.c_size_t]
    kernel32.VirtualFree.restype = wintypes.BOOL
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                     wintypes.DWORD]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_size_t,
                                           ctypes.POINTER(ctypes.c_size_t)]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL,
                                     wintypes.DWORD]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD

# --------------------------------------------------------------------------- #
# protection decoding
# --------------------------------------------------------------------------- #

PROTECT_FLAGS = {
    0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD", 0x200: "PAGE_NOCACHE", 0x400: "PAGE_WRITECOMBINE",
}

STATE_FLAGS = {0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x10000: "MEM_FREE"}
TYPE_FLAGS = {0x20000: "MEM_PRIVATE", 0x40000: "MEM_MAPPED", 0x1000000: "MEM_IMAGE"}


def decode_protect(p: int) -> str:
    base = p & 0xFF
    name = PROTECT_FLAGS.get(base, f"0x{base:x}")
    extra = []
    if p & 0x100:
        extra.append("GUARD")
    if p & 0x200:
        extra.append("NOCACHE")
    if p & 0x400:
        extra.append("WRITECOMBINE")
    return name + (("+" + "+".join(extra)) if extra else "")


def decode_state(s: int) -> str:
    return STATE_FLAGS.get(s, f"0x{s:x}")


def decode_type(t: int) -> str:
    return TYPE_FLAGS.get(t, f"0x{t:x}")


class Report:
    def __init__(self):
        self.experiments = []
        self.started = datetime.now(timezone.utc).isoformat()

    def add(self, name, objective, api_calls, observed, conclusion):
        rec = {
            "experiment": name,
            "objective": objective,
            "api_calls": api_calls,
            "observed": observed,
            "conclusion": conclusion,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        self.experiments.append(rec)
        return rec

    def dump(self, verbose=False):
        print("=" * 78)
        print("PHANTOM-X :: WINDOWS MEMORY LAB")
        print("=" * 78)
        print(f"host      : {platform.node()}  pid={os.getpid()}")
        print(f"python    : {platform.python_version()}  {platform.platform()}")
        print("")
        for e in self.experiments:
            print("-" * 78)
            print(f"[{e['experiment']}] {e['objective']}")
            for k, v in e["api_calls"].items():
                print(f"    {k}")
                if isinstance(v, dict):
                    for kk, vv in v.items():
                        print(f"        {kk}: {vv}")
                else:
                    print(f"        {v}")
            print(f"    -> {e['conclusion']}")
        print("-" * 78)
        print()
        print("DISTINCTION HELD THROUGHOUT:")
        print("  Allocating memory is not executing code. Each experiment below")
        print("  states explicitly which of the two it performed.")


# --------------------------------------------------------------------------- #
# experiments
# --------------------------------------------------------------------------- #

def exp1_virtual_alloc(rep: Report):
    """Reserve and commit a region; record size, address and protection."""
    calls = {}
    size = 0x10000  # 64 KiB

    ptr = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE)
    err = ctypes.get_last_error()
    calls["VirtualAlloc(lpAddress=NULL, dwSize=0x%x, "
          "flAllocationType=MEM_COMMIT|MEM_RESERVE, flProtect=PAGE_READWRITE)"
          % size] = {
        "returned_address": hex(ptr) if ptr else None,
        "last_error": err,
        "size_bytes": size,
        "protection": "PAGE_READWRITE",
    }
    if not ptr:
        calls["result"] = "FAILED"
        rep.add("E1_VirtualAlloc", "Reserve and commit a private RW region",
                calls, {}, "Allocation failed; nothing further can be concluded.")
        return None, size

    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQuery(ptr, ctypes.byref(mbi), ctypes.sizeof(mbi))
    calls["VirtualQuery"] = {
        "base_address": hex(mbi.BaseAddress),
        "allocation_base": hex(mbi.AllocationBase),
        "region_size": hex(mbi.RegionSize),
        "state": decode_state(mbi.State),
        "protect": decode_protect(mbi.Protect),
        "type": decode_type(mbi.Type),
    }

    rep.add("E1_VirtualAlloc",
            "Reserve and commit a private region, then describe it",
            calls,
            {"allocated_bytes": size, "address": hex(ptr),
             "protection": "PAGE_READWRITE"},
            "Memory was ALLOCATED and is now committed and writable. "
            "No code has been executed. Allocation is not execution.")
    return ptr, size


def exp2_virtual_protect(rep: Report, ptr, size):
    """Transition the region RW -> RX and read the protection back."""
    if not ptr:
        return
    calls = {}
    old = wintypes.DWORD(0)

    ok = kernel32.VirtualProtect(ptr, size, PAGE_EXECUTE_READ,
                                 ctypes.byref(old))
    err = ctypes.get_last_error()
    calls["VirtualProtect(lpAddress=%s, dwSize=0x%x, "
          "flNewProtect=PAGE_EXECUTE_READ, lpflOldProtect=&old)" % (hex(ptr), size)] = {
        "succeeded": bool(ok),
        "last_error": err,
        "old_protection": decode_protect(old.value),
        "new_protection": "PAGE_EXECUTE_READ",
    }

    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQuery(ptr, ctypes.byref(mbi), ctypes.sizeof(mbi))
    calls["VirtualQuery (verify)"] = {
        "protect": decode_protect(mbi.Protect),
        "state": decode_state(mbi.State),
    }

    observed = {
        "address": hex(ptr),
        "protection_before": "PAGE_READWRITE",
        "protection_after": decode_protect(mbi.Protect),
    }
    conclusion = ("Protection was changed from PAGE_READWRITE to "
                  "PAGE_EXECUTE_READ and read back to confirm it. "
                  "The region is now executable but was NOT executed here.")
    if not ok:
        conclusion = ("VirtualProtect failed (error %d). The region remains "
                      "non-executable." % err)
    rep.add("E2_VirtualProtect",
            "Change a region's protection and verify it took effect",
            calls, observed, conclusion)


def exp3_execute_proof(rep: Report, ptr):
    """
    Minimal in-memory code execution proof.

    The stub below is x86-64 machine code whose only effect is to exit the
    thread with a known value. It performs no I/O, opens no handles and
    touches nothing else. Running it produces an observable result (the
    thread exit code) that can only happen if the bytes actually executed.
    """
    if not ptr:
        return
    calls = {}

    # mov eax, 0xC0DE ; ret   ->  the thread's exit code becomes 0xC0DE
    stub = bytes([0xB8, 0xDE, 0xC0, 0x00, 0x00, 0xC3])

    buf = (ctypes.c_ubyte * len(stub)).from_buffer_copy(stub)
    ctypes.memmove(ptr, buf, len(stub))

    calls["memmove(lpAddress=%s, stub, %d)" % (hex(ptr), len(stub))] = {
        "bytes_written": stub.hex(),
        "meaning": "mov eax, 0xC0DE ; ret",
        "note": "bytes written into the allocated region",
    }

    # The region must be executable to run. It already is (E2).
    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQuery(ptr, ctypes.byref(mbi), ctypes.sizeof(mbi))
    calls["VirtualQuery (pre-exec)"] = {"protect": decode_protect(mbi.Protect)}

    func_type = ctypes.WINFUNCTYPE(wintypes.DWORD)
    fn = func_type(ptr)
    exit_code = fn()
    calls["call through function pointer"] = {
        "thread_exit_code": hex(exit_code),
        "expected": "0xc0de",
    }

    ok = (exit_code == 0xC0DE)
    rep.add("E3_InMemoryExecution",
            "Execute a minimal stub from allocated memory and observe the result",
            calls,
            {"thread_exit_code": hex(exit_code), "executed": ok},
            ("CODE WAS EXECUTED from the allocated region: the stub returned "
             "0xC0DE, which only happens if the bytes ran. This is the "
             "execution step, distinct from the allocation in E1."
             if ok else
             "Execution did not produce the expected result. The stub did "
             "not run; no execution claim is made."))


def exp4_read_process_memory(rep: Report, ptr):
    """Read our own process memory through ReadProcessMemory."""
    if not ptr:
        return
    calls = {}
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  False, os.getpid())
    calls["OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, pid=%d)"
          % os.getpid()] = {
        "handle": hex(handle) if handle else None,
        "last_error": ctypes.get_last_error(),
    }

    marker = b"PHANTOM_X_MEMORY_MARKER_0123456789"
    ctypes.memmove(ptr, marker, len(marker))

    out = (ctypes.c_ubyte * len(marker))()
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ptr, out, len(marker),
                                    ctypes.byref(read))
    err = ctypes.get_last_error()
    calls["ReadProcessMemory(hProcess, %s, buf, %d, &read)" % (hex(ptr), len(marker))] = {
        "succeeded": bool(ok),
        "last_error": err,
        "bytes_read": read.value,
        "data": bytes(out).decode("latin-1", "replace"),
    }

    matched = bytes(out) == marker
    rep.add("E4_ReadProcessMemory",
            "Read our own process memory back through the documented API",
            calls,
            {"bytes_read": read.value, "content_matched": matched},
            ("The region was read back through ReadProcessMemory and the "
             "content matched exactly. Note the scope: this read THIS "
             "process only. The API is not limited to self, but this "
             "experiment deliberately stays within it."
             if matched else "Read did not return the expected content."))


def exp5_memory_layout(rep: Report):
    """Walk our own address space and summarise the region map."""
    calls = {}
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0x10000
    summary = {}
    regions = []

    while address < 0x7FFFFFFFFFFF:
        got = kernel32.VirtualQuery(ctypes.c_void_p(address),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not got:
            break
        base = mbi.BaseAddress
        size = mbi.RegionSize
        key = f"{decode_type(mbi.Type)}/{decode_state(mbi.State)}/" \
              f"{decode_protect(mbi.Protect)}"
        summary[key] = summary.get(key, 0) + size
        regions.append({
            "base": hex(base),
            "size": hex(size),
            "state": decode_state(mbi.State),
            "protect": decode_protect(mbi.Protect),
            "type": decode_type(mbi.Type),
        })
        nxt = base + size
        if nxt <= address:
            break
        address = nxt
        if len(regions) > 4000:
            break

    calls["VirtualQuery sweep"] = {
        "regions_examined": len(regions),
        "note": "walked from 0x10000 upward until the query failed",
    }

    exec_regions = [r for r in regions
                    if "EXECUTE" in r["protect"] and r["state"] == "MEM_COMMIT"]
    img_regions = [r for r in regions if r["type"] == "MEM_IMAGE"]

    rep.add("E5_MemoryLayout",
            "Enumerate the process memory map and characterise it",
            calls,
            {"total_regions": len(regions),
             "by_class": {k: hex(v) for k, v in summary.items()},
             "executable_committed_regions": len(exec_regions),
             "image_backed_regions": len(img_regions),
             "first_regions": regions[:12]},
            ("The region map was walked. MEM_IMAGE regions are the loader's "
             "view of DLL and EXE images; MEM_PRIVATE regions are "
             "allocator-owned. The presence of executable regions reflects "
             "loaded modules, not injected code -- distinguishing the two is "
             "the job of a baseline diff, which is what Phase 3 is for."))


def exp6_pe_architecture(rep: Report):
    """Inspect PE header structures to document the loading architecture."""
    calls = {}
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    base = kernel32.GetModuleHandleW(None)
    calls["GetModuleHandleW(NULL)"] = {
        "returned": hex(base) if base else None,
        "meaning": "base address of the main executable image",
    }
    if not base:
        rep.add("E6_PEArchitecture", "Inspect the loaded PE headers",
                calls, {}, "Could not obtain the main module base.")
        return

    hdr = (ctypes.c_ubyte * 0x1000).from_address(base)
    e_magic = struct.unpack_from("<H", hdr, 0)[0]
    e_lfanew = struct.unpack_from("<i", hdr, 0x3C)[0]
    sig = struct.unpack_from("<I", hdr, e_lfanew)[0]
    machine = struct.unpack_from("<H", hdr, e_lfanew + 4)[0]
    num_sections = struct.unpack_from("<H", hdr, e_lfanew + 6)[0]
    opt_magic = struct.unpack_from("<H", hdr, e_lfanew + 24)[0]
    entry_rva = struct.unpack_from("<I", hdr, e_lfanew + 40)[0]
    image_base = struct.unpack_from("<Q", hdr, e_lfanew + 48)[0]
    size_of_image = struct.unpack_from("<I", hdr, e_lfanew + 80)[0]

    calls["parse DOS/NT headers"] = {
        "e_magic": hex(e_magic),
        "e_lfanew": hex(e_lfanew),
        "nt_signature": hex(sig),
        "machine": hex(machine),
        "number_of_sections": num_sections,
        "optional_header_magic": hex(opt_magic),
        "address_of_entry_point": hex(entry_rva),
        "image_base": hex(image_base),
        "size_of_image": hex(size_of_image),
    }

    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQuery(ctypes.c_void_p(base), ctypes.byref(mbi),
                          ctypes.sizeof(mbi))
    calls["VirtualQuery(main image)"] = {
        "type": decode_type(mbi.Type),
        "state": decode_state(mbi.State),
        "protect": decode_protect(mbi.Protect),
        "region_size": hex(mbi.RegionSize),
    }

    rep.add("E6_PEArchitecture",
            "Document how a PE image is laid out in memory",
            calls,
            {"image_base": hex(image_base), "entry_rva": hex(entry_rva),
             "sections": num_sections},
            ("The loaded image is a MEM_IMAGE region whose base equals the "
             "PE's declared ImageBase and whose entry point is an RVA "
             "relative to it. This is the structure the reflective loader "
             "in phase3_fileless/loader reproduces by hand: it must map "
             "sections at their virtual addresses, apply relocations if the "
             "image is not at its preferred base, and resolve imports "
             "before the entry point can run."))


def exp7_virtual_free(rep: Report, ptr, size):
    """Release the region and confirm it is no longer committed."""
    if not ptr:
        return
    calls = {}
    ok = kernel32.VirtualFree(ptr, 0, MEM_RELEASE)
    err = ctypes.get_last_error()
    calls["VirtualFree(lpAddress=%s, dwSize=0, dwFreeType=MEM_RELEASE)"
          % hex(ptr)] = {
        "succeeded": bool(ok), "last_error": err,
    }

    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQuery(ctypes.c_void_p(ptr), ctypes.byref(mbi),
                          ctypes.sizeof(mbi))
    calls["VirtualQuery (verify)"] = {
        "state": decode_state(mbi.State),
        "protect": decode_protect(mbi.Protect),
    }
    freed = mbi.State != 0x1000  # no longer MEM_COMMIT
    rep.add("E7_VirtualFree",
            "Release the region and confirm the state changed",
            calls,
            {"freed": bool(freed), "state_after": decode_state(mbi.State)},
            ("The region was released and the state is no longer "
             "MEM_COMMIT. Cleanup completed; the address space is back to "
             "its pre-experiment shape."
             if freed else "The region still reads as committed after the "
                           "release call."))


# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PHANTOM-X Windows memory lab")
    ap.add_argument("--json", default=None, help="write JSON report")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    if not IS_WINDOWS:
        print("error: this lab exercises Windows APIs and must run on Windows.",
              file=sys.stderr)
        print("       On the research VM:  python win_mem_lab.py --json report.json",
              file=sys.stderr)
        return 2

    rep = Report()
    ptr, size = exp1_virtual_alloc(rep)
    exp2_virtual_protect(rep, ptr, size)
    exp3_execute_proof(rep, ptr)
    exp4_read_process_memory(rep, ptr)
    exp5_memory_layout(rep)
    exp6_pe_architecture(rep)
    exp7_virtual_free(rep, ptr, size)

    rep.dump(args.verbose)

    if args.json:
        out = {
            "schema": "phantom-x.phase2.memory-lab/1.0",
            "tool": "win_mem_lab.py",
            "host": platform.node(),
            "pid": os.getpid(),
            "started_utc": rep.started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "experiments": rep.experiments,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, default=str)
        print(f"\n[+] JSON report written: {os.path.abspath(args.json)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
