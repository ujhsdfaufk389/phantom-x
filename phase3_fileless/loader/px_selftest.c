/* ================================================================== */
/* PHANTOM-X :: self-test for the payload's freestanding formatter       */
/* ================================================================== */
/*                                                                        */
/* The formatter in px_payload.c is freestanding: it cannot use the CRT  */
/* printf, so it is hand-written. Hand-written formatters have bugs, and  */
/* three of them were found in this one during development:              */
/*                                                                        */
/*   1. "%ld" was not recognised, so the exit code in every RESULT line  */
/*      reached the C2 server as the literal text "%ld".                  */
/*   2. Zero padding ("%04u") was not implemented, so the timestamp in   */
/*      the marker file came out as "202611110940".                      */
/*   3. The padding calculation underflowed when no width was given      */
/*      (0 - len is a huge unsigned number), filling the buffer with    */
/*      spaces.                                                           */
/*                                                                        */
/* Each of those produced a wrong answer that looked plausible. This     */
/* harness is the regression test for them.                              */
/*                                                                        */
/* The payload source is INCLUDED rather than compiled separately, so    */
/* the test exercises the exact code the payload runs and not a copy.    */
/*                                                                        */
/* Build and run:                                                       */
/*   cl.exe /nologo /O2 /W4 /GS- /Zl /Gs999999999 px_selftest.c \       */
/*          /Fe:px_selftest.exe /link /NOENTRY \                         */
/*          /ENTRY:px_selftest_entry /SUBSYSTEM:CONSOLE ws2_32.lib \   */
/*          kernel32.lib /NODEFAULTLIB                                   */
/*                                                                        */
/* or: python3 phase3_fileless/loader/run_selftest.py                   */
/* ================================================================== */

#include <windows.h>

/* The payload source, included so the test exercises the real code. */
#include "px_payload.c"

/* ================================================================== */
/* the test harness                                                    */
/* ================================================================== */
static int g_pass = 0;
static int g_fail = 0;

/* A local strcmp: the CRT is not linked into this build. */
static int px_streq(const char *a, const char *b)
{
    if (!a || !b)
        return a == b;
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static void check_str(const char *what, const char *got, const char *want)
{
    if (px_streq(got, want)) {
        g_pass++;
    } else {
        g_fail++;
        px_logf("  FAIL %-24s got [%s] want [%s]\n", what,
                got ? got : "(null)", want ? want : "(null)");
    }
}

/* Format into a buffer using the payload's own formatter.
 *
 * px_vfmt is variadic, so this is a straight call. */
static const char *fmt(const char *spec, ...)
{
    static char buf[256];
    px_va_list ap;
    PX_VA_START(ap, spec);
    px_vfmt_va(buf, sizeof(buf), spec, ap);
    PX_VA_END(ap);
    return buf;
}

__declspec(dllexport) void px_selftest_entry(void)
{
    px_logf("PHANTOM-X :: payload formatter self-test\r\n\r\n");

    /* -- the exact strings the payload sends --------------------------- */
    {
        char line[256];
        px_logf("  testing the RESULT line ...\r\n");
        px_vfmt(line, sizeof(line), "RESULT|%s|%s|%ld\r\n",
                "7", "b3BhcXVl", (long)42);
        check_str("RESULT line", line, "RESULT|7|b3BhcXVl|42\r\n");
    }

    {
        char line[256];
        px_logf("  testing the HELLO line ...\r\n");
        px_vfmt(line, sizeof(line), "HELLO|%s|%lu|%s\r\n",
                "x64", (unsigned long)1234, "HOST");
        check_str("HELLO line", line, "HELLO|x64|1234|HOST\r\n");
    }

    /* -- the timestamp that was unpadded ------------------------------- */
    {
        char line[256];
        px_logf("  testing the timestamp ...\r\n");
        px_vfmt(line, sizeof(line),
                "%04lu-%02lu-%02lu %02lu:%02lu:%02lu",
                (unsigned long)2026, (unsigned long)11, (unsigned long)11,
                (unsigned long)9, (unsigned long)40, (unsigned long)5);
        check_str("timestamp", line, "2026-11-11 09:40:05");
    }

    /* -- plain conversions ---------------------------------------------- */
    {
        px_logf("  testing plain conversions ...\r\n");
        check_str("string", fmt("%s", "hello"), "hello");
        check_str("int", fmt("%d", 1234), "1234");
        check_str("negative", fmt("%d", -42), "-42");
        check_str("unsigned", fmt("%u", 4294967295u), "4294967295");
        check_str("long", fmt("%ld", 123456L), "123456");
        check_str("negative long", fmt("%ld", -123456L), "-123456");
        check_str("long long", fmt("%lld", 1234567890123LL), "1234567890123");
        check_str("hex", fmt("%x", 0xdeadbeefu), "deadbeef");
        check_str("percent", fmt("100%%"), "100%");
    }

    /* -- precision ------------------------------------------------------- */
    {
        px_logf("  testing the precision ...\r\n");
        /* The precision caps the string.
         *
         * The '.' was not implemented at all, and the formatter did not
         * complain: an unknown conversion was copied out literally. So
         * "%.4s" printed the four characters "%.4s" and the string it
         * was supposed to shorten was not printed at all. */
        check_str("precision", fmt("%.4s", "abcdefgh"), "abcd");
        check_str("precision longer than the string", fmt("%.10s", "abc"), "abc");
        check_str("precision zero", fmt("[%.0s]", "abc"), "[]");
    }

    /* -- the underflow bug ---------------------------------------------- */
    {
        px_logf("  testing the padding underflow ...\r\n");
        /* No width given: the output must be exactly the digits, with no
         * spaces before or after. */
        check_str("no-width string", fmt("[%s]", "abc"), "[abc]");
        check_str("no-width int", fmt("[%d]", 7), "[7]");
        check_str("no-width long", fmt("[%ld]", 7L), "[7]");
    }

    /* -- width and padding ---------------------------------------------- */
    {
        px_logf("  testing widths ...\r\n");
        check_str("zero pad", fmt("%04lu", 42UL), "0042");
        check_str("zero pad 2", fmt("%02lu", 5UL), "05");
        check_str("space pad", fmt("%5d", 42), "   42");
        check_str("width longer", fmt("%6s", "ab"), "    ab");
    }

    /* -- buffer safety -------------------------------------------------- */
    {
        char tiny[8];
        px_logf("  testing the buffer bound ...\r\n");
        px_vfmt(tiny, sizeof(tiny), "%s", "0123456789abcdef");
        check_str("truncated", tiny, "0123456");
    }

    px_logf("\r\n  %d passed, %d failed\r\n", g_pass, g_fail);
    if (g_fail) {
        px_logf("  RESULT: FAIL\r\n");
    } else {
        px_logf("  RESULT: PASS\r\n");
    }
}
