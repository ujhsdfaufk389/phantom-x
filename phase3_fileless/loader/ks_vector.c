/* ================================================================== */
/* PHANTOM-X :: keystream vector generator (test tool)                 */
/* ================================================================== */
/*                                                                        */
/* Prints the keystream the payload's cipher produces, so that the Go   */
/* implementation can be pinned to the same vector.                      */
/*                                                                        */
/* The point is that the two implementations are independent -- one in   */
/* C, one in Go -- and a difference between them is invisible until a   */
/* session fails to start. Printing the vector lets the Go test       */
/* assert on it.                                                         */
/*                                                                        */
/* BUILD AND RUN                                                         */
/*     cl.exe /nologo /O2 /GS- /Zl /Gs999999999 ks_vector.c \          */
/*            /Fe:ks_vector.exe /link /NOENTRY /ENTRY:ks_vector_entry \*/
/*            /SUBSYSTEM:CONSOLE ws2_32.lib kernel32.lib /NODEFAULTLIB */
/*     ks_vector.exe                                                     */
/* ================================================================== */

#include <windows.h>

/* The keystream, copied verbatim from px_crypt.c so that the vector is
 * produced by the same code the payload runs. Copying it rather than
 * including px_crypt.c keeps this tool free of the payload's other
 * dependencies. */

typedef struct ks {
    unsigned char state[256];
    unsigned char pos;
} ks;

static void ks_init(ks *k, const char *key, unsigned int keylen,
                     unsigned char seed)
{
    unsigned int i;
    unsigned char j = 0;

    for (i = 0; i < 256; i++)
        k->state[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        unsigned char t;
        j = (unsigned char)(j + k->state[i] + key[i % keylen] + seed);
        t = k->state[i];
        k->state[i] = k->state[j];
        k->state[j] = t;
    }
    k->pos = 0;
}

static unsigned char ks_byte(ks *k)
{
    unsigned char t;
    unsigned char j;

    k->pos = (unsigned char)(k->pos + 1);
    t = k->state[k->pos];
    j = (unsigned char)(t + k->pos);
    k->state[k->pos] = k->state[j];
    k->state[j] = t;
    return k->state[(unsigned char)(k->state[k->pos] + k->state[j])];
}

static void ks_apply(ks *k, unsigned char *buf, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++)
        buf[i] ^= ks_byte(k);
}

__declspec(dllexport) void ks_vector_entry(void)
{
    const char *key = "phantomx-lab-key-0123456789abcdef";
    /* The key length MUST be the real one, not a hardcoded number.
     *
     * "phantomx-lab-key-0123456789abcdef" is 33 characters. An earlier
     * version of this tool had 32 hardcoded, which produced a different
     * permutation and a vector that the Go implementation could never
     * match -- and the failure looked exactly like a cipher bug. */
    unsigned int keylen = 33;
    unsigned char buf[16];
    unsigned int i;

    /* The outbound stream: seed 0x00. */
    {
        ks k;
        ks_init(&k, key, keylen, 0x00);
        for (i = 0; i < 16; i++)
            buf[i] = 0;
        ks_apply(&k, buf, 16);
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "outbound : ", 10, NULL, NULL);
        for (i = 0; i < 16; i++) {
            char t[4];
            t[0] = "0123456789ABCDEF"[buf[i] >> 4];
            t[1] = "0123456789ABCDEF"[buf[i] & 0xF];
            t[2] = ' ';
            t[3] = 0;
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), t, 3, NULL, NULL);
        }
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "\r\n", 2, NULL, NULL);
    }

    /* The inbound stream: seed 0x5A. */
    {
        ks k;
        ks_init(&k, key, keylen, 0x5A);
        for (i = 0; i < 16; i++)
            buf[i] = 0;
        ks_apply(&k, buf, 16);
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "inbound  : ", 10, NULL, NULL);
        for (i = 0; i < 16; i++) {
            char t[4];
            t[0] = "0123456789ABCDEF"[buf[i] >> 4];
            t[1] = "0123456789ABCDEF"[buf[i] & 0xF];
            t[2] = ' ';
            t[3] = 0;
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), t, 3, NULL, NULL);
        }
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "\r\n", 2, NULL, NULL);
    }
}
