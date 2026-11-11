/* ================================================================== */
/* PHANTOM-X :: string obfuscation                                     */
/* ================================================================== */
/*                                                                        */
/* px_obfuscate.c -- runtime decoder for the encoded string table.        */
/*                                                                        */
/* WHAT THIS IS                                                          */
/*     The baseline payload carries its sensitive strings as plain        */
/*     literals, so a defender can grep for them. This decoder removes   */
/*     those literals from the binary and reconstructs them at runtime.  */
/*                                                                        */
/* WHY IT EXISTS IN A DETECTION LAB                                     */
/*     The interesting question is not "can a payload hide its strings"  */
/*     -- obviously it can. The question is: HOW MUCH of a detection     */
/*     depends on a plaintext string being present, and what ELSE       */
/*     catches the payload once the string is gone?                      */
/*                                                                        */
/*     So the lab builds two arms:                                       */
/*                                                                        */
/*       baseline  - plain literals, no decoder compiled in              */
/*       obfuscated- this decoder, literals absent from the binary       */
/*                                                                        */
/*     and compares what the endpoint sees. A rule that only fired on    */
/*     the string stops firing on the obfuscated arm. That gap is the    */
/*     finding, and it is a finding about the RULE, not about the       */
/*     payload.                                                          */
/*                                                                        */
/* WHAT THIS IS NOT                                                      */
/*     Not a packer. Not an anti-disassembly measure. Not a             */
/*     cryptographic protection. The bytes are recoverable by anyone      */
/*     who looks, and the encoding is deliberately trivial so that the   */
/*     lab's own analysis tooling can decode it.                         */
/*                                                                        */
/*     The point is to remove a LITERAL, and to be able to prove that   */
/*     it is gone.                                                      */
/* ================================================================== */

#include "px_config.h"

/* The string table is ALWAYS compiled in.
 *
 * An earlier version compiled the table only for the obfuscated arm, and
 * the decoder was a stub in the others. That was wrong: the other arms
 * still call px_obf_decode -- for the channel key, for the protocol
 * vocabulary, for the module names -- and the stub returned 0, so the
 * key came out empty and the encrypted channel never started.
 *
 * The table being present is NOT the same as the strings being
 * obfuscated. The obfuscation is about what the COMPILER puts in the
 * binary; the table is about what the program can look up at runtime.
 * The arm that matters is decided by whether the plaintext literals are
 * used for the sensitive strings, which is a separate question.
 */
#include "px_strings.h"

/* The decoded string lives in a caller-supplied buffer so that the
 * decoded value's lifetime is obvious and there is no hidden global
 * state to reason about.
 *
 * px_obf_decode returns the length written, or 0 on a bad index. */
unsigned int px_obf_decode(unsigned int index, char *out, unsigned int cap)
{
    const px_encoded_string *e;
    unsigned int i;

    if (index >= PX_STRING_COUNT)
        return 0;
    e = &px_string_table[index];
    if (e->len + 1 > cap)
        return 0;

    for (i = 0; i < e->len; i++)
        out[i] = (char)(e->bytes[i] ^ e->key);
    out[e->len] = '\0';
    return e->len;
}

/* The ID of an encoded string, so the caller does not have to know the
 * table index. The names come from px_strings.def via an enum, so that
 * adding a string to the .def does not silently renumber the table. */
unsigned int px_obf_id(unsigned int id)
{
    return id;
}
