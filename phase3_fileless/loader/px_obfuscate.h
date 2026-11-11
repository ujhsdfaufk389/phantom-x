/* ================================================================== */
/* PHANTOM-X :: string obfuscation interface                           */
/* ================================================================== */
/*                                                                        */
/* The decoder lives in px_obfuscate.c. This header exists so that the  */
/* variant files can include it by name rather than relying on the      */
/* payload including them in the right order.                           */
/* ================================================================== */

#ifndef PX_OBFUSCATE_H
#define PX_OBFUSCATE_H

#include "px_config.h"

#if PX_OBFUSCATE
#include "px_strings.h"
#endif

/* Decode an encoded string into `out`.
 *
 * Returns the length written, or 0 if the index is out of range or the
 * buffer is too small.
 *
 * When the obfuscation variant is not compiled in, this is a no-op that
 * returns 0: the caller uses the plain literal in that build. */
unsigned int px_obf_decode(unsigned int index, char *out, unsigned int cap);

#endif /* PX_OBFUSCATE_H */
