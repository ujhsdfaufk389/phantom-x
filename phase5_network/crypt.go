// =============================================================================
// PHANTOM-X :: Phase 5 -- the encrypted channel, server side
// =============================================================================
// crypt.go -- The server half of the encrypted-channel variant.
//
// WHY THIS IS HERE AT ALL
//
//     The question the encrypted arm answers is: WHICH of the network
//     detections are keyed on the plaintext of the protocol?
//
//     To answer it, the server has to be able to read the traffic --
//     otherwise the lab produces an opaque stream and no measurement.
//     But the traffic ON THE WIRE must be opaque, because that is what
//     a defender's IDS sees.
//
//     So: the wire is encrypted, the server decrypts it, and the audit
//     log records BOTH the plaintext that was said AND the fact that it
//     was said opaquely. A defender's rule that matched the plaintext
//     stops matching; the lab can see that it stopped, and can see
//     exactly what the rule was keyed on.
//
// THE CIPHER
//
//     XOR against a keystream derived from the shared key. The key
//     schedule matches px_crypt.c exactly, because the two have to
//     agree byte for byte or nothing works.
//
//     The two directions use different seeds, so a message in one
//     direction is never encrypted with the same keystream as a message
//     in the other.
//
//     This is not cryptography in the security sense. It is here to
//     make the plaintext disappear from the wire while keeping it
//     readable to the lab.
//
// -----------------------------------------------------------------------------

package main

import "fmt"

// Keystream is one direction of the channel cipher.
//
// The state is a 256-byte permutation, seeded from the key. The
// generator advances the permutation and mixes in the key material,
// which is the same construction as RC4 but with a fixed key schedule
// rather than a random drop.
type Keystream struct {
	state [256]byte
	pos   byte
}

// NewKeystream seeds a keystream from a key and a direction seed.
//
// The seed differs per direction so that the two streams are
// unrelated: a message encrypted outbound is never encrypted with the
// same keystream as a message sent in the other direction.
func NewKeystream(key []byte, seed byte) *Keystream {
	ks := &Keystream{}
	var j byte
	for i := 0; i < 256; i++ {
		ks.state[i] = byte(i)
	}
	keyLen := len(key)
	if keyLen == 0 {
		keyLen = 1
	}
	for i := 0; i < 256; i++ {
		// The sum is computed in a WIDER type and truncated ONCE, at
		// the end.
		//
		// This matters, and it is the bug that broke the encrypted
		// channel. Written as
		//
		//     j += ks.state[i] + key[i%keyLen] + seed
		//
		// Go evaluates the inner sum in 8-bit arithmetic, so it wraps
		// BEFORE it is added to j. The C implementation sums everything
		// in int and truncates once, at the end.
		//
		// The two agree while the inner sum stays below 256, which is
		// why the first few bytes of the keystream matched and then
		// diverged -- and why the session opened, exchanged the
		// handshake, and then went silent at the first encrypted frame.
		sum := int(j) + int(ks.state[i]) + int(key[i%keyLen]) + int(seed)
		j = byte(sum)

		// The swap, in the same order as the C version: the old
		// state[i] is captured first, so the two implementations
		// cannot drift apart here either.
		t := ks.state[i]
		ks.state[i] = ks.state[j]
		ks.state[j] = t
	}
	ks.pos = 0
	return ks
}

// next produces the next keystream byte.
func (ks *Keystream) next() byte {
	ks.pos++
	t := ks.state[ks.pos]

	// The index arithmetic is done in a WIDER type.
	//
	// C promotes unsigned char to int before adding, so `t + pos` is
	// computed without wrapping and truncated once afterwards. Go does
	// NOT promote: byte + byte is byte arithmetic and wraps. When the
	// sum exceeds 255 the two implementations pick different indices,
	// and the keystreams diverge.
	//
	// This was the second half of the bug that broke the encrypted
	// channel, and the reason the first few bytes matched: the sums
	// stayed below 256 for the first few steps.
	j := byte(int(t) + int(ks.pos))

	// The swap, in the C order: the old state[pos] is captured first,
	// so the two implementations cannot drift apart here either.
	old := ks.state[ks.pos]
	ks.state[ks.pos] = ks.state[j]
	ks.state[j] = old

	return ks.state[byte(int(ks.state[ks.pos])+int(ks.state[j]))]
}
// Apply XORs the buffer with the keystream.
//
// Symmetric: the same call encrypts and decrypts.
func (ks *Keystream) Apply(buf []byte) {
	for i := range buf {
		buf[i] ^= ks.next()
	}
}

// FrameLengthPrefix is the size of the plaintext-length header that
// precedes every encrypted frame.
const FrameLengthPrefix = 4

// EncryptFrame frames and encrypts a plaintext line.
//
// The 4-byte plaintext length goes out in the clear. That is
// deliberate: it means a defender can still see the exact size of
// every message, and the lab can measure how much that alone gives
// away. A length prefix in the clear is a realistic design, not a
// mistake.
func (ks *Keystream) EncryptFrame(plain []byte) []byte {
	out := make([]byte, FrameLengthPrefix+len(plain))
	n := len(plain)
	out[0] = byte(n & 0xFF)
	out[1] = byte((n >> 8) & 0xFF)
	out[2] = byte((n >> 16) & 0xFF)
	out[3] = byte((n >> 24) & 0xFF)
	copy(out[FrameLengthPrefix:], plain)
	ks.Apply(out[FrameLengthPrefix:])
	return out
}

// DecryptFrame decodes a frame.
//
// Returns the plaintext and the number of bytes consumed, or nil if
// the frame is malformed. A malformed frame is discarded whole rather
// than partially decoded, which is what keeps the keystream in sync
// across a dropped frame.
func (ks *Keystream) DecryptFrame(frame []byte) ([]byte, int, error) {
	if len(frame) < FrameLengthPrefix {
		return nil, 0, errShortFrame
	}
	n := int(frame[0]) |
		(int(frame[1]) << 8) |
		(int(frame[2]) << 16) |
		(int(frame[3]) << 24)
	if n < 0 || n > maxFrameSize {
		return nil, 0, errBadLength
	}
	if len(frame) < FrameLengthPrefix+n {
		return nil, 0, errShortFrame
	}
	out := make([]byte, n)
	copy(out, frame[FrameLengthPrefix:FrameLengthPrefix+n])
	ks.Apply(out)
	return out, FrameLengthPrefix + n, nil
}

// maxFrameSize bounds a single frame. A length prefix is attacker
// controlled, so it has to be checked before it is used to size an
// allocation.
const maxFrameSize = 1 << 20 // 1 MiB

var (
	errShortFrame = fmt.Errorf("short frame")
	errBadLength  = fmt.Errorf("bad frame length")
)
