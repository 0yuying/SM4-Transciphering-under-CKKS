package ckks_cipher

// Plain SM4/CTR reference implementation for the default big-endian block/counter semantics.
// It reuses the round-function helpers and key schedule from sm4_ctr.go.

// storeU32BE stores x into out[0:4] using big-endian byte order.
func storeU32BE(x uint32, out []byte) {
	out[0] = byte(x >> 24)
	out[1] = byte(x >> 16)
	out[2] = byte(x >> 8)
	out[3] = byte(x)
}

// SM4 encryption linear layer:
// L(b) = b ^ (b<<<2) ^ (b<<<10) ^ (b<<<18) ^ (b<<<24)
func sm4L(b uint32) uint32 {
	return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
}

// PlainSM4Cipher caches the expanded SM4 round keys for repeated client-side use.
type PlainSM4Cipher struct {
	roundKeys [32]uint32
}

// NewPlainSM4Cipher creates a reusable plain SM4 context.
func NewPlainSM4Cipher(key16 []byte) *PlainSM4Cipher {
	if len(key16) != 16 {
		panic("NewPlainSM4Cipher: key must be 16 bytes")
	}
	tmp := &SM4Ctr{}
	return &PlainSM4Cipher{roundKeys: tmp.sm4KeySchedulePlain(key16)}
}

// EncryptBlock encrypts one 16-byte block using standard big-endian SM4 block semantics.
func (cipher *PlainSM4Cipher) EncryptBlock(in16 []byte) [16]byte {
	if len(in16) != 16 {
		panic("PlainSM4Cipher.EncryptBlock: input must be 16 bytes")
	}

	tmp := &SM4Ctr{}

	X := make([]uint32, 36)
	X[0] = loadU32BE(in16[0:4])
	X[1] = loadU32BE(in16[4:8])
	X[2] = loadU32BE(in16[8:12])
	X[3] = loadU32BE(in16[12:16])

	for i := 0; i < 32; i++ {
		t := X[i+1] ^ X[i+2] ^ X[i+3] ^ cipher.roundKeys[i]
		t = tmp.tau(t)
		t = sm4L(t)
		X[i+4] = X[i] ^ t
	}

	var out [16]byte
	storeU32BE(X[35], out[0:4])
	storeU32BE(X[34], out[4:8])
	storeU32BE(X[33], out[8:12])
	storeU32BE(X[32], out[12:16])
	return out
}

// SM4EncryptBlock encrypts one block with a one-shot SM4 context.
func SM4EncryptBlock(key16, in16 []byte) [16]byte {
	return NewPlainSM4Cipher(key16).EncryptBlock(in16)
}

// inc128BE increments a 16-byte counter interpreted as a big-endian 128-bit integer.
func inc128BE(counter16 []byte) {
	for i := len(counter16) - 1; i >= 0; i-- {
		counter16[i]++
		if counter16[i] != 0 {
			return
		}
	}
}

// CTR applies standard big-endian CTR mode:
// out = in XOR E(key, counter+i), with counter treated as a big-endian 128-bit integer.
func (cipher *PlainSM4Cipher) CTR(iv16, in []byte) []byte {
	if len(iv16) != 16 {
		panic("PlainSM4Cipher.CTR: iv must be 16 bytes")
	}

	out := make([]byte, len(in))

	counter := make([]byte, 16)
	copy(counter, iv16)

	for off := 0; off < len(in); off += 16 {
		ks := cipher.EncryptBlock(counter)

		n := 16
		if off+n > len(in) {
			n = len(in) - off
		}
		for i := 0; i < n; i++ {
			out[off+i] = in[off+i] ^ ks[i]
		}

		inc128BE(counter)
	}

	return out
}

// SM4CTR applies CTR mode with a one-shot SM4 context.
func SM4CTR(key16, iv16, in []byte) []byte {
	return NewPlainSM4Cipher(key16).CTR(iv16, in)
}
