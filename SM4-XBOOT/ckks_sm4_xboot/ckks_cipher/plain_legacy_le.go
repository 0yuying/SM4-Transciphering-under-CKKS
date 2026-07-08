package ckks_cipher

// Legacy plain SM4/CTR reference implementation kept only for debug/reference purposes.
// It preserves the historical LE counter/block variant and is not standard CTR interoperable.

func loadU32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func storeU32LE(x uint32, out []byte) {
	out[0] = byte(x)
	out[1] = byte(x >> 8)
	out[2] = byte(x >> 16)
	out[3] = byte(x >> 24)
}

func tauLE(a uint32) uint32 {
	b0 := uint32(SM4Sbox[a&0xff])
	b1 := uint32(SM4Sbox[(a>>8)&0xff])
	b2 := uint32(SM4Sbox[(a>>16)&0xff])
	b3 := uint32(SM4Sbox[(a>>24)&0xff])
	return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

func sm4KeySchedulePlainLE(key []byte) [32]uint32 {
	if len(key) != 16 {
		panic("sm4KeySchedulePlainLE: key must be 16 bytes")
	}

	mk0 := loadU32LE(key[0:4])
	mk1 := loadU32LE(key[4:8])
	mk2 := loadU32LE(key[8:12])
	mk3 := loadU32LE(key[12:16])

	K := make([]uint32, 36)
	K[0] = mk0 ^ sm4FK[0]
	K[1] = mk1 ^ sm4FK[1]
	K[2] = mk2 ^ sm4FK[2]
	K[3] = mk3 ^ sm4FK[3]

	var rk [32]uint32
	for i := 0; i < 32; i++ {
		t := K[i+1] ^ K[i+2] ^ K[i+3] ^ sm4CK[i]
		t = tauLE(t)
		t = (&SM4Ctr{}).lPrime(t)
		K[i+4] = K[i] ^ t
		rk[i] = K[i+4]
	}
	return rk
}

// Deprecated: debug only; legacy LE variant; not standard CTR interoperable.
func SM4EncryptBlockLE(key16, in16 []byte) [16]byte {
	if len(key16) != 16 {
		panic("SM4EncryptBlockLE: key must be 16 bytes")
	}
	if len(in16) != 16 {
		panic("SM4EncryptBlockLE: input must be 16 bytes")
	}

	rk := sm4KeySchedulePlainLE(key16)

	X := make([]uint32, 36)
	X[0] = loadU32LE(in16[0:4])
	X[1] = loadU32LE(in16[4:8])
	X[2] = loadU32LE(in16[8:12])
	X[3] = loadU32LE(in16[12:16])

	for i := 0; i < 32; i++ {
		t := X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]
		t = tauLE(t)
		t = sm4L(t)
		X[i+4] = X[i] ^ t
	}

	var out [16]byte
	storeU32LE(X[35], out[0:4])
	storeU32LE(X[34], out[4:8])
	storeU32LE(X[33], out[8:12])
	storeU32LE(X[32], out[12:16])
	return out
}

func inc128LE(counter16 []byte) {
	for i := 0; i < 16; i++ {
		counter16[i]++
		if counter16[i] != 0 {
			return
		}
	}
}

// Deprecated: debug only; legacy LE variant; not standard CTR interoperable.
func SM4CTRLE(key16, iv16, in []byte) []byte {
	if len(key16) != 16 {
		panic("SM4CTRLE: key must be 16 bytes")
	}
	if len(iv16) != 16 {
		panic("SM4CTRLE: iv must be 16 bytes")
	}

	out := make([]byte, len(in))
	counter := make([]byte, 16)
	copy(counter, iv16)

	for off := 0; off < len(in); off += 16 {
		ks := SM4EncryptBlockLE(key16, counter)

		n := 16
		if off+n > len(in) {
			n = len(in) - off
		}
		for i := 0; i < n; i++ {
			out[off+i] = in[off+i] ^ ks[i]
		}

		inc128LE(counter)
	}

	return out
}
