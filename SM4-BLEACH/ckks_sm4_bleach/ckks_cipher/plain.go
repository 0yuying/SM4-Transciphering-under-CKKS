package ckks_cipher

import (
	"encoding/hex"
	"fmt"
)

// =====================
// 1) 提供明文 SM4-CTR（LE）参考实现，用来对拍 HE 侧 keystream / 解密结果
// 2) 不重复定义 sm4_ctr.go 已有的 FK/CK/tau/lPrime/rotl32/loadU32BE/keySchedule
//
// 端序/比特约定：与 sm4_ctr.go 保持一致：
// - loadU32BE 实际按 LE 读取（你在 sm4_ctr.go 已改成 LE）
// - tau 也是按 LE 字节顺序做 SBox
// - round key 从 sm4KeySchedulePlain 得到（LE 语义）
// =====================

// storeU32LE: 把 uint32 按 LE 存到 out[0:4]
func storeU32LE(x uint32, out []byte) {
	out[0] = byte(x)
	out[1] = byte(x >> 8)
	out[2] = byte(x >> 16)
	out[3] = byte(x >> 24)
}

// SM4 的 L：b ^ (b<<<2) ^ (b<<<10) ^ (b<<<18) ^ (b<<<24)
// 这里使用 sm4_ctr.go 已有的 rotl32
func sm4L(b uint32) uint32 {
	return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
}

// SM4EncryptBlockLE: 明文单块加密（16B -> 16B）
// - 使用 sm4_ctr.go 的：loadU32BE(实际上LE)、tau(LE)、sm4KeySchedulePlain(LE语义)
func SM4EncryptBlockLE(key16, in16 []byte) [16]byte {
	if len(key16) != 16 {
		panic("SM4EncryptBlockLE: key must be 16 bytes")
	}
	if len(in16) != 16 {
		panic("SM4EncryptBlockLE: input must be 16 bytes")
	}

	// 复用 sm4_ctr.go 的 key schedule（LE 语义）
	// 注意：sm4KeySchedulePlain 是 SM4Ctr 的方法，这里构造一个临时对象只为调用它
	tmp := &SM4Ctr{}
	rk := tmp.sm4KeySchedulePlain(key16) // [32]uint32

	// X0..X3（LE 装载：使用 loadU32BE，但它在 sm4_ctr.go 里已改成 LE）
	X := make([]uint32, 36)
	X[0] = loadU32BE(in16[0:4])
	X[1] = loadU32BE(in16[4:8])
	X[2] = loadU32BE(in16[8:12])
	X[3] = loadU32BE(in16[12:16])

	// 32 rounds
	for i := 0; i < 32; i++ {
		// tmp = X1 ^ X2 ^ X3 ^ rk
		t := X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]
		// τ（LE）
		t = tmp.tau(t)
		// L（加密轮的 L，不是 key schedule 的 L'）
		t = sm4L(t)
		// X[i+4] = X[i] ^ t
		X[i+4] = X[i] ^ t
	}

	// 反序输出：X35, X34, X33, X32（按 LE store）
	var out [16]byte
	storeU32LE(X[35], out[0:4])
	storeU32LE(X[34], out[4:8])
	storeU32LE(X[33], out[8:12])
	storeU32LE(X[32], out[12:16])
	return out
}

// inc128LE: 把 16 字节视为 LE 的 128-bit 整数，自增 1
// byte0 是最低字节，先加 byte0，溢出再进位
func inc128LE(counter16 []byte) {
	for i := 0; i < 16; i++ {
		counter16[i]++
		if counter16[i] != 0 {
			return
		}
	}
}

// SM4CTRLE: 明文 CTR 加/解密（同函数）
// out = in XOR E(key, counter+i)
// - counter 采用 LE 的 128-bit 自增
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

// =====================
// 可选：调试对拍 helpers
// =====================

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// DebugPlainSM4CTRLE: 用于快速验证 plain CTR 与 HE 侧是否对齐
func DebugPlainSM4CTRLE() {
	key := mustHex("0123456789abcdeffedcba9876543210")
	iv := make([]byte, 16) // all-zero counter start（LE）
	pt := mustHex("00112233445566778899aabbccddeeff")

	ct := SM4CTRLE(key, iv, pt)
	fmt.Printf("CT = %x\n", ct)

	pt2 := SM4CTRLE(key, iv, ct)
	fmt.Printf("PT = %x\n", pt2)
}
