package ckks_cipher

import (
	"bytes"
	"testing"
)

func TestBlockBytesBERoundTrip(t *testing.T) {
	block := mustHex("0123456789abcdeffedcba9876543210")
	bits := NewBitSet(128)
	bits.SetBlockBytesBE(block)

	if got := bits.BlockBytesBE(); !bytes.Equal(got, block) {
		t.Fatalf("BlockBytesBE round-trip mismatch: got %x, want %x", got, block)
	}
}

func TestSM4EncryptBlock_StandardVector(t *testing.T) {
	key := mustHex("0123456789abcdeffedcba9876543210")
	pt := mustHex("0123456789abcdeffedcba9876543210")
	want := mustHex("681edf34d206965e86b3e94f536e4246")

	got := SM4EncryptBlock(key, pt)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("SM4EncryptBlock mismatch: got %x, want %x", got, want)
	}
}

func TestSM4CTR_RoundTrip(t *testing.T) {
	key := mustHex("0123456789abcdeffedcba9876543210")
	iv := mustHex("00000000000000000000000000000000")
	pt := mustHex("00112233445566778899aabbccddeeff10203040")
	wantCT := mustHex("2666d6584d9444bb1fcc99ab97094cd55e796bb0")

	ct := SM4CTR(key, iv, pt)
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("SM4CTR ciphertext mismatch: got %x, want %x", ct, wantCT)
	}

	pt2 := SM4CTR(key, iv, ct)
	if !bytes.Equal(pt2, pt) {
		t.Fatalf("SM4CTR round-trip mismatch: got %x, want %x", pt2, pt)
	}
}

func TestPlainSM4CipherWrappersCompatible(t *testing.T) {
	key := mustHex("0123456789abcdeffedcba9876543210")
	iv := mustHex("000000000000000000000000000000ff")
	plain := mustHex("00112233445566778899aabbccddeeff102030405060708090")
	cipher := NewPlainSM4Cipher(key)

	if got, want := cipher.EncryptBlock(plain[:16]), SM4EncryptBlock(key, plain[:16]); !bytes.Equal(got[:], want[:]) {
		t.Fatalf("EncryptBlock wrapper mismatch: got %x, want %x", got, want)
	}
	if got, want := cipher.CTR(iv, plain), SM4CTR(key, iv, plain); !bytes.Equal(got, want) {
		t.Fatalf("CTR wrapper mismatch: got %x, want %x", got, want)
	}
}

func TestPlainSM4CipherCTRArbitraryLengths(t *testing.T) {
	key := mustHex("0123456789abcdeffedcba9876543210")
	iv := mustHex("00000000000000000000000000000000")
	cipher := NewPlainSM4Cipher(key)

	for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33} {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i*17 + 3)
		}
		encrypted := cipher.CTR(iv, plain)
		if got := cipher.CTR(iv, encrypted); !bytes.Equal(got, plain) {
			t.Fatalf("CTR round-trip size=%d mismatch: got %x, want %x", size, got, plain)
		}
	}
}

func TestPlainSM4CipherCTRCounterCarry(t *testing.T) {
	key := mustHex("0123456789abcdeffedcba9876543210")
	iv := mustHex("000000000000000000000000000000ff")
	cipher := NewPlainSM4Cipher(key)
	got := cipher.CTR(iv, make([]byte, 32))

	first := cipher.EncryptBlock(iv)
	next := mustHex("00000000000000000000000000000100")
	second := cipher.EncryptBlock(next)
	want := append(first[:], second[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("CTR carry mismatch: got %x, want %x", got, want)
	}
}

func TestCTRBigEndianCounterIncrement(t *testing.T) {
	iv := NewBitSet(128)
	iv.SetBlockBytesBE(make([]byte, 16))

	out := ctr(iv, 1)
	want := make([]byte, 16)
	want[15] = 1

	if got := out.BlockBytesBE(); !bytes.Equal(got, want) {
		t.Fatalf("big-endian ctr increment mismatch: got %x, want %x", got, want)
	}
}

func TestCTRBigEndianCarryToNextByte(t *testing.T) {
	iv := NewBitSet(128)
	start := make([]byte, 16)
	start[15] = 0xff
	iv.SetBlockBytesBE(start)

	out := ctr(iv, 1)
	want := make([]byte, 16)
	want[14] = 0x01

	if got := out.BlockBytesBE(); !bytes.Equal(got, want) {
		t.Fatalf("big-endian ctr carry mismatch: got %x, want %x", got, want)
	}
}

func TestBitSetToULongKeepsHighBits(t *testing.T) {
	b := NewBitSet(128)
	b.SetBit(9, 1)
	if got := b.ToULong(); got != 1<<9 {
		t.Fatalf("ToULong high-bit mapping failed: got %d, want %d", got, 1<<9)
	}
}
