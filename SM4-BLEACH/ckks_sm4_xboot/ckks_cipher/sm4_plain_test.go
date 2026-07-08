package ckks_cipher

import "testing"

func TestSM4CTRLE_RoundTrip(t *testing.T) {
	key := []byte{
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98,
		0x76, 0x54, 0x32, 0x10,
	}
	iv := make([]byte, 16)
	pt := []byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x20, 0x30, 0x40,
	}

	ct := SM4CTRLE(key, iv, pt)
	pt2 := SM4CTRLE(key, iv, ct)

	if len(pt2) != len(pt) {
		t.Fatalf("round-trip length mismatch: got %d, want %d", len(pt2), len(pt))
	}
	for i := range pt {
		if pt2[i] != pt[i] {
			t.Fatalf("round-trip mismatch at byte %d: got %02x, want %02x", i, pt2[i], pt[i])
		}
	}
}

func TestCTRBitMapping(t *testing.T) {
	iv := NewBitSet(128)
	iv.Set(0)

	c1 := ctr(iv, 1)
	if c1.bits[64] != 1 || c1.bits[65] != 0 {
		t.Fatalf("ctr=1 mapping wrong: bit64=%d bit65=%d", c1.bits[64], c1.bits[65])
	}

	c2 := ctr(iv, 2)
	if c2.bits[64] != 0 || c2.bits[65] != 1 {
		t.Fatalf("ctr=2 mapping wrong: bit64=%d bit65=%d", c2.bits[64], c2.bits[65])
	}
}
