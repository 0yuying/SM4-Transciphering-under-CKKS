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
	if c1.bits[0] != 1 || c1.bits[1] != 0 {
		t.Fatalf("ctr=1 mapping wrong: bit0=%d bit1=%d", c1.bits[0], c1.bits[1])
	}

	c2 := ctr(iv, 2)
	if c2.bits[0] != 0 || c2.bits[1] != 1 {
		t.Fatalf("ctr=2 mapping wrong: bit0=%d bit1=%d", c2.bits[0], c2.bits[1])
	}
}

func TestCTRCarryToHighBits(t *testing.T) {
	iv := NewBitSet(128)
	for i := 0; i < 64; i++ {
		iv.bits[i] = 1
	}

	out := ctr(iv, 1)
	for i := 0; i < 64; i++ {
		if out.bits[i] != 0 {
			t.Fatalf("carry reset failed at bit %d: got %d, want 0", i, out.bits[i])
		}
	}
	if out.bits[64] != 1 {
		t.Fatalf("carry into bit64 failed: got %d, want 1", out.bits[64])
	}
}

func TestBitSetToULongKeepsHighBits(t *testing.T) {
	b := NewBitSet(128)
	b.bits[9] = 1
	if got := b.ToULong(); got != 1<<9 {
		t.Fatalf("ToULong high-bit mapping failed: got %d, want %d", got, 1<<9)
	}
}
