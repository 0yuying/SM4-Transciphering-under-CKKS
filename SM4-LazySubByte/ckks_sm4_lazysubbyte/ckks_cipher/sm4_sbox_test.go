package ckks_cipher

import "testing"

var sm4SboxANFCoeffs = [8][]int{
	Sbox0[:], Sbox1[:], Sbox2[:], Sbox3[:],
	Sbox4[:], Sbox5[:], Sbox6[:], Sbox7[:],
}

func sm4MonomialMasks(t *testing.T) []uint64 {
	t.Helper()

	variables := make([]*BitSet, 0, 8)
	for i := 0; i < 8; i++ {
		x := NewBitSet(8)
		x.Set(1 << i)
		variables = append(variables, x)
	}

	monomials, err := LayeredCombineBin(variables)
	if err != nil {
		t.Fatalf("LayeredCombineBin failed: %v", err)
	}
	if len(monomials) != 255 {
		t.Fatalf("unexpected monomial count: got %d, want 255", len(monomials))
	}

	masks := make([]uint64, len(monomials))
	seen := make(map[uint64]struct{}, len(monomials))
	for i := 0; i < len(monomials); i++ {
		mask := monomials[i].ToULong()
		if mask == 0 || mask > 255 {
			t.Fatalf("invalid monomial mask at index %d: %d", i, mask)
		}
		if _, ok := seen[mask]; ok {
			t.Fatalf("duplicate monomial mask detected: %d", mask)
		}
		seen[mask] = struct{}{}
		masks[i] = mask
	}
	if len(seen) != 255 {
		t.Fatalf("unexpected unique mask count: got %d, want 255", len(seen))
	}

	return masks
}

func evalSM4ANFBit(x byte, outBit int, monomialMasks []uint64) int {
	sum := int((SM4Sbox[0] >> uint(outBit)) & 1)
	coeffArr := sm4SboxANFCoeffs[outBit]

	for i := 0; i < len(monomialMasks); i++ {
		mask := monomialMasks[i]
		coeff := coeffArr[int(mask)-1]
		if coeff == 0 {
			continue
		}

		prod := 1
		for k := 0; k < 8; k++ {
			if (mask>>uint(k))&1 == 1 && ((x>>uint(k))&1) == 0 {
				prod = 0
				break
			}
		}
		if prod == 1 {
			sum += coeff
		}
	}

	return sum
}

func TestSM4SboxANFMatchesTable(t *testing.T) {
	monomialMasks := sm4MonomialMasks(t)

	for x := 0; x < 256; x++ {
		var out byte
		for bit := 0; bit < 8; bit++ {
			v := evalSM4ANFBit(byte(x), bit, monomialMasks)
			if v != 0 && v != 1 {
				t.Fatalf("non-binary ANF output at x=%d bit=%d: %d", x, bit, v)
			}
			out |= byte(v) << uint(bit)
		}

		if out != SM4Sbox[x] {
			t.Fatalf("SM4 S-box mismatch at x=%d: got 0x%02x, want 0x%02x", x, out, SM4Sbox[x])
		}
	}
}

func TestSM4SboxANFBitRange(t *testing.T) {
	monomialMasks := sm4MonomialMasks(t)

	for x := 0; x < 256; x++ {
		for bit := 0; bit < 8; bit++ {
			v := evalSM4ANFBit(byte(x), bit, monomialMasks)
			if v != 0 && v != 1 {
				t.Fatalf("ANF output out of bit range at x=%d bit=%d: %d", x, bit, v)
			}
		}
	}
}
