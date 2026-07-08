package ckks_cipher

import (
	"math/bits"
	"testing"
)

type sm4JointBoundTerm struct {
	mask  int
	coeff int
}

type sm4JointLazySboxBounds struct {
	min    [8]int
	max    [8]int
	maxAbs [8]int
}

func TestSM4JointLazyScheduleIntegerBounds(t *testing.T) {
	bounds := sm4ComputeJointLazySboxBounds(t)

	wantMin := [8]int{-104436, -62703, -82635, -60144, -350115, -169284, -35103, -100299}
	wantMax := [8]int{56268, 102897, 433521, 60528, 75153, 80092, 155089, 60249}
	wantMaxAbs := [8]int{104436, 102897, 433521, 60528, 350115, 169284, 155089, 100299}

	if bounds.min != wantMin {
		t.Fatalf("S-box integer lower bounds changed: got=%v want=%v", bounds.min, wantMin)
	}
	if bounds.max != wantMax {
		t.Fatalf("S-box integer upper bounds changed: got=%v want=%v", bounds.max, wantMax)
	}
	if bounds.maxAbs != wantMaxAbs {
		t.Fatalf("S-box integer max-abs bounds changed: got=%v want=%v", bounds.maxAbs, wantMaxAbs)
	}

	t.Logf("joint lazy S-box carrier bounds: min=%v max=%v maxAbs=%v", bounds.min, bounds.max, bounds.maxAbs)
}

func TestSM4SboxOutputToLLayerCarrierBounds(t *testing.T) {
	bounds := sm4ComputeJointLazySboxBounds(t)

	maxSboxAbs := sm4MaxIntArray(bounds.maxAbs[:])
	globalLBound := 5 * maxSboxAbs
	globalXiBound := globalLBound + 1
	rotationAwareLBound := sm4RotationAwareLBound(bounds.maxAbs)
	rotationAwareXiBound := rotationAwareLBound + 1

	if maxSboxAbs != 433521 {
		t.Fatalf("max S-box abs bound changed: got=%d want=%d", maxSboxAbs, 433521)
	}
	if globalLBound != 2167605 {
		t.Fatalf("global L-layer bound changed: got=%d want=%d", globalLBound, 2167605)
	}
	if globalXiBound != 2167606 {
		t.Fatalf("global Xi bound changed: got=%d want=%d", globalXiBound, 2167606)
	}
	if rotationAwareLBound != 2000793 {
		t.Fatalf("rotation-aware L-layer bound changed: got=%d want=%d", rotationAwareLBound, 2000793)
	}
	if rotationAwareXiBound != 2000794 {
		t.Fatalf("rotation-aware Xi bound changed: got=%d want=%d", rotationAwareXiBound, 2000794)
	}

	t.Logf("S-box -> L-layer fused-lazy carrier bounds: maxSboxAbs=%d globalL=%d globalXi=%d rotationAwareL=%d rotationAwareXi=%d",
		maxSboxAbs, globalLBound, globalXiBound, rotationAwareLBound, rotationAwareXiBound)
}

func TestSM4OneBootScheduleCarrierBounds(t *testing.T) {
	maxWord := make([]int, 36)
	for i := 0; i < 4; i++ {
		maxWord[i] = 1
	}

	tmpBounds := make([]int, 32)
	maxTmp := 0
	for round := 0; round < 32; round++ {
		tmp := maxWord[round+1] + maxWord[round+2] + maxWord[round+3] + 1
		tmpBounds[round] = tmp
		if tmp > sm4OneBootTmpBound {
			t.Fatalf("round %d tmp carrier bound exceeds LazyMod2 capacity: got=%d max=%d", round+1, tmp, sm4OneBootTmpBound)
		}
		if tmp > maxTmp {
			maxTmp = tmp
		}
		// After tmp is bootstrapped to a bit, S-box/L contributes a parity carrier
		// bounded by five additive terms; x4 then adds the previous x0 carrier.
		maxWord[round+4] = maxWord[round] + 5
	}

	finalMax := 0
	for wordIdx, bound := range maxWord[32:36] {
		if bound > sm4OneBootFinalBound {
			t.Fatalf("final word %d carrier bound exceeds final LazyMod2 capacity: got=%d max=%d", wordIdx, bound, sm4OneBootFinalBound)
		}
		if bound > finalMax {
			finalMax = bound
		}
	}

	if maxTmp != sm4OneBootTmpBound {
		t.Fatalf("one-boot tmp carrier bound changed: got=%d want=%d", maxTmp, sm4OneBootTmpBound)
	}
	if finalMax != sm4OneBootFinalBound {
		t.Fatalf("one-boot final carrier bound changed: got=%d want=%d", finalMax, sm4OneBootFinalBound)
	}

	t.Logf("one-boot schedule carrier bounds: tmp=0..%d final=0..%d tmpBounds=%v wordBounds=%v", maxTmp, finalMax, tmpBounds, maxWord[32:36])
}

func sm4ComputeJointLazySboxBounds(t *testing.T) sm4JointLazySboxBounds {
	t.Helper()

	monomialMasks := sm4MonomialMasks(t)

	var sparse [8][]sm4JointBoundTerm
	for outBit := 0; outBit < 8; outBit++ {
		for _, mask := range monomialMasks {
			coeff := sm4SboxANFCoeffs[outBit][int(mask)-1]
			if coeff == 0 {
				continue
			}
			sparse[outBit] = append(sparse[outBit], sm4JointBoundTerm{
				mask:  int(mask),
				coeff: coeff,
			})
		}
	}

	const inputRange = 5 // tmp bit values are modeled as {0,1,2,3,4}.
	const inputCases = inputRange * inputRange * inputRange * inputRange *
		inputRange * inputRange * inputRange * inputRange

	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1

	bounds := sm4JointLazySboxBounds{}
	for bit := 0; bit < 8; bit++ {
		bounds.min[bit] = maxInt
		bounds.max[bit] = minInt
	}

	var in [8]int
	var monomialValue [256]int

	for caseIdx := 0; caseIdx < inputCases; caseIdx++ {
		x := caseIdx
		parityByte := 0
		for bit := 0; bit < 8; bit++ {
			in[bit] = x % inputRange
			if in[bit]&1 == 1 {
				parityByte |= 1 << bit
			}
			x /= inputRange
		}

		monomialValue[0] = 1
		for mask := 1; mask < len(monomialValue); mask++ {
			lsb := mask & -mask
			bit := bits.TrailingZeros(uint(lsb))
			monomialValue[mask] = monomialValue[mask^lsb] * in[bit]
		}

		for outBit := 0; outBit < 8; outBit++ {
			sum := int((SM4Sbox[0] >> uint(outBit)) & 1)
			for _, term := range sparse[outBit] {
				sum += term.coeff * monomialValue[term.mask]
			}

			wantParity := int((SM4Sbox[parityByte] >> uint(outBit)) & 1)
			if sum&1 != wantParity {
				t.Fatalf("joint integer ANF parity mismatch: input=%v parityByte=0x%02x outBit=%d got=%d want=%d value=%d",
					in, parityByte, outBit, sum&1, wantParity, sum)
			}

			if sum < bounds.min[outBit] {
				bounds.min[outBit] = sum
			}
			if sum > bounds.max[outBit] {
				bounds.max[outBit] = sum
			}
			if abs := sm4AbsInt(sum); abs > bounds.maxAbs[outBit] {
				bounds.maxAbs[outBit] = abs
			}
		}
	}

	return bounds
}

func sm4AbsInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func sm4MaxIntArray(xs []int) int {
	max := 0
	for _, x := range xs {
		if x > max {
			max = x
		}
	}
	return max
}

func sm4RotationAwareLBound(sboxMaxAbs [8]int) int {
	maxBound := 0
	rotations := [...]int{0, 2, 10, 18, 24}
	for bit := 0; bit < 32; bit++ {
		bound := 0
		for _, rot := range rotations {
			sourceBit := (bit - rot) & 31
			bound += sboxMaxAbs[sourceBit&7]
		}
		if bound > maxBound {
			maxBound = bound
		}
	}
	return maxBound
}
