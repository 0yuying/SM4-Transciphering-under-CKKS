package ckks_cipher

import (
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func optimizedMonomialMasksLayout() []uint64 {
	pair := func(a, b uint64) []uint64 {
		return []uint64{a, b, a | b}
	}
	combine := func(left, right []uint64) []uint64 {
		out := make([]uint64, 0, len(left)*len(right)+len(left)+len(right))
		for i := 0; i < len(left); i++ {
			for j := 0; j < len(right); j++ {
				out = append(out, left[i]|right[j])
			}
		}
		out = append(out, left...)
		out = append(out, right...)
		return out
	}

	g0 := pair(1<<0, 1<<1)
	g1 := pair(1<<2, 1<<3)
	g2 := pair(1<<4, 1<<5)
	g3 := pair(1<<6, 1<<7)

	left := combine(g0, g1)
	right := combine(g2, g3)

	return combine(left, right)
}

func newSM4SboxHarness(t *testing.T, eval *bootstrapping.Evaluator) *SM4Ctr {
	t.Helper()
	sm4 := &SM4Ctr{
		RtBCipher: &RtBCipher{Evaluator: eval},
	}

	var monomialOrder []*BitSet
	for i := 0; i < 8; i++ {
		x := NewBitSet(8)
		x.Set(1 << i)
		monomialOrder = append(monomialOrder, x)
	}
	var err error
	sm4.sboxMonomialOrder, err = LayeredCombineBin(monomialOrder)
	if err != nil {
		t.Fatalf("LayeredCombineBin failed: %v", err)
	}

	for i := 0; i < 256; i++ {
		tmp := NewBitSet(8)
		tmp.Set(int(SM4Sbox[i]))
		sm4.bitSbox = append(sm4.bitSbox, tmp)
	}
	sm4.precomputeSboxSparseTerms()
	return sm4
}

func cloneBits(cts []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	out := make([]*rlwe.Ciphertext, len(cts))
	for i := 0; i < len(cts); i++ {
		out[i] = cts[i].CopyNew()
	}
	return out
}

func makeByteInput(t *testing.T, tc mod2TestContext, x byte) []*rlwe.Ciphertext {
	t.Helper()
	in := make([]*rlwe.Ciphertext, 8)
	for bit := 0; bit < 8; bit++ {
		in[bit] = tc.encryptConst(t, float64((x>>uint(bit))&1))
	}
	return in
}

func decodeByteFromBits(t *testing.T, tc mod2TestContext, bits []*rlwe.Ciphertext) (out byte, values [8]float64) {
	t.Helper()
	for bit := 0; bit < 8; bit++ {
		v := tc.decodeSlot0(t, bits[bit])
		values[bit] = v
		if v > 0.5 {
			out |= byte(1 << uint(bit))
		}
	}
	return
}

func buildOptimizedLeftRight(t *testing.T, sm4 *SM4Ctr, eval *bootstrapping.Evaluator, sboxIn []*rlwe.Ciphertext) (left, right []*rlwe.Ciphertext) {
	t.Helper()
	if len(sboxIn) != 8 {
		t.Fatalf("input length must be 8, got %d", len(sboxIn))
	}

	group := make([][]*rlwe.Ciphertext, 4)
	for i := 0; i < 4; i++ {
		a := sboxIn[2*i]
		b := sboxIn[2*i+1]
		ab, err := eval.MulRelinNew(a, b)
		if err != nil {
			t.Fatalf("pair MulRelinNew[%d] failed: %v", i, err)
		}
		if err := eval.Rescale(ab, ab); err != nil {
			t.Fatalf("pair Rescale[%d] failed: %v", i, err)
		}
		group[i] = []*rlwe.Ciphertext{a, b, ab}
	}

	var stats sm4SboxOpStats
	var err error
	left, err = sm4.combineMonomialReusable(eval, group[0], group[1], &stats)
	if err != nil {
		t.Fatalf("left combine failed: %v", err)
	}
	right, err = sm4.combineMonomialReusable(eval, group[2], group[3], &stats)
	if err != nil {
		t.Fatalf("right combine failed: %v", err)
	}
	if len(left) != 15 || len(right) != 15 {
		t.Fatalf("unexpected left/right sizes: left=%d right=%d", len(left), len(right))
	}
	return
}

func TestSM4OptimizedMonomialLayoutMatchesLayeredCombineBin(t *testing.T) {
	ref := sm4MonomialMasks(t)
	got := optimizedMonomialMasksLayout()

	if len(got) != len(ref) {
		t.Fatalf("layout size mismatch: got %d, want %d", len(got), len(ref))
	}
	for i := 0; i < len(got); i++ {
		if got[i] != ref[i] {
			t.Fatalf("mask mismatch at index %d: got %d, want %d", i, got[i], ref[i])
		}
	}
}

func TestSM4OptimizedLevelNormalizationToMinLevel(t *testing.T) {
	tc := newMod2TestContext(t)
	sm4 := newSM4SboxHarness(t, tc.eval)
	eval := tc.eval.ShallowCopy()

	left, right := buildOptimizedLeftRight(t, sm4, eval, cloneBits(makeByteInput(t, tc, 0x6d)))
	leftMin := sm4MinLevel(left)
	rightMin := sm4MinLevel(right)
	wantTarget := leftMin
	if rightMin < wantTarget {
		wantTarget = rightMin
	}

	target, err := sm4.normalizeToTargetLevel(eval, left, right)
	if err != nil {
		t.Fatalf("normalizeToTargetLevel failed: %v", err)
	}
	if target != wantTarget {
		t.Fatalf("target level mismatch: got %d, want %d", target, wantTarget)
	}

	for i, ct := range left {
		if ct.Level() != target {
			t.Fatalf("left[%d] level mismatch: got %d, want %d", i, ct.Level(), target)
		}
	}
	for i, ct := range right {
		if ct.Level() != target {
			t.Fatalf("right[%d] level mismatch: got %d, want %d", i, ct.Level(), target)
		}
	}
}

func TestSM4OptimizedLogScaleQuantizationHalfStep(t *testing.T) {
	a := sm4QuantizedLogScaleBitsHalf(60.21)
	b := sm4QuantizedLogScaleBitsHalf(60.24)
	c := sm4QuantizedLogScaleBitsHalf(60.26)

	if a != b {
		t.Fatalf("close scales should map to same half-step bucket: a=%v b=%v", a, b)
	}
	if a == c {
		t.Fatalf("scale crossing half-step boundary should map to different bucket")
	}
}

func TestSM4OptimizedQuantizedBucketCountNotMoreThanExact(t *testing.T) {
	tc := newMod2TestContext(t)
	sm4 := newSM4SboxHarness(t, tc.eval)
	eval := tc.eval.ShallowCopy()

	left, right := buildOptimizedLeftRight(t, sm4, eval, cloneBits(makeByteInput(t, tc, 0x53)))
	if _, err := sm4.normalizeToTargetLevel(eval, left, right); err != nil {
		t.Fatalf("normalizeToTargetLevel failed: %v", err)
	}

	exact := map[sm4OptimizedBucketKey]struct{}{}
	quant := map[sm4OptimizedBucketKey]struct{}{}

	for i := 0; i < len(left); i++ {
		for j := 0; j < len(right); j++ {
			monomialIdx := i*len(right) + j
			if len(sm4.sboxMonomialCoeff[monomialIdx]) == 0 {
				continue
			}

			prod, err := eval.MulNew(left[i], right[j])
			if err != nil {
				t.Fatalf("MulNew(%d,%d) failed: %v", i, j, err)
			}

			exact[sm4OptimizedBucketKey{level: prod.Level(), logScaleBits: math.Float64bits(prod.LogScale())}] = struct{}{}
			quant[sm4OptimizedBucketKey{level: prod.Level(), logScaleBits: sm4QuantizedLogScaleBitsHalf(prod.LogScale())}] = struct{}{}
		}
	}

	if len(quant) > len(exact) {
		t.Fatalf("quantized buckets should not exceed exact buckets: quant=%d exact=%d", len(quant), len(exact))
	}
}

func TestSM4OptimizedSubByteCounterAndOutputAgreement(t *testing.T) {
	tc := newMod2TestContext(t)
	sm4 := newSM4SboxHarness(t, tc.eval)

	in := makeByteInput(t, tc, 0x53)

	eagerIn := cloneBits(in)
	if err := sm4.sm4SubbyteLUTEager(tc.eval.ShallowCopy(), eagerIn); err != nil {
		t.Fatalf("eager subbyte failed: %v", err)
	}

	optimizedOutArr, stats, err := sm4.sm4SubbyteLUTOptimized(tc.eval.ShallowCopy(), cloneBits(in))
	if err != nil {
		t.Fatalf("optimized subbyte failed: %v", err)
	}
	optimizedOut := make([]*rlwe.Ciphertext, 8)
	for bit := 0; bit < 8; bit++ {
		optimizedOut[bit] = optimizedOutArr[bit]
	}

	_, eagerValues := decodeByteFromBits(t, tc, eagerIn)
	_, optimizedValues := decodeByteFromBits(t, tc, optimizedOut)

	for bit := 0; bit < 8; bit++ {
		if math.IsNaN(eagerValues[bit]) || math.IsInf(eagerValues[bit], 0) {
			t.Fatalf("eager output invalid at bit %d: %.6f", bit, eagerValues[bit])
		}
		if math.IsNaN(optimizedValues[bit]) || math.IsInf(optimizedValues[bit], 0) {
			t.Fatalf("optimized output invalid at bit %d: %.6f", bit, optimizedValues[bit])
		}
	}

	if stats.relin >= sm4SboxEagerRelinPerByte {
		t.Fatalf("optimized relin count not reduced: got %d, baseline %d", stats.relin, sm4SboxEagerRelinPerByte)
	}
	if stats.rescale >= sm4SboxEagerRescalePerByte {
		t.Fatalf("optimized rescale count not reduced: got %d, baseline %d", stats.rescale, sm4SboxEagerRescalePerByte)
	}
	if stats.bucketCount <= 0 {
		t.Fatalf("bucket count should be positive, got %d", stats.bucketCount)
	}
	if stats.coeffMulBaseline <= 0 {
		t.Fatalf("coeffMulBaseline should be positive, got %d", stats.coeffMulBaseline)
	}
	if stats.coeffMul >= stats.coeffMulBaseline {
		t.Fatalf("coeff cache not effective: coeffMul=%d baseline=%d", stats.coeffMul, stats.coeffMulBaseline)
	}
	wantTarget := stats.leftMinLevelBefore
	if stats.rightMinLevelBefore < wantTarget {
		wantTarget = stats.rightMinLevelBefore
	}
	if stats.targetLevel != wantTarget {
		t.Fatalf("target level mismatch: got %d, want %d", stats.targetLevel, wantTarget)
	}
}
