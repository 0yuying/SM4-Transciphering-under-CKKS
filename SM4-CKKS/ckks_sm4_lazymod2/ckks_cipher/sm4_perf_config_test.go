package ckks_cipher

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func mustParamsWithLogN(t *testing.T, logN int) ckks.Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            logN,
		LogQ:            []int{45, 35},
		LogP:            []int{45},
		LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatalf("ckks.NewParametersFromLiteral(logN=%d) failed: %v", logN, err)
	}
	return params
}

func TestFixedLazyMod2Policy(t *testing.T) {
	sm4Short := &SM4Ctr{RtBCipher: &RtBCipher{params: mustParamsWithLogN(t, 9)}}
	if sm4Short.useLazyMod2() {
		t.Fatalf("useLazyMod2 should be false when LogN<=9")
	}

	sm4Large := &SM4Ctr{RtBCipher: &RtBCipher{params: mustParamsWithLogN(t, 10)}}
	if !sm4Large.useLazyMod2() {
		t.Fatalf("useLazyMod2 should be true when LogN>9")
	}
}

func TestLazyMod2BootstrapRejectsShortParams(t *testing.T) {
	sm4 := &SM4Ctr{RtBCipher: &RtBCipher{params: mustParamsWithLogN(t, 9)}}
	cts := []*rlwe.Ciphertext{{}, {}}
	err := sm4.bootstrapBitsCmplxThenDivideLazyMod2(cts, 1, "tmp")
	if err == nil {
		t.Fatalf("expected lazy-mod2 path to reject short parameters")
	}
	if !strings.Contains(err.Error(), "unsupported for short parameters") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetWorkerConfigResetsEvalPools(t *testing.T) {
	sm4 := &SM4Ctr{}
	sm4.bootstrapEvalPool = make([]*bootstrapping.Evaluator, 2)
	sm4.sboxEvalPool = make([]*bootstrapping.Evaluator, 2)

	sm4.SetWorkerConfig(3, 4)

	if sm4.bootstrapWorkers != 3 || sm4.sboxWorkers != 4 {
		t.Fatalf("worker config mismatch: bootstrap=%d sbox=%d", sm4.bootstrapWorkers, sm4.sboxWorkers)
	}
	if sm4.bootstrapEvalPool != nil || sm4.sboxEvalPool != nil {
		t.Fatalf("SetWorkerConfig should reset eval pools")
	}
}

func TestFinalOutputBitCountOnlyTrimsSinglePartialBlock(t *testing.T) {
	sm4 := &SM4Ctr{blockSize: 128}

	if got := sm4.finalOutputBitCount(40, 1); got != 40 {
		t.Fatalf("single partial block should trim to requested bits: got %d", got)
	}
	if got := sm4.finalOutputBitCount(128, 1); got != 128 {
		t.Fatalf("full block should keep all bits: got %d", got)
	}
	if got := sm4.finalOutputBitCount(200, 2); got != 128 {
		t.Fatalf("multi-block SIMD output needs all bit positions: got %d", got)
	}
	if got := sm4.finalOutputBitCount(0, 0); got != 128 {
		t.Fatalf("zero-bit legacy path should keep block width: got %d", got)
	}
}

func TestEvenBootstrapBitCount(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		maxBits int
		want    int
	}{
		{name: "zero", bits: 0, maxBits: 128, want: 0},
		{name: "even", bits: 40, maxBits: 128, want: 40},
		{name: "odd", bits: 41, maxBits: 128, want: 42},
		{name: "capped", bits: 129, maxBits: 128, want: 128},
	}

	for _, tt := range tests {
		if got := evenBootstrapBitCount(tt.bits, tt.maxBits); got != tt.want {
			t.Fatalf("%s: got %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestWarmupKeyScheduleCompatAliasUsesCacheFastPath(t *testing.T) {
	sm4 := &SM4Ctr{keyCacheReady: true}

	// Should be a no-op and must not panic even without encoder/encryptor.
	sm4.WarmupKeySchedule()
	sm4.EncryptKey()
}

func TestLogfRespectsProgress(t *testing.T) {
	var buf bytes.Buffer
	sm4 := &SM4Ctr{
		progress:  false,
		logWriter: &buf,
	}

	sm4.logf(true, "progress-only\n")
	if buf.Len() != 0 {
		t.Fatalf("progress-only log should be suppressed when progress=false, got %q", buf.String())
	}

	sm4.logf(false, "always\n")
	if !strings.Contains(buf.String(), "always") {
		t.Fatalf("always log missing, got %q", buf.String())
	}

	buf.Reset()
	sm4.progress = true
	sm4.logf(true, "enabled\n")
	if !strings.Contains(buf.String(), "enabled") {
		t.Fatalf("progress log missing when progress=true, got %q", buf.String())
	}
}

func TestHEDecryptRejectsTooManyBlocks(t *testing.T) {
	params := mustParamsWithLogN(t, 10)
	sm4 := &SM4Ctr{
		RtBCipher: &RtBCipher{params: params},
		blockSize: 128,
	}

	_, err := sm4.HEDecrypt(nil, (params.MaxSlots()+1)*sm4.blockSize)
	if err == nil {
		t.Fatalf("expected HEDecrypt to reject numBlock > MaxSlots")
	}
	if !strings.Contains(err.Error(), "exceeds max slots") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShallowCopyCreatesIndependentWorkerState(t *testing.T) {
	tc := newMod2TestContext(t)
	cachedRK := [][]*rlwe.Ciphertext{{tc.encryptConst(t, 1)}}
	sm4 := &SM4Ctr{
		RtBCipher: &RtBCipher{
			Evaluator:      tc.eval,
			params:         tc.params,
			encoder:        tc.encoder,
			encryptor:      tc.encryptor,
			decryptor:      tc.decryptor,
			totalLevel:     tc.params.MaxLevel(),
			remainingLevel: tc.params.MaxLevel(),
		},
		iv:                  []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		blockSize:           128,
		keySize:             128,
		rounds:              32,
		progress:            true,
		allZeroIn:           true,
		rkEncrypted:         cachedRK,
		keyCacheReady:       true,
		bootstrapWorkers:    2,
		sboxWorkers:         3,
		legacyTwoBootRounds: true,
	}
	sm4.inputEncrypted = []*rlwe.Ciphertext{tc.encryptConst(t, 0)}
	sm4.encodeCipher = []*rlwe.Ciphertext{tc.encryptConst(t, 0)}
	sm4.slotFloatScratch = []float64{1}

	worker := sm4.ShallowCopy()

	if worker == sm4 || worker.RtBCipher == sm4.RtBCipher {
		t.Fatal("ShallowCopy should return a distinct SM4Ctr/RtBCipher instance")
	}
	if worker.Evaluator == sm4.Evaluator || worker.encoder == sm4.encoder || worker.encryptor == sm4.encryptor || worker.decryptor == sm4.decryptor {
		t.Fatal("ShallowCopy should allocate worker-local evaluator/encoder/encryptor/decryptor")
	}
	if worker.allZeroIn != sm4.allZeroIn || worker.bootstrapWorkers != sm4.bootstrapWorkers || worker.sboxWorkers != sm4.sboxWorkers || worker.legacyTwoBootRounds != sm4.legacyTwoBootRounds {
		t.Fatal("ShallowCopy should preserve configuration snapshot")
	}
	if len(worker.inputEncrypted) != 0 || len(worker.encodeCipher) != 0 || len(worker.slotFloatScratch) != 0 {
		t.Fatal("ShallowCopy should start with fresh runtime scratch/buffers")
	}
	if worker.rkEncrypted[0][0] != sm4.rkEncrypted[0][0] {
		t.Fatal("ShallowCopy should reuse cached encrypted round keys")
	}
	worker.iv[0] = 255
	if sm4.iv[0] == 255 {
		t.Fatal("ShallowCopy should copy IV instead of aliasing it")
	}
}

func TestEncodeCiphertextClearsDirtyTailOnShortInputReuse(t *testing.T) {
	tc := newMod2TestContext(t)
	sm4 := &SM4Ctr{
		RtBCipher: &RtBCipher{
			Evaluator:      tc.eval,
			params:         tc.params,
			encoder:        tc.encoder,
			encryptor:      tc.encryptor,
			remainingLevel: tc.params.MaxLevel(),
		},
		blockSize: 128,
	}

	sm4.EncodeCiphertext(bytes.Repeat([]byte{0xff}, 16), 1)
	sm4.EncodeCiphertext([]byte{0x01}, 1)

	want := make([]byte, 16)
	want[0] = 0x01
	if got := sm4.cipherBitScratch[0].BlockBytesBE(); !bytes.Equal(got, want) {
		t.Fatalf("dirty tail remained after short input reuse: got %x, want %x", got, want)
	}
}

func cloneWord(ct *rlwe.Ciphertext) []*rlwe.Ciphertext {
	out := make([]*rlwe.Ciphertext, 32)
	for i := range out {
		out[i] = ct.CopyNew()
	}
	return out
}

func assertWordApproxEqual(t *testing.T, tc mod2TestContext, got, want []*rlwe.Ciphertext, tol float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("word length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		g := tc.decodeSlot0(t, got[i])
		w := tc.decodeSlot0(t, want[i])
		if math.Abs(g-w) > tol {
			t.Fatalf("word[%d] mismatch: got %.8f, want %.8f, tol %.2e", i, g, w, tol)
		}
	}
}

func TestWordHelperConsistency(t *testing.T) {
	tc := newMod2TestContext(t)
	sm4 := &SM4Ctr{RtBCipher: &RtBCipher{Evaluator: tc.eval}}

	a := tc.encryptConst(t, 1)
	b := tc.encryptConst(t, 0)
	fxorWrap := sm4.WordFXORNew(cloneWord(a), cloneWord(b))
	fxorEval := sm4.wordFXORNewWithEval(sm4.Evaluator.ShallowCopy(), cloneWord(a), cloneWord(b))
	assertWordApproxEqual(t, tc, fxorWrap, fxorEval, 1e-6)

	in4 := tc.encryptConst(t, 3)
	mod4Wrap := sm4.WordMod2Reduce4New(cloneWord(in4))
	mod4Eval := sm4.wordMod2Reduce4NewWithEval(sm4.Evaluator.ShallowCopy(), cloneWord(in4))
	assertWordApproxEqual(t, tc, mod4Wrap, mod4Eval, 1e-6)

	in6 := tc.encryptConst(t, 5)
	mod6Wrap := sm4.WordMod2Reduce6New(cloneWord(in6))
	mod6Eval := sm4.wordMod2Reduce6NewWithEval(sm4.Evaluator.ShallowCopy(), cloneWord(in6))
	assertWordApproxEqual(t, tc, mod6Wrap, mod6Eval, 1e-6)
}
