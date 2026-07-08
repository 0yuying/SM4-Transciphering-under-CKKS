package ckks_cipher

import (
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type mod2TestContext struct {
	params    ckks.Parameters
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	eval      *bootstrapping.Evaluator
}

func newMod2TestContext(t *testing.T) mod2TestContext {
	t.Helper()

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{50, 45, 45, 45, 45, 45},
		LogP:            []int{52},
		LogDefaultScale: 40,
		Xs:              ring.Ternary{H: 64},
	})
	if err != nil {
		t.Fatalf("new params: %v", err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	return mod2TestContext{
		params:    params,
		encoder:   ckks.NewEncoder(params),
		encryptor: rlwe.NewEncryptor(params, pk),
		decryptor: rlwe.NewDecryptor(params, sk),
		eval:      &bootstrapping.Evaluator{Evaluator: ckks.NewEvaluator(params, evk)},
	}
}

func (tc mod2TestContext) encryptConst(t *testing.T, value float64) *rlwe.Ciphertext {
	t.Helper()
	data := make([]float64, tc.params.MaxSlots())
	for i := range data {
		data[i] = value
	}
	pt := ckks.NewPlaintext(tc.params, tc.params.MaxLevel())
	tc.encoder.Encode(data, pt)
	ct, err := tc.encryptor.EncryptNew(pt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return ct
}

func (tc mod2TestContext) decodeSlot0(t *testing.T, ct *rlwe.Ciphertext) float64 {
	t.Helper()
	values := make([]float64, ct.Slots())
	if err := tc.encoder.Decode(tc.decryptor.DecryptNew(ct), values); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return values[0]
}

func TestMod2Reduce2NewTruthTable(t *testing.T) {
	tc := newMod2TestContext(t)
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1, 1},
		{2, 0},
	}

	for _, c := range cases {
		ct := tc.encryptConst(t, c.in)
		out := Mod2Reduce2New(tc.eval, ct)
		got := tc.decodeSlot0(t, out)
		if math.Abs(got-c.want) > 0.30 {
			t.Fatalf("Mod2Reduce2New(%v): got %.6f, want %.1f", c.in, got, c.want)
		}
	}
}

func TestMod2Reduce4NewTruthTable(t *testing.T) {
	tc := newMod2TestContext(t)
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1, 1},
		{2, 0},
		{3, 1},
		{4, 0},
	}

	for _, c := range cases {
		ct := tc.encryptConst(t, c.in)
		out := Mod2Reduce4New(tc.eval, ct)
		got := tc.decodeSlot0(t, out)
		if math.Abs(got-c.want) > 0.40 {
			t.Fatalf("Mod2Reduce4New(%v): got %.6f, want %.1f", c.in, got, c.want)
		}
	}
}
