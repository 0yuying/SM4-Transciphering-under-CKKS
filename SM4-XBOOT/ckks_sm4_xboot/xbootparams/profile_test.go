package xbootparams

import (
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestDefaultProfile(t *testing.T) {
	profile := Default(DefaultLogN)
	params, btpParams, err := profile.Build()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := params.QCount(), 14; got != want {
		t.Fatalf("QCount=%d, want %d", got, want)
	}
	if got, want := params.PCount(), 5; got != want {
		t.Fatalf("PCount=%d, want %d", got, want)
	}
	if got, want := btpParams.SlotsToCoeffsParameters.LevelQ, 1; got != want {
		t.Fatalf("SlotsToCoeffs.LevelQ=%d, want %d", got, want)
	}
	if got, want := btpParams.CircuitOrder, bootstrapping.DecodeThenModUp; got != want {
		t.Fatalf("CircuitOrder=%d, want %d", got, want)
	}
	if got, want := len(Grid(DefaultLogN)), 72; got != want {
		t.Fatalf("grid size=%d, want %d", got, want)
	}
}

func TestPairedXBOOTRecoversParityAtSM4Bounds(t *testing.T) {
	if testing.Short() {
		t.Skip("XBOOT key generation is intentionally skipped by go test -short")
	}

	params, btpParams, err := Default(DefaultLogN).Build()
	if err != nil {
		t.Fatal(err)
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := bootstrapping.NewEvaluator(btpParams, evk)
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	decryptor := rlwe.NewDecryptor(params, sk)

	encrypt := func(values []float64) *rlwe.Ciphertext {
		pt := ckks.NewPlaintext(params, evaluator.SlotsToCoeffsParameters.LevelQ)
		if err := encoder.Encode(values, pt); err != nil {
			t.Fatal(err)
		}
		ct, err := encryptor.EncryptNew(pt)
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}
	decode := func(ct *rlwe.Ciphertext) []float64 {
		values := make([]float64, params.MaxSlots())
		if err := encoder.Decode(decryptor.DecryptNew(ct), values); err != nil {
			t.Fatal(err)
		}
		return values
	}

	for _, terms := range []int{42, 124, 256} {
		realWant := xbootValues(params.MaxSlots(), terms)
		imagWant := xbootValues(params.MaxSlots(), terms+1)
		real, imag, err := evaluator.BootstrapCmplxThenDivide(encrypt(realWant), encrypt(imagWant))
		if err != nil {
			t.Fatalf("terms=%d: %v", terms, err)
		}
		assertParity := func(component string, have, want []float64) {
			for slot := range want {
				parity := float64(int64(want[slot]) & 1)
				if diff := math.Abs(have[slot] - parity); diff > DefaultEngineeringError {
					t.Fatalf("terms=%d component=%s slot=%d: have=%g want=%g diff=%g", terms, component, slot, have[slot], parity, diff)
				}
			}
		}
		assertParity("real", decode(real), realWant)
		assertParity("imag", decode(imag), imagWant)
	}
}

func xbootValues(slots, terms int) []float64 {
	values := make([]float64, slots)
	for i := range values {
		switch i % 4 {
		case 0:
			values[i] = float64(terms)
		case 1:
			values[i] = float64(terms - 1)
		case 2:
			values[i] = float64((terms + 1) / 2)
		case 3:
			values[i] = float64(terms / 3)
		}
	}
	return values
}
