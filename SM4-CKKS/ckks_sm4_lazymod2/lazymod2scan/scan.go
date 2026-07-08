package lazymod2scan

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/lazymod2params"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type Context struct {
	Profile        lazymod2params.Profile
	Params         ckks.Parameters
	BtpParams      bootstrapping.Parameters
	EvaluationKeys *bootstrapping.EvaluationKeys
	Evaluator      *bootstrapping.Evaluator
	Encoder        *ckks.Encoder
	Encryptor      *rlwe.Encryptor
	Decryptor      *rlwe.Decryptor
	Paired         bool
}

type Measurement struct {
	Profile       lazymod2params.Profile
	Mode          string
	Terms         int
	PreMaxError   float64
	PreAvgError   float64
	PostMaxError  float64
	PostAvgError  float64
	WrongSlots    int
	OverTolerance int
	OutputLevel   int
	Duration      time.Duration
}

func NewContext(profile lazymod2params.Profile, paired bool) (*Context, error) {
	params, btpParams, err := profile.Build()
	if err != nil {
		return nil, err
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		return nil, fmt.Errorf("generate bootstrapping keys: %w", err)
	}
	evaluator, err := bootstrapping.NewEvaluator(btpParams, evk)
	if err != nil {
		return nil, fmt.Errorf("new bootstrapping evaluator: %w", err)
	}
	return &Context{
		Profile:        profile,
		Params:         params,
		BtpParams:      btpParams,
		EvaluationKeys: evk,
		Evaluator:      evaluator,
		Encoder:        ckks.NewEncoder(params),
		Encryptor:      rlwe.NewEncryptor(params, pk),
		Decryptor:      rlwe.NewDecryptor(params, sk),
		Paired:         paired,
	}, nil
}

func (ctx *Context) Scan(mode string, checkpoints []int) ([]Measurement, error) {
	checkpoints = normalizedCheckpoints(checkpoints)
	switch mode {
	case "direct":
		var results []Measurement
		for _, terms := range checkpoints {
			values := directValues(ctx.Params.MaxSlots(), terms)
			ct, err := ctx.Encrypt(values)
			if err != nil {
				return nil, err
			}
			result, err := ctx.Measure(mode, terms, ct, values)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		}
		return results, nil
	case "independent":
		return ctx.scanIndependent(checkpoints)
	case "correlated":
		return ctx.scanCorrelated(checkpoints)
	default:
		return nil, fmt.Errorf("unsupported scan mode %q", mode)
	}
}

func (ctx *Context) PassesRequired(results []Measurement) bool {
	for _, result := range results {
		if result.Terms == lazymod2params.SM4MarginBoundary {
			continue
		}
		if result.WrongSlots != 0 || result.PostMaxError >= lazymod2params.LazyMod2Tolerance {
			return false
		}
	}
	return true
}

func (ctx *Context) scanIndependent(checkpoints []int) ([]Measurement, error) {
	maxTerms := checkpoints[len(checkpoints)-1]
	want := make([]float64, ctx.Params.MaxSlots())
	acc, err := ctx.Encrypt(want)
	if err != nil {
		return nil, err
	}
	next := 0
	var results []Measurement
	for term := 0; term < maxTerms; term++ {
		values := bitValues(ctx.Params.MaxSlots(), term)
		ct, err := ctx.Encrypt(values)
		if err != nil {
			return nil, err
		}
		if err := ctx.Evaluator.Add(acc, ct, acc); err != nil {
			return nil, err
		}
		for i := range want {
			want[i] += values[i]
		}
		if term+1 == checkpoints[next] {
			result, err := ctx.Measure("independent", term+1, acc, want)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
			next++
			if next == len(checkpoints) {
				break
			}
		}
	}
	return results, nil
}

func (ctx *Context) scanCorrelated(checkpoints []int) ([]Measurement, error) {
	values := bitValues(ctx.Params.MaxSlots(), 0)
	base, err := ctx.Encrypt(values)
	if err != nil {
		return nil, err
	}
	var results []Measurement
	for _, terms := range checkpoints {
		acc, err := ctx.Evaluator.MulNew(base, terms)
		if err != nil {
			return nil, err
		}
		want := make([]float64, len(values))
		for i := range want {
			want[i] = values[i] * float64(terms)
		}
		result, err := ctx.Measure("correlated", terms, acc, want)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (ctx *Context) Measure(mode string, terms int, ct *rlwe.Ciphertext, want []float64) (Measurement, error) {
	result := Measurement{Profile: ctx.Profile, Mode: mode, Terms: terms}
	pre, err := ctx.DecodeReal(ct)
	if err != nil {
		return result, err
	}
	result.addPreErrors(pre, want)

	var out *rlwe.Ciphertext
	var imagWant []float64
	var imagValues []float64
	start := time.Now()
	if ctx.Paired {
		imagWant = pairedImagValues(ctx.Params.MaxSlots(), terms)
		imagIn, err := ctx.Encrypt(imagWant)
		if err != nil {
			return result, err
		}
		imagPre, err := ctx.DecodeReal(imagIn)
		if err != nil {
			return result, err
		}
		result.addPreErrors(imagPre, imagWant)
		var imag *rlwe.Ciphertext
		out, imag, err = ctx.Evaluator.BootstrapCmplxThenDivideLazyMod2(ct.CopyNew(), imagIn)
		if err != nil {
			return result, err
		}
		imagValues, err = ctx.DecodeReal(imag)
		if err != nil {
			return result, err
		}
	} else {
		out, err = ctx.Evaluator.BootstrapReal(ct.CopyNew())
		if err != nil {
			return result, err
		}
	}
	result.Duration = time.Since(start)
	result.OutputLevel = out.Level()

	have, err := ctx.DecodeReal(out)
	if err != nil {
		return result, err
	}
	for i := range want {
		result.addPostError(have[i], want[i])
	}
	for i := range imagWant {
		result.addPostError(imagValues[i], imagWant[i])
	}
	lanes := len(want) + len(imagWant)
	result.PreAvgError /= float64(lanes)
	result.PostAvgError /= float64(lanes)
	return result, nil
}

func (ctx *Context) Encrypt(values []float64) (*rlwe.Ciphertext, error) {
	pt := ckks.NewPlaintext(ctx.Params, ctx.Evaluator.SlotsToCoeffsParameters.LevelQ)
	if err := ctx.Encoder.Encode(values, pt); err != nil {
		return nil, err
	}
	return ctx.Encryptor.EncryptNew(pt)
}

func (ctx *Context) DecodeReal(ct *rlwe.Ciphertext) ([]float64, error) {
	values := make([]float64, ctx.Params.MaxSlots())
	if err := ctx.Encoder.Decode(ctx.Decryptor.DecryptNew(ct), values); err != nil {
		return nil, err
	}
	return values, nil
}

func (result *Measurement) addPreErrors(have, want []float64) {
	for i := range want {
		err := math.Abs(have[i] - want[i])
		result.PreAvgError += err
		if err > result.PreMaxError {
			result.PreMaxError = err
		}
	}
}

func (result *Measurement) addPostError(have, want float64) {
	parity := float64(int64(math.Round(want)) & 1)
	err := math.Abs(have - parity)
	result.PostAvgError += err
	if err > result.PostMaxError {
		result.PostMaxError = err
	}
	if err >= lazymod2params.LazyMod2Tolerance {
		result.OverTolerance++
	}
	if math.Abs(math.Round(have)-parity) > 0 {
		result.WrongSlots++
	}
}

func directValues(slots, terms int) []float64 {
	values := make([]float64, slots)
	for i := range values {
		switch i % 6 {
		case 0:
			values[i] = float64(terms)
		case 1:
			values[i] = float64(max(terms-1, 0))
		case 2:
			values[i] = float64((terms + 1) / 2)
		case 3:
			values[i] = float64(terms / 3)
		case 4:
			values[i] = float64(terms / 5)
		default:
			values[i] = float64(i & 1)
		}
	}
	return values
}

func pairedImagValues(slots, terms int) []float64 {
	values := directValues(slots, terms+1)
	for i := range values {
		values[i] += float64(i & 1)
	}
	return values
}

func bitValues(slots, term int) []float64 {
	values := make([]float64, slots)
	for i := range values {
		values[i] = float64(((term * 1103515245) + (i * 12345)) >> 8 & 1)
	}
	return values
}

func normalizedCheckpoints(checkpoints []int) []int {
	out := append([]int(nil), checkpoints...)
	sort.Ints(out)
	j := 0
	for _, value := range out {
		if value <= 0 {
			continue
		}
		if j == 0 || out[j-1] != value {
			out[j] = value
			j++
		}
	}
	return out[:j]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
