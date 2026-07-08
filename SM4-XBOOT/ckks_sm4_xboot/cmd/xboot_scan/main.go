package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/xbootparams"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type context struct {
	profile   xbootparams.Profile
	params    ckks.Parameters
	btpParams bootstrapping.Parameters
	evaluator *bootstrapping.Evaluator
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	paired    bool
}

type measurement struct {
	mode          string
	terms         int
	preMaxError   float64
	preAvgError   float64
	postMaxError  float64
	postAvgError  float64
	wrongSlots    int
	overThreshold int
	duration      time.Duration
}

func main() {
	logN := flag.Int("logN", xbootparams.DefaultLogN, "experimental CKKS ring degree")
	modesFlag := flag.String("modes", "direct,independent,correlated", "comma-separated scan modes")
	checkpointsFlag := flag.String("checkpoints", "1,2,42,124,256", "comma-separated aggregation sizes")
	repeats := flag.Int("repeats", 1, "independent key generations")
	grid := flag.Bool("grid", false, "scan the two-stage grid instead of the default profile")
	maxCandidates := flag.Int("max-candidates", 0, "optional cap for grid candidates; zero means all")
	threads := flag.Int("threads", runtime.NumCPU(), "maximum OS threads")
	paired := flag.Bool("paired", true, "probe production BootstrapCmplxThenDivide; set false to isolate BootstrapReal")
	output := flag.String("output", "", "optional CSV output path")
	flag.Parse()

	if *threads < 1 {
		*threads = 1
	}
	runtime.GOMAXPROCS(*threads)
	modes := mustCSVStrings(*modesFlag)
	checkpoints := mustCSVInts(*checkpointsFlag)
	if *repeats < 1 {
		panic("repeats must be positive")
	}

	profiles := []xbootparams.Profile{xbootparams.Default(*logN)}
	if *grid {
		profiles = xbootparams.Grid(*logN)
	}
	if *maxCandidates > 0 && *maxCandidates < len(profiles) {
		profiles = profiles[:*maxCandidates]
	}

	out := io.Writer(os.Stdout)
	var file *os.File
	if *output != "" {
		var err error
		file, err = os.Create(*output)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		out = io.MultiWriter(os.Stdout, file)
	}
	writer := csv.NewWriter(out)
	defer writer.Flush()
	_ = writer.Write([]string{"record", "repeat", "profile", "logN", "levels", "logQP", "mode", "terms", "pre_max_error", "pre_avg_error", "post_max_error", "post_avg_error", "wrong_slots", "over_1e-4_slots", "duration"})

	for _, profile := range profiles {
		for repeat := 1; repeat <= *repeats; repeat++ {
			ctx, err := newContext(profile, *paired)
			if err != nil {
				_ = writer.Write([]string{"build-failed", strconv.Itoa(repeat), profile.Name, strconv.Itoa(profile.LogN), "", "", "", "", "", "", "", "", "", "", err.Error()})
				writer.Flush()
				continue
			}
			for _, mode := range modes {
				for _, result := range ctx.scan(mode, checkpoints) {
					_ = writer.Write([]string{
						"measurement",
						strconv.Itoa(repeat),
						profile.Name,
						strconv.Itoa(profile.LogN),
						strconv.Itoa(ctx.params.QCount()),
						fmt.Sprintf("%.3f", ctx.params.LogQP()),
						result.mode,
						strconv.Itoa(result.terms),
						fmt.Sprintf("%.8e", result.preMaxError),
						fmt.Sprintf("%.8e", result.preAvgError),
						fmt.Sprintf("%.8e", result.postMaxError),
						fmt.Sprintf("%.8e", result.postAvgError),
						strconv.Itoa(result.wrongSlots),
						strconv.Itoa(result.overThreshold),
						result.duration.String(),
					})
					writer.Flush()
				}
			}
		}
	}
}

func newContext(profile xbootparams.Profile, paired bool) (*context, error) {
	params, btpParams, err := profile.Build()
	if err != nil {
		return nil, err
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		return nil, fmt.Errorf("generate bootstrap keys: %w", err)
	}
	evaluator, err := bootstrapping.NewEvaluator(btpParams, evk)
	if err != nil {
		return nil, fmt.Errorf("new bootstrap evaluator: %w", err)
	}
	return &context{
		profile:   profile,
		params:    params,
		btpParams: btpParams,
		evaluator: evaluator,
		encoder:   ckks.NewEncoder(params),
		encryptor: rlwe.NewEncryptor(params, pk),
		decryptor: rlwe.NewDecryptor(params, sk),
		paired:    paired,
	}, nil
}

func (ctx *context) scan(mode string, checkpoints []int) []measurement {
	switch mode {
	case "direct":
		var results []measurement
		for _, terms := range checkpoints {
			values := directValues(ctx.params.MaxSlots(), terms)
			results = append(results, ctx.measure(mode, terms, ctx.encrypt(values), values))
		}
		return results
	case "independent":
		return ctx.scanIndependent(checkpoints)
	case "correlated":
		return ctx.scanCorrelated(checkpoints)
	default:
		panic("unsupported scan mode: " + mode)
	}
}

func (ctx *context) scanIndependent(checkpoints []int) []measurement {
	maxTerms := checkpoints[len(checkpoints)-1]
	want := make([]float64, ctx.params.MaxSlots())
	acc := ctx.encrypt(want)
	next := 0
	var results []measurement
	for term := 0; term < maxTerms; term++ {
		values := bitValues(ctx.params.MaxSlots(), term)
		if err := ctx.evaluator.Add(acc, ctx.encrypt(values), acc); err != nil {
			panic(err)
		}
		for i := range want {
			want[i] += values[i]
		}
		if term+1 == checkpoints[next] {
			results = append(results, ctx.measure("independent", term+1, acc, want))
			next++
			if next == len(checkpoints) {
				break
			}
		}
	}
	return results
}

func (ctx *context) scanCorrelated(checkpoints []int) []measurement {
	values := bitValues(ctx.params.MaxSlots(), 0)
	repeated := ctx.encrypt(values)
	var results []measurement
	for _, terms := range checkpoints {
		acc, err := ctx.evaluator.MulNew(repeated, terms)
		if err != nil {
			panic(err)
		}
		want := make([]float64, len(values))
		for i := range want {
			want[i] = values[i] * float64(terms)
		}
		results = append(results, ctx.measure("correlated", terms, acc, want))
	}
	return results
}

func (ctx *context) measure(mode string, terms int, ct *rlwe.Ciphertext, want []float64) measurement {
	result := measurement{mode: mode, terms: terms}
	result.addPreErrors(ctx.decode(ct), want)

	var out *rlwe.Ciphertext
	var imagWant []float64
	var imagValues []float64
	if ctx.paired {
		imagWant = pairedImagValues(ctx.params.MaxSlots(), terms)
		imagIn := ctx.encrypt(imagWant)
		result.addPreErrors(ctx.decode(imagIn), imagWant)
		start := time.Now()
		var imag *rlwe.Ciphertext
		var err error
		out, imag, err = ctx.evaluator.BootstrapCmplxThenDivide(ct.CopyNew(), imagIn)
		if err != nil {
			panic(err)
		}
		result.duration = time.Since(start)
		imagValues = ctx.decode(imag)
	} else {
		start := time.Now()
		var err error
		out, err = ctx.evaluator.BootstrapReal(ct.CopyNew())
		if err != nil {
			panic(err)
		}
		result.duration = time.Since(start)
	}
	have := ctx.decode(out)
	for i := range want {
		result.addPostError(have[i], want[i])
	}
	for i := range imagWant {
		result.addPostError(imagValues[i], imagWant[i])
	}
	lanes := len(want) + len(imagWant)
	result.preAvgError /= float64(lanes)
	result.postAvgError /= float64(lanes)
	return result
}

func (result *measurement) addPreErrors(have, want []float64) {
	for i := range want {
		err := math.Abs(have[i] - want[i])
		result.preAvgError += err
		if err > result.preMaxError {
			result.preMaxError = err
		}
	}
}

func (result *measurement) addPostError(have, want float64) {
	parity := float64(int64(want) & 1)
	err := math.Abs(have - parity)
	result.postAvgError += err
	if err > result.postMaxError {
		result.postMaxError = err
	}
	if err > xbootparams.DefaultEngineeringError {
		result.overThreshold++
	}
	if math.Round(have) != parity {
		result.wrongSlots++
	}
}

func (ctx *context) encrypt(values []float64) *rlwe.Ciphertext {
	pt := ckks.NewPlaintext(ctx.params, ctx.evaluator.SlotsToCoeffsParameters.LevelQ)
	if err := ctx.encoder.Encode(values, pt); err != nil {
		panic(err)
	}
	ct, err := ctx.encryptor.EncryptNew(pt)
	if err != nil {
		panic(err)
	}
	return ct
}

func (ctx *context) decode(ct *rlwe.Ciphertext) []float64 {
	values := make([]float64, ctx.params.MaxSlots())
	if err := ctx.encoder.Decode(ctx.decryptor.DecryptNew(ct), values); err != nil {
		panic(err)
	}
	return values
}

func directValues(slots, terms int) []float64 {
	values := make([]float64, slots)
	for i := range values {
		switch i % 4 {
		case 0:
			values[i] = float64(terms)
		case 1:
			values[i] = float64(max(terms-1, 0))
		case 2:
			values[i] = float64((terms + 1) / 2)
		case 3:
			values[i] = float64(terms / 3)
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

func mustCSVStrings(text string) []string {
	var out []string
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		panic("list must not be empty")
	}
	return out
}

func mustCSVInts(text string) []int {
	var out []int
	for _, item := range mustCSVStrings(text) {
		value, err := strconv.Atoi(item)
		if err != nil || value < 1 {
			panic("checkpoints must be positive integers")
		}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}
