package lazymod2params

import (
	"fmt"
	"math/bits"
	"strings"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	DefaultLogN              = 12
	DefaultEphemeralSecret   = 32
	DefaultSecretHamming     = 192
	LazyMod2Tolerance        = 0.45
	LazyMod2PostDropLevels   = 3
	LazyMod2SboxDepth        = 3
	LazyMod2FinalReduceDepth = 1
	SM4TmpBoundary           = 124
	SM4FinalBoundary         = 41
	SM4MarginBoundary        = 256
)

// Profile describes one experimental SM4 LazyMod2 bootstrapping chain.
// LogN=12 profiles in this package are development parameters and are not
// presented as 128-bit security parameter sets.
type Profile struct {
	Name                      string
	LogN                      int
	LogDefaultScale           int
	Q0LogScale                int
	SlotLogScale              int
	HighLogScale              int
	SlotsToCoeffsLevels       []int
	SlotsToCoeffsLogBSGSRatio int
	CircuitLevels             int
	CoeffsToSlotsLevels       []int
	CoeffsToSlotsLogBSGSRatio int
	LogP                      []int
	PLogScale                 int
	PCount                    int
	Mod1Degree                int
	Mod1DoubleAngle           int
	Mod1K                     int
	LogMessageRatio           int
	EphemeralSecretWeight     int
	SecretHammingWeight       int
}

func Baseline(logN int) Profile {
	if logN == 0 {
		logN = DefaultLogN
	}
	return Profile{
		Name:                      "lazymod2-baseline",
		LogN:                      logN,
		LogDefaultScale:           42,
		Q0LogScale:                58,
		SlotLogScale:              42,
		HighLogScale:              58,
		SlotsToCoeffsLevels:       []int{1, 1, 1},
		SlotsToCoeffsLogBSGSRatio: 1,
		CircuitLevels:             9,
		CoeffsToSlotsLevels:       []int{1, 1, 1, 1},
		CoeffsToSlotsLogBSGSRatio: 1,
		LogP:                      []int{59, 59, 60, 60, 60},
		Mod1Degree:                30,
		Mod1DoubleAngle:           3,
		Mod1K:                     16,
		LogMessageRatio:           10,
		EphemeralSecretWeight:     DefaultEphemeralSecret,
		SecretHammingWeight:       DefaultSecretHamming,
	}
}

func Default(logN int) Profile {
	p := Baseline(logN)
	p.Name = "lazymod2-default"
	if p.LogN <= 9 {
		return p
	}
	p.CircuitLevels = 7
	return p
}

func CriticalBoundary(logN int) Profile {
	p := Baseline(logN)
	p.Name = "lazymod2-critical-boundary"
	p.LogDefaultScale = 30
	p.Q0LogScale = 46
	p.SlotLogScale = 30
	p.HighLogScale = 46
	p.SlotsToCoeffsLevels = []int{1}
	p.CircuitLevels = 7
	p.CoeffsToSlotsLevels = []int{1}
	p.LogP = nil
	p.PLogScale = 31
	p.PCount = 1
	return p
}

func Mod1Grid(logN int) []Profile {
	base := Baseline(logN)
	var profiles []Profile
	for _, k := range []int{8, 12, 16} {
		for _, doubleAngle := range []int{0, 1, 2, 3, 4} {
			for _, ratio := range []int{6, 8, 10, 12} {
				for _, degree := range mod1DegreeOptions(k) {
					p := base
					p.Name = fmt.Sprintf("mod1-k%d-d%d-da%d-r%d", k, degree, doubleAngle, ratio)
					p.Mod1K = k
					p.Mod1Degree = degree
					p.Mod1DoubleAngle = doubleAngle
					p.LogMessageRatio = ratio
					profiles = append(profiles, p)
				}
			}
		}
	}
	return profiles
}

func ChainGrid(seed Profile) []Profile {
	slotScales := []int{30, 32, 34, 36, 38, 40, 42}
	highScales := []int{44, 46, 48, 50, 52, 54, 56, 58}
	stcLevels := [][]int{{1}, {1, 1}, {1, 1, 1}}
	circuitLevels := []int{6, 7, 8, 9}
	ctsLevels := [][]int{{1}, {1, 1}, {1, 1, 1}, {1, 1, 1, 1}}
	pCounts := []int{2, 3, 4, 5}

	var profiles []Profile
	for _, slotScale := range slotScales {
		for _, highScale := range highScales {
			for _, stc := range stcLevels {
				for _, circuit := range circuitLevels {
					for _, cts := range ctsLevels {
						for _, pCount := range pCounts {
							for _, pLog := range uniqueInts([]int{min(60, highScale+1), 60}) {
								p := seed
								p.Name = fmt.Sprintf("chain-s%d-h%d-stc%d-c%d-cts%d-p%dx%d-%s",
									slotScale, highScale, len(stc), circuit, len(cts), pCount, pLog, seed.Mod1Tag())
								p.LogDefaultScale = slotScale
								p.Q0LogScale = highScale
								p.SlotLogScale = slotScale
								p.HighLogScale = highScale
								p.SlotsToCoeffsLevels = cloneInts(stc)
								p.CircuitLevels = circuit
								p.CoeffsToSlotsLevels = cloneInts(cts)
								p.LogP = nil
								p.PCount = pCount
								p.PLogScale = pLog
								profiles = append(profiles, p)
							}
						}
					}
				}
			}
		}
	}
	return profiles
}

func (p Profile) Build() (ckks.Parameters, bootstrapping.Parameters, error) {
	if p.LogN == 0 {
		p.LogN = DefaultLogN
	}
	if p.EphemeralSecretWeight == 0 {
		p.EphemeralSecretWeight = DefaultEphemeralSecret
	}
	if p.SecretHammingWeight == 0 {
		p.SecretHammingWeight = DefaultSecretHamming
	}
	if p.Mod1K <= 0 {
		return ckks.Parameters{}, bootstrapping.Parameters{}, fmt.Errorf("Mod1K must be positive")
	}
	if p.Mod1Degree < 2*(p.Mod1K-1) {
		return ckks.Parameters{}, bootstrapping.Parameters{}, fmt.Errorf("cos-discrete degree=%d below 2*(K-1)=%d", p.Mod1Degree, 2*(p.Mod1K-1))
	}
	if len(p.SlotsToCoeffsLevels) == 0 || len(p.CoeffsToSlotsLevels) == 0 {
		return ckks.Parameters{}, bootstrapping.Parameters{}, fmt.Errorf("StC and CtS levels must be non-empty")
	}
	if p.CircuitLevels < 1 {
		return ckks.Parameters{}, bootstrapping.Parameters{}, fmt.Errorf("CircuitLevels must be positive")
	}

	mod1Literal := mod1.ParametersLiteral{
		LogScale:        p.HighLogScale,
		Mod1Type:        mod1.CosDiscrete,
		Mod1Degree:      p.Mod1Degree,
		DoubleAngle:     p.Mod1DoubleAngle,
		K:               p.Mod1K,
		LogMessageRatio: p.LogMessageRatio,
		Mod1InvDegree:   0,
	}
	mod1Depth := mod1Literal.Depth()

	logQ := []int{p.Q0LogScale}
	logQ = append(logQ, repeat(p.SlotLogScale, len(p.SlotsToCoeffsLevels))...)
	logQ = append(logQ, repeat(p.SlotLogScale, p.CircuitLevels)...)
	logQ = append(logQ, repeat(p.HighLogScale, mod1Depth)...)
	logQ = append(logQ, repeat(p.HighLogScale, len(p.CoeffsToSlotsLevels))...)
	logP := cloneInts(p.LogP)
	if len(logP) == 0 {
		if p.PCount <= 0 || p.PLogScale <= 0 {
			return ckks.Parameters{}, bootstrapping.Parameters{}, fmt.Errorf("either LogP or PCount/PLogScale must be set")
		}
		logP = repeat(p.PLogScale, p.PCount)
	}

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            p.LogN,
		LogQ:            logQ,
		LogP:            logP,
		LogDefaultScale: p.LogDefaultScale,
		Xs:              ring.Ternary{H: p.SecretHammingWeight},
	})
	if err != nil {
		return ckks.Parameters{}, bootstrapping.Parameters{}, fmt.Errorf("new CKKS parameters for %s: %w", p.Name, err)
	}

	coeffsToSlots := dft.MatrixLiteral{
		Type:         dft.HomomorphicEncode,
		Format:       dft.RepackImagAsReal,
		LogSlots:     params.LogMaxSlots(),
		LevelQ:       params.MaxLevelQ(),
		LevelP:       params.MaxLevelP(),
		LogBSGSRatio: p.CoeffsToSlotsLogBSGSRatio,
		Levels:       cloneInts(p.CoeffsToSlotsLevels),
	}
	mod1Literal.LevelQ = params.MaxLevel() - coeffsToSlots.Depth(true)
	if p.LogN <= 9 {
		mod1Literal.LogMessageRatio += 16 - params.LogN()
		if mod1Literal.LogMessageRatio > 16 {
			mod1Literal.LogMessageRatio = 16
		}
	}

	slotsToCoeffs := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: p.SlotsToCoeffsLogBSGSRatio,
		LevelP:       params.MaxLevelP(),
		Levels:       cloneInts(p.SlotsToCoeffsLevels),
	}
	slotsToCoeffs.LevelQ = len(slotsToCoeffs.Levels)

	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: slotsToCoeffs,
		Mod1ParametersLiteral:   mod1Literal,
		CoeffsToSlotsParameters: coeffsToSlots,
		EphemeralSecretWeight:   p.EphemeralSecretWeight,
		CircuitOrder:            bootstrapping.DecodeThenModUp,
	}
	if err := p.validateBudget(params, btpParams); err != nil {
		return ckks.Parameters{}, bootstrapping.Parameters{}, err
	}
	return params, btpParams, nil
}

func (p Profile) validateBudget(params ckks.Parameters, btpParams bootstrapping.Parameters) error {
	if p.LogN <= 9 {
		return nil
	}
	remaining := params.MaxLevel() - btpParams.Depth() + btpParams.SlotsToCoeffsParameters.LevelQ
	minRoundOutput := remaining - 1 - LazyMod2PostDropLevels - LazyMod2SboxDepth
	if minRoundOutput < btpParams.SlotsToCoeffsParameters.LevelQ {
		return fmt.Errorf("insufficient round budget: remaining=%d minRoundOutput=%d stcLevelQ=%d", remaining, minRoundOutput, btpParams.SlotsToCoeffsParameters.LevelQ)
	}
	minFinalOutput := remaining - 1 - LazyMod2PostDropLevels
	if minFinalOutput < LazyMod2FinalReduceDepth {
		return fmt.Errorf("insufficient final reducer budget: remaining=%d minFinalOutput=%d", remaining, minFinalOutput)
	}
	return nil
}

func (p Profile) Mod1Tag() string {
	return fmt.Sprintf("k%d-d%d-da%d-r%d", p.Mod1K, p.Mod1Degree, p.Mod1DoubleAngle, p.LogMessageRatio)
}

func (p Profile) LogQ() []int {
	mod1Literal := mod1.ParametersLiteral{
		LogScale:        p.HighLogScale,
		Mod1Type:        mod1.CosDiscrete,
		Mod1Degree:      p.Mod1Degree,
		DoubleAngle:     p.Mod1DoubleAngle,
		K:               p.Mod1K,
		LogMessageRatio: p.LogMessageRatio,
	}
	logQ := []int{p.Q0LogScale}
	logQ = append(logQ, repeat(p.SlotLogScale, len(p.SlotsToCoeffsLevels))...)
	logQ = append(logQ, repeat(p.SlotLogScale, p.CircuitLevels)...)
	logQ = append(logQ, repeat(p.HighLogScale, mod1Literal.Depth())...)
	logQ = append(logQ, repeat(p.HighLogScale, len(p.CoeffsToSlotsLevels))...)
	return logQ
}

func (p Profile) LogPList() []int {
	if len(p.LogP) > 0 {
		return cloneInts(p.LogP)
	}
	return repeat(p.PLogScale, p.PCount)
}

func (p Profile) CSVFields() []string {
	return []string{
		p.Name,
		fmt.Sprint(p.LogN),
		fmt.Sprint(p.LogDefaultScale),
		fmt.Sprint(p.Q0LogScale),
		fmt.Sprint(p.SlotLogScale),
		fmt.Sprint(p.HighLogScale),
		intsString(p.SlotsToCoeffsLevels),
		fmt.Sprint(p.CircuitLevels),
		intsString(p.CoeffsToSlotsLevels),
		intsString(p.LogPList()),
		fmt.Sprint(p.Mod1K),
		fmt.Sprint(p.Mod1Degree),
		fmt.Sprint(p.Mod1DoubleAngle),
		fmt.Sprint(p.LogMessageRatio),
	}
}

func mod1DegreeOptions(k int) []int {
	minDegree := 2 * (k - 1)
	baseDepth := bits.Len(uint(max(minDegree, 2*k-1)))
	maxSameDepth := (1 << baseDepth) - 1
	return uniqueInts([]int{minDegree, maxSameDepth, 30})
}

func cloneInts(in []int) []int {
	return append([]int(nil), in...)
}

func repeat(value, count int) []int {
	out := make([]int, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func uniqueInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, value := range in {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func intsString(values []int) string {
	var b strings.Builder
	for i, value := range values {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(fmt.Sprint(value))
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
