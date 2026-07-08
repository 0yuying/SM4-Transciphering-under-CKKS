package xbootparams

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	DefaultLogN             = 12
	ShortLogN               = 9
	DefaultLogScale         = 33
	DefaultCircuitLevels    = 3
	DefaultEphemeralSecret  = 32
	DefaultSecretHamming    = 256
	DefaultMod1Degree       = 120
	DefaultMod1K            = 12
	DefaultLogMessageRatio  = 1
	DefaultEngineeringError = 1e-4
)

var (
	DefaultSlotsToCoeffsLevels = []int{1}
	DefaultCoeffsToSlotsLevels = []int{1, 1}
)

// Profile describes an experimental SM4 XBOOT chain. LogN=12 is intentionally
// a development profile and is not presented as a 128-bit security parameter set.
type Profile struct {
	Name                      string
	LogN                      int
	LogDefaultScale           int
	SlotsToCoeffsLevels       []int
	SlotsToCoeffsLogBSGSRatio int
	CircuitLevels             int
	CoeffsToSlotsLevels       []int
	CoeffsToSlotsLogBSGSRatio int
	Mod1Degree                int
	Mod1K                     int
	LogMessageRatio           int
	EphemeralSecretWeight     int
	SecretHammingWeight       int
}

func Default(logN int) Profile {
	if logN == 0 {
		logN = DefaultLogN
	}
	return NewGridProfile("sm4-xboot-default", logN, DefaultLogScale, DefaultSlotsToCoeffsLevels, DefaultCircuitLevels, DefaultCoeffsToSlotsLevels)
}

func NewGridProfile(name string, logN, logScale int, slotsToCoeffs []int, circuitLevels int, coeffsToSlots []int) Profile {
	stcBSGS := 1
	if len(slotsToCoeffs) > 1 {
		stcBSGS = 2
	}
	return Profile{
		Name:                      name,
		LogN:                      logN,
		LogDefaultScale:           logScale,
		SlotsToCoeffsLevels:       cloneInts(slotsToCoeffs),
		SlotsToCoeffsLogBSGSRatio: stcBSGS,
		CircuitLevels:             circuitLevels,
		CoeffsToSlotsLevels:       cloneInts(coeffsToSlots),
		CoeffsToSlotsLogBSGSRatio: 1,
		Mod1Degree:                DefaultMod1Degree,
		Mod1K:                     DefaultMod1K,
		LogMessageRatio:           DefaultLogMessageRatio,
		EphemeralSecretWeight:     DefaultEphemeralSecret,
		SecretHammingWeight:       DefaultSecretHamming,
	}
}

func Grid(logN int) []Profile {
	var profiles []Profile
	scales := []int{31, 33, 35, 37, 39, 41}
	stcLevels := [][]int{{1}, {1, 1}}
	circuitLevels := []int{3, 4}
	ctsLevels := [][]int{{1, 1}, {1, 1, 1}, {1, 1, 1, 1}}
	for _, scale := range scales {
		for _, stc := range stcLevels {
			for _, circuit := range circuitLevels {
				for _, cts := range ctsLevels {
					name := fmt.Sprintf("n%d-s%d-stc%d-circuit%d-cts%d", logN, scale, len(stc), circuit, len(cts))
					profiles = append(profiles, NewGridProfile(name, logN, scale, stc, circuit, cts))
				}
			}
		}
	}
	return profiles
}

func (p Profile) Build() (ckks.Parameters, bootstrapping.Parameters, error) {
	mod1Literal := mod1.ParametersLiteral{
		LogScale:        p.LogDefaultScale + 1,
		Mod1Type:        mod1.CosDiscreteXBOOT,
		Mod1Degree:      p.Mod1Degree,
		K:               p.Mod1K,
		LogMessageRatio: p.LogMessageRatio,
	}

	logQ := []int{p.LogDefaultScale + 1}
	logQ = append(logQ, repeat(p.LogDefaultScale-3, len(p.SlotsToCoeffsLevels))...)
	logQ = append(logQ, repeat(p.LogDefaultScale, p.CircuitLevels)...)
	logQ = append(logQ, repeat(p.LogDefaultScale+1, mod1Literal.Depth())...)
	logQ = append(logQ, repeat(p.LogDefaultScale-1, len(p.CoeffsToSlotsLevels))...)

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            p.LogN,
		LogQ:            logQ,
		LogP:            repeat(p.LogDefaultScale+1, 5),
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

	slotsToCoeffs := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: p.SlotsToCoeffsLogBSGSRatio,
		LevelP:       params.MaxLevelP(),
		Levels:       cloneInts(p.SlotsToCoeffsLevels),
	}
	slotsToCoeffs.LevelQ = len(slotsToCoeffs.Levels)

	return params, bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: slotsToCoeffs,
		Mod1ParametersLiteral:   mod1Literal,
		CoeffsToSlotsParameters: coeffsToSlots,
		EphemeralSecretWeight:   p.EphemeralSecretWeight,
		CircuitOrder:            bootstrapping.DecodeThenModUp,
	}, nil
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
