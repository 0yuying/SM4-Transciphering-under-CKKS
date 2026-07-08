package lazymod2params

import (
	"math"
	"testing"
)

func TestBaselineReproducesCurrentChain(t *testing.T) {
	params, btpParams, err := Baseline(12).Build()
	if err != nil {
		t.Fatalf("Baseline Build failed: %v", err)
	}
	if params.QCount() != 25 {
		t.Fatalf("baseline QCount changed: got=%d want=25", params.QCount())
	}
	if math.Abs(params.LogQP()-1556.0) > 1.0 {
		t.Fatalf("baseline LogQP changed: got=%.6f want approximately 1556", params.LogQP())
	}
	if btpParams.Mod1ParametersLiteral.Depth() != 8 {
		t.Fatalf("baseline Mod1 depth changed: got=%d want=8", btpParams.Mod1ParametersLiteral.Depth())
	}
	if btpParams.SlotsToCoeffsParameters.LevelQ != 3 {
		t.Fatalf("baseline StC LevelQ changed: got=%d want=3", btpParams.SlotsToCoeffsParameters.LevelQ)
	}
}

func TestBudgetRejectsInsufficientCircuitReserve(t *testing.T) {
	p := Baseline(12)
	p.CircuitLevels = 6
	if _, _, err := p.Build(); err == nil {
		t.Fatalf("Build succeeded with insufficient circuit reserve")
	}
}

func TestDefaultBuilds(t *testing.T) {
	params, _, err := Default(12).Build()
	if err != nil {
		t.Fatalf("Default Build failed: %v", err)
	}
	if params.LogN() != 12 {
		t.Fatalf("default LogN changed: got=%d want=12", params.LogN())
	}
	if params.QCount() != 23 {
		t.Fatalf("default QCount changed: got=%d want=23", params.QCount())
	}
	if math.Abs(params.LogQP()-1472.0) > 1.0 {
		t.Fatalf("default LogQP changed: got=%.6f want approximately 1472", params.LogQP())
	}
}

func TestCriticalBoundaryBuilds(t *testing.T) {
	params, _, err := CriticalBoundary(12).Build()
	if err != nil {
		t.Fatalf("CriticalBoundary Build failed: %v", err)
	}
	if params.QCount() != 18 {
		t.Fatalf("critical QCount changed: got=%d want=18", params.QCount())
	}
	if math.Abs(params.LogQP()-731.0) > 1.0 {
		t.Fatalf("critical LogQP changed: got=%.6f want approximately 731", params.LogQP())
	}
}
