package lazymod2scan

import (
	"os"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/lazymod2params"
)

func TestNormalizeCheckpoints(t *testing.T) {
	got := normalizedCheckpoints([]int{124, 41, 0, 41, 256})
	want := []int{41, 124, 256}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("checkpoint mismatch: got=%v want=%v", got, want)
		}
	}
}

func TestLazyMod2BoundaryHeavy(t *testing.T) {
	if os.Getenv("LAZYMOD2_HEAVY") != "1" {
		t.Skip("set LAZYMOD2_HEAVY=1 to run the slot-packed LazyMod2 boundary test")
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	ctx, err := NewContext(lazymod2params.Baseline(12), true)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}
	var all []Measurement
	for _, mode := range []string{"direct", "independent", "correlated"} {
		results, err := ctx.Scan(mode, []int{lazymod2params.SM4FinalBoundary, lazymod2params.SM4TmpBoundary, lazymod2params.SM4MarginBoundary})
		if err != nil {
			t.Fatalf("Scan(%s) failed: %v", mode, err)
		}
		all = append(all, results...)
	}
	if !ctx.PassesRequired(all) {
		t.Fatalf("baseline did not pass required LazyMod2 boundaries: %+v", all)
	}
	if err := ctx.ValidateOneRound(); err != nil {
		t.Fatalf("one-round validation failed: %v", err)
	}
}
