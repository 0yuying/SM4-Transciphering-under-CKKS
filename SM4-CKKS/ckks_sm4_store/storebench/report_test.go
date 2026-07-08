package storebench

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestWriteReport(t *testing.T) {
	now := time.Date(2026, time.June, 2, 1, 2, 3, 4, time.UTC)
	result := Result{
		Dataset:                       DatasetLoan,
		Path:                          PathSM4CompactCTR,
		Workers:                       1,
		Runs:                          1,
		LogicalTransactions:           2,
		CiphertextObjects:             2,
		PlaintextBytes:                4,
		UploadBytes:                   20,
		StoredBytes:                   20,
		StorageExpansionRatio:         5,
		EncryptDuration:               time.Microsecond,
		TotalDuration:                 2 * time.Microsecond,
		AverageLatency:                time.Microsecond,
		TransactionsPerSecond:         1_000_000,
		UploadPreparationMiBPerSecond: 10,
	}
	report := NewReport("quick", 12, 2048, 1, []int{1}, map[string]float64{DatasetLoan: 1e-10}, []Result{result}, now)
	jsonPath, csvPath, err := WriteReport(t.TempDir(), report, now)
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonData), `"upload_bytes": 20`) {
		t.Fatalf("JSON report=%s", jsonData)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csvData), "loan,sm4_compact_ctr,1,1,2,2,4,20,20") {
		t.Fatalf("CSV report=%s", csvData)
	}
}
