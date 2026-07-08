package storebench

import (
	"io"
	"math"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/ckks_cipher"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestBenchmarkSM4WorkerMatrixAndMetrics(t *testing.T) {
	dataset := testLoanDataset()
	cipher := ckks_cipher.NewPlainSM4Cipher(make([]byte, SM4BlockBytes))
	for _, workers := range []int{1, 4, 8, 16} {
		result, err := BenchmarkSM4(cipher, dataset, PathSM4CompactCTR, workers, 2, make([]byte, SM4BlockBytes))
		if err != nil {
			t.Fatal(err)
		}
		if result.LogicalTransactions != 3 || result.CiphertextObjects != 3 {
			t.Fatalf("workers=%d transactions=%d objects=%d", workers, result.LogicalTransactions, result.CiphertextObjects)
		}
		if result.PlaintextBytes != 6 || result.UploadBytes != 6+SM4IVMetadataBytes {
			t.Fatalf("workers=%d plaintext=%d upload=%d", workers, result.PlaintextBytes, result.UploadBytes)
		}
		wantTPS := float64(result.LogicalTransactions) / result.TotalDuration.Seconds()
		if math.Abs(result.TransactionsPerSecond-wantTPS) > 1e-9 {
			t.Fatalf("workers=%d TPS=%g, want %g", workers, result.TransactionsPerSecond, wantTPS)
		}
	}
	slotReady, err := BenchmarkSM4(cipher, dataset, PathSM4SlotReadyCTR, 1, 1, make([]byte, SM4BlockBytes))
	if err != nil {
		t.Fatal(err)
	}
	if slotReady.UploadBytes != 3*SM4BlockBytes+SM4IVMetadataBytes {
		t.Fatalf("slot-ready upload=%d", slotReady.UploadBytes)
	}
}

func TestBenchmarkDirectCKKSAggregatesWorkerResults(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{50},
		LogDefaultScale: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := BenchmarkDirectCKKS(NewDirectCKKSContext(params), testLoanDataset(), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.LogicalTransactions != 3 || result.CiphertextObjects != 3 {
		t.Fatalf("transactions=%d objects=%d", result.LogicalTransactions, result.CiphertextObjects)
	}
	if result.UploadBytes <= 0 || result.StoredBytes != result.UploadBytes {
		t.Fatalf("upload=%d stored=%d", result.UploadBytes, result.StoredBytes)
	}
}

func TestRunTransactionsReportsWallTimeAndLatency(t *testing.T) {
	result, err := runTransactions(4, 2, func(_, _ int) (taskMetrics, error) {
		time.Sleep(time.Millisecond)
		return taskMetrics{uploadBytes: 2, latency: time.Millisecond}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.uploadBytes != 8 || result.latency != 4*time.Millisecond || result.totalDuration <= 0 {
		t.Fatalf("result=%+v", result)
	}
}

func BenchmarkDirectCKKSSerialization(b *testing.B) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{50},
		LogDefaultScale: 30,
	})
	if err != nil {
		b.Fatal(err)
	}
	worker := NewDirectCKKSContext(params).NewWorker()
	for index := 0; index < b.N; index++ {
		if _, err := worker.EncryptAndSerialize([]float64{1, 2, 3}, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func testLoanDataset() Dataset {
	return Dataset{
		Name:        DatasetLoan,
		ScalarBytes: 2,
		Transactions: []Transaction{
			{Raw: []byte{0, 1}, Values: []float64{1}},
			{Raw: []byte{0, 2}, Values: []float64{2}},
			{Raw: []byte{0, 3}, Values: []float64{3}},
		},
	}
}
