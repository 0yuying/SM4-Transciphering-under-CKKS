package storebench

import (
	"io"
	"testing"

	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSplitCKKSChunks(t *testing.T) {
	values := make([]float64, 9)
	chunks := SplitCKKSChunks(values, 4)
	if len(chunks) != 3 || len(chunks[0]) != 4 || len(chunks[1]) != 4 || len(chunks[2]) != 1 {
		t.Fatalf("chunk sizes=%v", []int{len(chunks[0]), len(chunks[1]), len(chunks[2])})
	}
	if got := CKKSChunkCount(4096, 2048); got != 2 {
		t.Fatalf("chunks=%d, want 2", got)
	}
}

func TestDirectCKKSContextEncryptSerializeAndVerify(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{50},
		LogDefaultScale: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewDirectCKKSContext(params)
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	operation, err := ctx.NewWorker().EncryptAndSerialize(values, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if operation.CiphertextObjects != 2 {
		t.Fatalf("ciphertext objects=%d, want 2", operation.CiphertextObjects)
	}
	if operation.UploadBytes <= 0 {
		t.Fatalf("upload bytes=%d", operation.UploadBytes)
	}
	maxError, err := ctx.Verify(values)
	if err != nil {
		t.Fatal(err)
	}
	if maxError > 1e-5 {
		t.Fatalf("verification max error=%g", maxError)
	}
}
