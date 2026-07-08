package storebench

import (
	"fmt"
	"io"
	"math"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const DefaultLogN = 12

type DirectCKKSContext struct {
	Params    ckks.Parameters
	Encoder   *ckks.Encoder
	Encryptor *rlwe.Encryptor
	Decryptor *rlwe.Decryptor
}

type DirectCKKSWorker struct {
	params    ckks.Parameters
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
}

type DirectOperation struct {
	CiphertextObjects int64
	UploadBytes       int64
	EncodeDuration    time.Duration
	EncryptDuration   time.Duration
	SerializeDuration time.Duration
	TotalDuration     time.Duration
}

func BuildDirectCKKSParameters(logN int) (ckks.Parameters, error) {
	if logN < 2 {
		return ckks.Parameters{}, fmt.Errorf("logN must be at least 2, got %d", logN)
	}
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: logN,
		LogQ: []int{
			58,
			42, 42, 42,
			42, 42, 42, 42, 42, 42, 42, 42, 42,
			58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58,
		},
		LogP:            []int{59, 59, 60, 60, 60},
		LogDefaultScale: 42,
		Xs:              ring.Ternary{H: 192},
	})
}

func NewDirectCKKSContext(params ckks.Parameters) *DirectCKKSContext {
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	return &DirectCKKSContext{
		Params:    params,
		Encoder:   ckks.NewEncoder(params),
		Encryptor: rlwe.NewEncryptor(params, pk),
		Decryptor: rlwe.NewDecryptor(params, sk),
	}
}

func (ctx *DirectCKKSContext) NewWorker() *DirectCKKSWorker {
	return &DirectCKKSWorker{
		params:    ctx.Params,
		encoder:   ctx.Encoder.ShallowCopy(),
		encryptor: ctx.Encryptor.ShallowCopy(),
	}
}

func (worker *DirectCKKSWorker) EncryptAndSerialize(values []float64, writer io.Writer) (DirectOperation, error) {
	var result DirectOperation
	start := time.Now()
	for _, chunk := range SplitCKKSChunks(values, worker.params.MaxSlots()) {
		stage := time.Now()
		plaintext := ckks.NewPlaintext(worker.params, worker.params.MaxLevel())
		if err := worker.encoder.Encode(chunk, plaintext); err != nil {
			return result, fmt.Errorf("encode CKKS plaintext: %w", err)
		}
		result.EncodeDuration += time.Since(stage)

		stage = time.Now()
		ciphertext, err := worker.encryptor.EncryptNew(plaintext)
		if err != nil {
			return result, fmt.Errorf("encrypt CKKS plaintext: %w", err)
		}
		result.EncryptDuration += time.Since(stage)

		stage = time.Now()
		written, err := ciphertext.WriteTo(writer)
		if err != nil {
			return result, fmt.Errorf("serialize CKKS ciphertext: %w", err)
		}
		result.SerializeDuration += time.Since(stage)
		if want := int64(ciphertext.BinarySize()); written != want {
			return result, fmt.Errorf("serialize CKKS ciphertext wrote %d bytes, want %d", written, want)
		}
		result.CiphertextObjects++
		result.UploadBytes += written
	}
	result.TotalDuration = time.Since(start)
	return result, nil
}

func (ctx *DirectCKKSContext) Verify(values []float64) (float64, error) {
	var maxError float64
	for _, chunk := range SplitCKKSChunks(values, ctx.Params.MaxSlots()) {
		plaintext := ckks.NewPlaintext(ctx.Params, ctx.Params.MaxLevel())
		if err := ctx.Encoder.Encode(chunk, plaintext); err != nil {
			return 0, fmt.Errorf("encode verification plaintext: %w", err)
		}
		ciphertext, err := ctx.Encryptor.EncryptNew(plaintext)
		if err != nil {
			return 0, fmt.Errorf("encrypt verification plaintext: %w", err)
		}
		decoded := make([]float64, ctx.Params.MaxSlots())
		if err := ctx.Encoder.Decode(ctx.Decryptor.DecryptNew(ciphertext), decoded); err != nil {
			return 0, fmt.Errorf("decode verification plaintext: %w", err)
		}
		for index, want := range chunk {
			if err := math.Abs(decoded[index] - want); err > maxError {
				maxError = err
			}
		}
	}
	return maxError, nil
}

func SplitCKKSChunks(values []float64, slots int) [][]float64 {
	if slots <= 0 || len(values) == 0 {
		return nil
	}
	chunks := make([][]float64, 0, (len(values)+slots-1)/slots)
	for start := 0; start < len(values); start += slots {
		end := start + slots
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, values[start:end])
	}
	return chunks
}

func CKKSChunkCount(values, slots int) int {
	if values <= 0 || slots <= 0 {
		return 0
	}
	return (values + slots - 1) / slots
}
