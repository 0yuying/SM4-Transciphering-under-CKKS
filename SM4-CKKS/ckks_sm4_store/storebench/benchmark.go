package storebench

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/ckks_cipher"
)

type Suite struct {
	Direct *DirectCKKSContext
	SM4    *ckks_cipher.PlainSM4Cipher
}

type Result struct {
	Dataset                       string
	Path                          Path
	Workers                       int
	Runs                          int
	LogicalTransactions           int64
	CiphertextObjects             int64
	PlaintextBytes                int64
	UploadBytes                   int64
	StoredBytes                   int64
	StorageExpansionRatio         float64
	PackDuration                  time.Duration
	EncodeDuration                time.Duration
	EncryptDuration               time.Duration
	SerializeDuration             time.Duration
	TotalDuration                 time.Duration
	AverageLatency                time.Duration
	TransactionsPerSecond         float64
	UploadPreparationMiBPerSecond float64
}

type taskMetrics struct {
	ciphertextObjects int64
	uploadBytes       int64
	packDuration      time.Duration
	encodeDuration    time.Duration
	encryptDuration   time.Duration
	serializeDuration time.Duration
	latency           time.Duration
}

type runMetrics struct {
	taskMetrics
	totalDuration time.Duration
}

func NewSuite(logN int, key []byte) (*Suite, error) {
	if len(key) != SM4BlockBytes {
		return nil, fmt.Errorf("SM4 key must be %d bytes, got %d", SM4BlockBytes, len(key))
	}
	params, err := BuildDirectCKKSParameters(logN)
	if err != nil {
		return nil, err
	}
	return &Suite{
		Direct: NewDirectCKKSContext(params),
		SM4:    ckks_cipher.NewPlainSM4Cipher(key),
	}, nil
}

func (suite *Suite) VerifyDataset(dataset Dataset) (float64, error) {
	if len(dataset.Transactions) == 0 {
		return 0, fmt.Errorf("dataset %q has no transactions", dataset.Name)
	}
	return suite.Direct.Verify(dataset.Transactions[0].Values)
}

func (suite *Suite) BenchmarkDataset(dataset Dataset, workers, runs int, baseIV []byte) ([]Result, error) {
	direct, err := BenchmarkDirectCKKS(suite.Direct, dataset, workers, runs)
	if err != nil {
		return nil, err
	}
	compact, err := BenchmarkSM4(suite.SM4, dataset, PathSM4CompactCTR, workers, runs, baseIV)
	if err != nil {
		return nil, err
	}
	slotReady, err := BenchmarkSM4(suite.SM4, dataset, PathSM4SlotReadyCTR, workers, runs, baseIV)
	if err != nil {
		return nil, err
	}
	return []Result{direct, compact, slotReady}, nil
}

func BenchmarkDirectCKKS(ctx *DirectCKKSContext, dataset Dataset, workers, runs int) (Result, error) {
	if err := validateBenchmarkInputs(dataset, workers, runs); err != nil {
		return Result{}, err
	}
	workerContexts := make([]*DirectCKKSWorker, workers)
	for index := range workerContexts {
		workerContexts[index] = ctx.NewWorker()
	}
	result := newResult(dataset, PathDirectCKKS, workers, runs)
	for run := 0; run < runs; run++ {
		metrics, err := runTransactions(len(dataset.Transactions), workers, func(workerIndex, transactionIndex int) (taskMetrics, error) {
			operation, err := workerContexts[workerIndex].EncryptAndSerialize(dataset.Transactions[transactionIndex].Values, io.Discard)
			if err != nil {
				return taskMetrics{}, err
			}
			return taskMetrics{
				ciphertextObjects: operation.CiphertextObjects,
				uploadBytes:       operation.UploadBytes,
				encodeDuration:    operation.EncodeDuration,
				encryptDuration:   operation.EncryptDuration,
				serializeDuration: operation.SerializeDuration,
				latency:           operation.TotalDuration,
			}, nil
		})
		if err != nil {
			return Result{}, fmt.Errorf("benchmark %s dataset=%s: %w", PathDirectCKKS, dataset.Name, err)
		}
		result.add(metrics)
	}
	result.finish()
	return result, nil
}

func BenchmarkSM4(cipher *ckks_cipher.PlainSM4Cipher, dataset Dataset, path Path, workers, runs int, baseIV []byte) (Result, error) {
	if err := validateBenchmarkInputs(dataset, workers, runs); err != nil {
		return Result{}, err
	}
	pathIV, err := DeriveDatasetPathIV(baseIV, dataset.Name, path)
	if err != nil {
		return Result{}, err
	}
	offsets, blocksPerRun, err := PlanCTROffsets(dataset, path)
	if err != nil {
		return Result{}, err
	}
	result := newResult(dataset, path, workers, runs)
	for run := 0; run < runs; run++ {
		runIV, err := AddCTRBlocks(pathIV, uint64(run)*blocksPerRun)
		if err != nil {
			return Result{}, err
		}
		metrics, err := runTransactions(len(dataset.Transactions), workers, func(_ int, transactionIndex int) (taskMetrics, error) {
			start := time.Now()
			transaction := dataset.Transactions[transactionIndex]
			var payload []byte
			var packDuration time.Duration
			switch path {
			case PathSM4CompactCTR:
				payload = transaction.Raw
			case PathSM4SlotReadyCTR:
				stage := time.Now()
				payload, err = PackSlotReady(transaction.Raw, dataset.ScalarBytes)
				packDuration = time.Since(stage)
				if err != nil {
					return taskMetrics{}, err
				}
			default:
				return taskMetrics{}, fmt.Errorf("path %q is not an SM4 layout", path)
			}
			transactionIV, err := AddCTRBlocks(runIV, offsets[transactionIndex])
			if err != nil {
				return taskMetrics{}, err
			}
			stage := time.Now()
			encrypted := cipher.CTR(transactionIV, payload)
			encryptDuration := time.Since(stage)
			return taskMetrics{
				ciphertextObjects: 1,
				uploadBytes:       int64(len(encrypted)),
				packDuration:      packDuration,
				encryptDuration:   encryptDuration,
				latency:           time.Since(start),
			}, nil
		})
		if err != nil {
			return Result{}, fmt.Errorf("benchmark %s dataset=%s: %w", path, dataset.Name, err)
		}
		metrics.uploadBytes += SM4IVMetadataBytes
		result.add(metrics)
	}
	result.finish()
	return result, nil
}

func newResult(dataset Dataset, path Path, workers, runs int) Result {
	return Result{
		Dataset:             dataset.Name,
		Path:                path,
		Workers:             workers,
		Runs:                runs,
		LogicalTransactions: int64(len(dataset.Transactions)),
		PlaintextBytes:      dataset.PlaintextBytes(),
	}
}

func (result *Result) add(metrics runMetrics) {
	result.CiphertextObjects += metrics.ciphertextObjects
	result.UploadBytes += metrics.uploadBytes
	result.PackDuration += metrics.packDuration
	result.EncodeDuration += metrics.encodeDuration
	result.EncryptDuration += metrics.encryptDuration
	result.SerializeDuration += metrics.serializeDuration
	result.TotalDuration += metrics.totalDuration
	result.AverageLatency += metrics.latency
}

func (result *Result) finish() {
	divisor := int64(result.Runs)
	result.CiphertextObjects /= divisor
	result.UploadBytes /= divisor
	result.StoredBytes = result.UploadBytes
	result.PackDuration /= time.Duration(result.Runs)
	result.EncodeDuration /= time.Duration(result.Runs)
	result.EncryptDuration /= time.Duration(result.Runs)
	result.SerializeDuration /= time.Duration(result.Runs)
	result.TotalDuration /= time.Duration(result.Runs)
	result.AverageLatency /= time.Duration(result.Runs) * time.Duration(result.LogicalTransactions)
	if result.PlaintextBytes > 0 {
		result.StorageExpansionRatio = float64(result.StoredBytes) / float64(result.PlaintextBytes)
	}
	if result.TotalDuration > 0 {
		seconds := result.TotalDuration.Seconds()
		result.TransactionsPerSecond = float64(result.LogicalTransactions) / seconds
		result.UploadPreparationMiBPerSecond = float64(result.UploadBytes) / (1024 * 1024) / seconds
	}
}

func validateBenchmarkInputs(dataset Dataset, workers, runs int) error {
	if len(dataset.Transactions) == 0 {
		return fmt.Errorf("dataset %q has no transactions", dataset.Name)
	}
	if workers <= 0 {
		return fmt.Errorf("workers must be positive, got %d", workers)
	}
	if runs <= 0 {
		return fmt.Errorf("runs must be positive, got %d", runs)
	}
	return nil
}

func runTransactions(transactions, workers int, task func(workerIndex, transactionIndex int) (taskMetrics, error)) (runMetrics, error) {
	start := time.Now()
	jobs := make(chan int, transactions)
	results := make(chan taskMetrics, workers)
	errors := make(chan error, workers)
	for index := 0; index < transactions; index++ {
		jobs <- index
	}
	close(jobs)

	var group sync.WaitGroup
	for workerIndex := 0; workerIndex < workers; workerIndex++ {
		group.Add(1)
		go func(workerIndex int) {
			defer group.Done()
			var total taskMetrics
			for transactionIndex := range jobs {
				metrics, err := task(workerIndex, transactionIndex)
				if err != nil {
					errors <- err
					return
				}
				total.add(metrics)
			}
			results <- total
		}(workerIndex)
	}
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			return runMetrics{}, err
		}
	}
	var total taskMetrics
	for metrics := range results {
		total.add(metrics)
	}
	return runMetrics{taskMetrics: total, totalDuration: time.Since(start)}, nil
}

func (metrics *taskMetrics) add(other taskMetrics) {
	metrics.ciphertextObjects += other.ciphertextObjects
	metrics.uploadBytes += other.uploadBytes
	metrics.packDuration += other.packDuration
	metrics.encodeDuration += other.encodeDuration
	metrics.encryptDuration += other.encryptDuration
	metrics.serializeDuration += other.serializeDuration
	metrics.latency += other.latency
}
