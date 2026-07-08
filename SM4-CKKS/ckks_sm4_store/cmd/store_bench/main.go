package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_store/storebench"
)

type preset struct {
	workers []int
	runs    int
}

var presets = map[string]preset{
	"quick":   {workers: []int{1}, runs: 1},
	"default": {workers: []int{1, 4, 8, 16}, runs: 3},
	"paper":   {workers: []int{1, 4, 8, 16}, runs: 10},
}

func main() {
	presetName := flag.String("preset", "default", "benchmark preset: quick, default, or paper")
	dataset := flag.String("dataset", storebench.DatasetAll, "dataset: all, loan, or faces")
	workersOverride := flag.String("workers", "", "comma-separated worker counts; empty uses preset")
	runsOverride := flag.Int("runs", 0, "runs per dataset/path/worker combination; <=0 uses preset")
	limit := flag.Int("limit", 0, "maximum transactions per dataset; <=0 uses all prepared transactions")
	logN := flag.Int("logN", storebench.DefaultLogN, "CKKS logN")
	keyHex := flag.String("key-hex", "", "16-byte SM4 key as hex; empty means all zero")
	ivHex := flag.String("iv-hex", "", "16-byte SM4 base IV as hex; empty means all zero")
	dataDir := flag.String("data-dir", "./data/generated", "prepared dataset directory")
	outDir := flag.String("out-dir", "./results", "report output directory")
	flag.Parse()

	selectedPreset, ok := presets[*presetName]
	if !ok {
		exitError(fmt.Errorf("unknown preset %q", *presetName))
	}
	workers := selectedPreset.workers
	var err error
	if *workersOverride != "" {
		if workers, err = parseWorkers(*workersOverride); err != nil {
			exitError(err)
		}
	}
	runs := selectedPreset.runs
	if *runsOverride > 0 {
		runs = *runsOverride
	}
	key, err := parseHex16(*keyHex, "key")
	if err != nil {
		exitError(err)
	}
	iv, err := parseHex16(*ivHex, "iv")
	if err != nil {
		exitError(err)
	}
	datasets, err := storebench.LoadDatasets(*dataDir, *dataset, *limit)
	if err != nil {
		exitError(err)
	}

	initStart := time.Now()
	suite, err := storebench.NewSuite(*logN, key)
	if err != nil {
		exitError(err)
	}
	fmt.Printf("[store_bench][init] preset=%s logN=%d slots=%d workers=%v runs=%d datasets=%d init=%s\n",
		*presetName, *logN, suite.Direct.Params.MaxSlots(), workers, runs, len(datasets), time.Since(initStart))

	verification := make(map[string]float64, len(datasets))
	var results []storebench.Result
	for _, currentDataset := range datasets {
		maxError, err := suite.VerifyDataset(currentDataset)
		if err != nil {
			exitError(err)
		}
		verification[currentDataset.Name] = maxError
		fmt.Printf("[store_bench][verify] dataset=%s transactions=%d plaintext_bytes=%d direct_ckks_max_abs_error=%.8g\n",
			currentDataset.Name, len(currentDataset.Transactions), currentDataset.PlaintextBytes(), maxError)
		for _, workerCount := range workers {
			fmt.Printf("[store_bench][run] dataset=%s workers=%d runs=%d\n", currentDataset.Name, workerCount, runs)
			currentResults, err := suite.BenchmarkDataset(currentDataset, workerCount, runs, iv)
			if err != nil {
				exitError(err)
			}
			for _, result := range currentResults {
				printResult(result)
			}
			results = append(results, currentResults...)
		}
	}

	printTable(results)
	now := time.Now()
	report := storebench.NewReport(*presetName, *logN, suite.Direct.Params.MaxSlots(), runs, workers, verification, results, now)
	jsonPath, csvPath, err := storebench.WriteReport(*outDir, report, now)
	if err != nil {
		exitError(err)
	}
	fmt.Printf("[store_bench][report] json=%s csv=%s\n", jsonPath, csvPath)
}

func printResult(result storebench.Result) {
	fmt.Printf("[store_bench][summary] dataset=%s path=%s workers=%d runs=%d transactions=%d ciphertext_objects=%d plaintext_bytes=%d upload_bytes=%d stored_bytes=%d expansion=%.4fx pack=%s encode=%s encrypt=%s serialize=%s total=%s avg_latency=%s tps=%.4f upload_preparation_mib_per_sec=%.4f\n",
		result.Dataset,
		result.Path,
		result.Workers,
		result.Runs,
		result.LogicalTransactions,
		result.CiphertextObjects,
		result.PlaintextBytes,
		result.UploadBytes,
		result.StoredBytes,
		result.StorageExpansionRatio,
		result.PackDuration,
		result.EncodeDuration,
		result.EncryptDuration,
		result.SerializeDuration,
		result.TotalDuration,
		result.AverageLatency,
		result.TransactionsPerSecond,
		result.UploadPreparationMiBPerSecond)
}

func printTable(results []storebench.Result) {
	fmt.Println()
	fmt.Println("DATASET  PATH                WORKERS  RUNS  TX     CT_OBJECTS  PLAIN_BYTES  STORED_BYTES  EXPANSION   AVG_LATENCY  TPS")
	for _, result := range results {
		fmt.Printf("%-7s  %-18s  %7d  %4d  %5d  %10d  %11d  %12d  %8.2fx  %11s  %10.2f\n",
			result.Dataset,
			result.Path,
			result.Workers,
			result.Runs,
			result.LogicalTransactions,
			result.CiphertextObjects,
			result.PlaintextBytes,
			result.StoredBytes,
			result.StorageExpansionRatio,
			result.AverageLatency,
			result.TransactionsPerSecond)
	}
	fmt.Println()
}

func parseWorkers(value string) ([]int, error) {
	fields := strings.Split(value, ",")
	workers := make([]int, 0, len(fields))
	seen := make(map[int]bool, len(fields))
	for _, field := range fields {
		count, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || count <= 0 {
			return nil, fmt.Errorf("invalid worker count %q", field)
		}
		if !seen[count] {
			workers = append(workers, count)
			seen[count] = true
		}
	}
	if len(workers) == 0 {
		return nil, fmt.Errorf("workers must not be empty")
	}
	return workers, nil
}

func parseHex16(value, name string) ([]byte, error) {
	if value == "" {
		return make([]byte, 16), nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %w", name, err)
	}
	if len(decoded) != 16 {
		return nil, fmt.Errorf("%s must decode to 16 bytes, got %d", name, len(decoded))
	}
	return decoded, nil
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "store_bench:", err)
	os.Exit(2)
}
