package storebench

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Report struct {
	GeneratedAtUTC string             `json:"generated_at_utc"`
	Preset         string             `json:"preset"`
	LogN           int                `json:"logN"`
	Slots          int                `json:"slots"`
	Workers        []int              `json:"workers"`
	Runs           int                `json:"runs"`
	Verification   map[string]float64 `json:"direct_ckks_verification_max_abs_error"`
	Results        []ReportRow        `json:"results"`
}

type ReportRow struct {
	Dataset                       string  `json:"dataset"`
	Path                          Path    `json:"path"`
	Workers                       int     `json:"workers"`
	Runs                          int     `json:"runs"`
	LogicalTransactions           int64   `json:"logical_transactions"`
	CiphertextObjects             int64   `json:"ciphertext_objects"`
	PlaintextBytes                int64   `json:"plaintext_bytes"`
	UploadBytes                   int64   `json:"upload_bytes"`
	StoredBytes                   int64   `json:"stored_bytes"`
	StorageExpansionRatio         float64 `json:"storage_expansion_ratio"`
	PackDuration                  string  `json:"pack_duration"`
	EncodeDuration                string  `json:"encode_duration"`
	EncryptDuration               string  `json:"encrypt_duration"`
	SerializeDuration             string  `json:"serialize_duration"`
	TotalDuration                 string  `json:"total_duration"`
	AverageLatency                string  `json:"average_latency"`
	TransactionsPerSecond         float64 `json:"transactions_per_second"`
	UploadPreparationMiBPerSecond float64 `json:"upload_preparation_mib_per_second"`
}

func NewReport(preset string, logN, slots, runs int, workers []int, verification map[string]float64, results []Result, now time.Time) Report {
	rows := make([]ReportRow, len(results))
	for index, result := range results {
		rows[index] = result.ReportRow()
	}
	return Report{
		GeneratedAtUTC: now.UTC().Format(time.RFC3339Nano),
		Preset:         preset,
		LogN:           logN,
		Slots:          slots,
		Workers:        append([]int(nil), workers...),
		Runs:           runs,
		Verification:   verification,
		Results:        rows,
	}
}

func (result Result) ReportRow() ReportRow {
	return ReportRow{
		Dataset:                       result.Dataset,
		Path:                          result.Path,
		Workers:                       result.Workers,
		Runs:                          result.Runs,
		LogicalTransactions:           result.LogicalTransactions,
		CiphertextObjects:             result.CiphertextObjects,
		PlaintextBytes:                result.PlaintextBytes,
		UploadBytes:                   result.UploadBytes,
		StoredBytes:                   result.StoredBytes,
		StorageExpansionRatio:         result.StorageExpansionRatio,
		PackDuration:                  result.PackDuration.String(),
		EncodeDuration:                result.EncodeDuration.String(),
		EncryptDuration:               result.EncryptDuration.String(),
		SerializeDuration:             result.SerializeDuration.String(),
		TotalDuration:                 result.TotalDuration.String(),
		AverageLatency:                result.AverageLatency.String(),
		TransactionsPerSecond:         result.TransactionsPerSecond,
		UploadPreparationMiBPerSecond: result.UploadPreparationMiBPerSecond,
	}
}

func WriteReport(dir string, report Report, now time.Time) (jsonPath, csvPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("create report directory: %w", err)
	}
	stamp := now.UTC().Format("20060102_150405.000000000")
	jsonPath = filepath.Join(dir, "store_bench_"+stamp+".json")
	csvPath = filepath.Join(dir, "store_bench_"+stamp+".csv")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode JSON report: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		return "", "", fmt.Errorf("write JSON report: %w", err)
	}
	if err := writeCSVReport(csvPath, report.Results); err != nil {
		return "", "", err
	}
	return jsonPath, csvPath, nil
}

func writeCSVReport(path string, rows []ReportRow) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create CSV report: %w", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	header := []string{
		"dataset", "path", "workers", "runs", "logical_transactions", "ciphertext_objects",
		"plaintext_bytes", "upload_bytes", "stored_bytes", "storage_expansion_ratio",
		"pack_duration", "encode_duration", "encrypt_duration", "serialize_duration",
		"total_duration", "average_latency", "transactions_per_second",
		"upload_preparation_mib_per_second",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	for _, row := range rows {
		record := []string{
			row.Dataset,
			string(row.Path),
			strconv.Itoa(row.Workers),
			strconv.Itoa(row.Runs),
			strconv.FormatInt(row.LogicalTransactions, 10),
			strconv.FormatInt(row.CiphertextObjects, 10),
			strconv.FormatInt(row.PlaintextBytes, 10),
			strconv.FormatInt(row.UploadBytes, 10),
			strconv.FormatInt(row.StoredBytes, 10),
			strconv.FormatFloat(row.StorageExpansionRatio, 'f', 8, 64),
			row.PackDuration,
			row.EncodeDuration,
			row.EncryptDuration,
			row.SerializeDuration,
			row.TotalDuration,
			row.AverageLatency,
			strconv.FormatFloat(row.TransactionsPerSecond, 'f', 8, 64),
			strconv.FormatFloat(row.UploadPreparationMiBPerSecond, 'f', 8, 64),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write CSV row: %w", err)
		}
	}
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush CSV report: %w", err)
	}
	return nil
}
