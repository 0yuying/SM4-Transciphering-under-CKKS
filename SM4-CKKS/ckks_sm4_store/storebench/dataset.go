package storebench

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DatasetAll   = "all"
	DatasetLoan  = "loan"
	DatasetFaces = "faces"
)

type Transaction struct {
	Raw    []byte
	Values []float64
}

type Dataset struct {
	Name                  string
	ScalarBytes           int
	ScalarsPerTransaction int
	Transactions          []Transaction
}

type manifest struct {
	Version  int                        `json:"version"`
	Datasets map[string]manifestDataset `json:"datasets"`
}

type manifestDataset struct {
	File                  string `json:"file"`
	Transactions          int    `json:"transactions"`
	ScalarBytes           int    `json:"scalar_bytes"`
	ScalarsPerTransaction int    `json:"scalars_per_transaction"`
	PlaintextBytes        int    `json:"plaintext_bytes"`
	SHA256                string `json:"sha256"`
}

func LoadDatasets(dir, selection string, limit int) ([]Dataset, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read dataset manifest: %w", err)
	}
	var metadata manifest
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("decode dataset manifest: %w", err)
	}
	if metadata.Version != 1 {
		return nil, fmt.Errorf("unsupported dataset manifest version=%d", metadata.Version)
	}
	names, err := selectedDatasetNames(selection)
	if err != nil {
		return nil, err
	}
	datasets := make([]Dataset, 0, len(names))
	for _, name := range names {
		entry, ok := metadata.Datasets[name]
		if !ok {
			return nil, fmt.Errorf("dataset manifest does not contain %q", name)
		}
		dataset, err := loadDataset(dir, name, entry, limit)
		if err != nil {
			return nil, err
		}
		datasets = append(datasets, dataset)
	}
	return datasets, nil
}

func selectedDatasetNames(selection string) ([]string, error) {
	switch selection {
	case DatasetAll:
		return []string{DatasetLoan, DatasetFaces}, nil
	case DatasetLoan, DatasetFaces:
		return []string{selection}, nil
	default:
		return nil, fmt.Errorf("dataset must be %q, %q, or %q, got %q", DatasetAll, DatasetLoan, DatasetFaces, selection)
	}
}

func loadDataset(dir, name string, entry manifestDataset, limit int) (Dataset, error) {
	if entry.Transactions <= 0 || entry.ScalarBytes <= 0 || entry.ScalarsPerTransaction <= 0 {
		return Dataset{}, fmt.Errorf("dataset %q manifest has invalid dimensions", name)
	}
	transactionBytes := entry.ScalarBytes * entry.ScalarsPerTransaction
	if entry.PlaintextBytes != entry.Transactions*transactionBytes {
		return Dataset{}, fmt.Errorf("dataset %q manifest plaintext bytes=%d, want %d", name, entry.PlaintextBytes, entry.Transactions*transactionBytes)
	}
	payload, err := os.ReadFile(filepath.Join(dir, entry.File))
	if err != nil {
		return Dataset{}, fmt.Errorf("read dataset %q: %w", name, err)
	}
	if len(payload) != entry.PlaintextBytes {
		return Dataset{}, fmt.Errorf("dataset %q bytes=%d, want %d", name, len(payload), entry.PlaintextBytes)
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != entry.SHA256 {
		return Dataset{}, fmt.Errorf("dataset %q sha256=%s, want %s", name, got, entry.SHA256)
	}
	count := entry.Transactions
	if limit > 0 && limit < count {
		count = limit
	}
	transactions := make([]Transaction, count)
	for index := 0; index < count; index++ {
		raw := payload[index*transactionBytes : (index+1)*transactionBytes]
		values, err := decodeValues(raw, entry.ScalarBytes)
		if err != nil {
			return Dataset{}, fmt.Errorf("decode dataset %q transaction=%d: %w", name, index, err)
		}
		transactions[index] = Transaction{Raw: raw, Values: values}
	}
	return Dataset{
		Name:                  name,
		ScalarBytes:           entry.ScalarBytes,
		ScalarsPerTransaction: entry.ScalarsPerTransaction,
		Transactions:          transactions,
	}, nil
}

func decodeValues(raw []byte, scalarBytes int) ([]float64, error) {
	if scalarBytes <= 0 || len(raw)%scalarBytes != 0 {
		return nil, fmt.Errorf("raw bytes=%d are not divisible by scalar bytes=%d", len(raw), scalarBytes)
	}
	values := make([]float64, len(raw)/scalarBytes)
	switch scalarBytes {
	case 1:
		for index, value := range raw {
			values[index] = float64(value)
		}
	case 2:
		for index := range values {
			values[index] = float64(binary.BigEndian.Uint16(raw[index*2:]))
		}
	default:
		return nil, fmt.Errorf("unsupported scalar bytes=%d", scalarBytes)
	}
	return values, nil
}

func (dataset Dataset) PlaintextBytes() int64 {
	var total int64
	for _, transaction := range dataset.Transactions {
		total += int64(len(transaction.Raw))
	}
	return total
}
