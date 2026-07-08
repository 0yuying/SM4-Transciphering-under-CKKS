package storebench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDatasetsAndLimit(t *testing.T) {
	dir := t.TempDir()
	writePreparedDataset(t, dir, map[string][]byte{
		DatasetLoan:  {0x00, 0x0a, 0x01, 0x00, 0xff, 0xff},
		DatasetFaces: {1, 2, 3, 4, 5, 6, 7, 8},
	}, map[string]manifestDataset{
		DatasetLoan:  {File: "loan.bin", Transactions: 3, ScalarBytes: 2, ScalarsPerTransaction: 1, PlaintextBytes: 6},
		DatasetFaces: {File: "faces.bin", Transactions: 2, ScalarBytes: 1, ScalarsPerTransaction: 4, PlaintextBytes: 8},
	})

	datasets, err := LoadDatasets(dir, DatasetAll, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(datasets) != 2 {
		t.Fatalf("datasets=%d, want 2", len(datasets))
	}
	if got := datasets[0].Transactions[1].Values[0]; got != 256 {
		t.Fatalf("loan value=%v, want 256", got)
	}
	if got := len(datasets[1].Transactions); got != 2 {
		t.Fatalf("faces transactions=%d, want 2", got)
	}
	if got := datasets[1].Transactions[0].Values; len(got) != 4 || got[3] != 4 {
		t.Fatalf("faces values=%v", got)
	}
}

func TestLoadDatasetsRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	writePreparedDataset(t, dir, map[string][]byte{
		DatasetLoan: {0x00, 0x0a},
	}, map[string]manifestDataset{
		DatasetLoan: {File: "loan.bin", Transactions: 1, ScalarBytes: 2, ScalarsPerTransaction: 1, PlaintextBytes: 2},
	})
	if err := os.WriteFile(filepath.Join(dir, "loan.bin"), []byte{0x00, 0x0b}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDatasets(dir, DatasetLoan, 0); err == nil {
		t.Fatal("expected hash mismatch")
	}
}

func writePreparedDataset(t *testing.T, dir string, payloads map[string][]byte, entries map[string]manifestDataset) {
	t.Helper()
	for name, payload := range payloads {
		entry := entries[name]
		digest := sha256.Sum256(payload)
		entry.SHA256 = hex.EncodeToString(digest[:])
		entries[name] = entry
		if err := os.WriteFile(filepath.Join(dir, entry.File), payload, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(manifest{Version: 1, Datasets: entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
