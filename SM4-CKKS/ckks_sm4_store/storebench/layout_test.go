package storebench

import (
	"bytes"
	"testing"
)

func TestPackSlotReadyLoanAndFaces(t *testing.T) {
	loan, err := PackSlotReady([]byte{0x12, 0x34, 0xab, 0xcd}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(loan) != 2*SM4BlockBytes {
		t.Fatalf("loan bytes=%d", len(loan))
	}
	if !bytes.Equal(loan[:2], []byte{0x12, 0x34}) || !bytes.Equal(loan[16:18], []byte{0xab, 0xcd}) {
		t.Fatalf("loan payload=%x", loan)
	}
	faces, err := PackSlotReady([]byte{1, 2, 3}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(faces) != 3*SM4BlockBytes || faces[0] != 1 || faces[16] != 2 || faces[32] != 3 {
		t.Fatalf("faces payload=%x", faces)
	}
}

func TestPlanCTROffsetsDoesNotOverlapTransactionsOrRuns(t *testing.T) {
	dataset := Dataset{
		Name:        DatasetLoan,
		ScalarBytes: 2,
		Transactions: []Transaction{
			{Raw: []byte{0, 1}},
			{Raw: []byte{0, 2}},
			{Raw: []byte{0, 3}},
		},
	}
	offsets, total, err := PlanCTROffsets(dataset, PathSM4CompactCTR)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{0, 1, 2}; !equalUint64(offsets, want) || total != 3 {
		t.Fatalf("compact offsets=%v total=%d, want %v total=3", offsets, total, want)
	}
	offsets, total, err = PlanCTROffsets(dataset, PathSM4SlotReadyCTR)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{0, 1, 2}; !equalUint64(offsets, want) || total != 3 {
		t.Fatalf("slot-ready offsets=%v total=%d, want %v total=3", offsets, total, want)
	}
	base := make([]byte, SM4BlockBytes)
	run1, err := AddCTRBlocks(base, total)
	if err != nil {
		t.Fatal(err)
	}
	if got := run1[15]; got != 3 {
		t.Fatalf("next run IV last byte=%d, want 3", got)
	}
}

func TestDeriveDatasetPathIVSeparatesLayouts(t *testing.T) {
	base := make([]byte, SM4BlockBytes)
	compact, err := DeriveDatasetPathIV(base, DatasetFaces, PathSM4CompactCTR)
	if err != nil {
		t.Fatal(err)
	}
	slotReady, err := DeriveDatasetPathIV(base, DatasetFaces, PathSM4SlotReadyCTR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(compact, slotReady) {
		t.Fatalf("derived IV collision: %x", compact)
	}
}

func TestAddCTRBlocksCarries(t *testing.T) {
	iv := make([]byte, SM4BlockBytes)
	iv[15] = 0xff
	got, err := AddCTRBlocks(iv, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got[14] != 1 || got[15] != 0 {
		t.Fatalf("counter=%x", got)
	}
}

func equalUint64(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
