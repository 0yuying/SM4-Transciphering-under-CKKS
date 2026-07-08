package storebench

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	SM4BlockBytes      = 16
	SM4IVMetadataBytes = 16
)

type Path string

const (
	PathDirectCKKS      Path = "direct_ckks"
	PathSM4CompactCTR   Path = "sm4_compact_ctr"
	PathSM4SlotReadyCTR Path = "sm4_slot_ready_ctr"
)

func PackSlotReady(raw []byte, scalarBytes int) ([]byte, error) {
	if scalarBytes <= 0 || len(raw)%scalarBytes != 0 {
		return nil, fmt.Errorf("raw bytes=%d are not divisible by scalar bytes=%d", len(raw), scalarBytes)
	}
	scalars := len(raw) / scalarBytes
	out := make([]byte, scalars*SM4BlockBytes)
	for index := 0; index < scalars; index++ {
		copy(out[index*SM4BlockBytes:], raw[index*scalarBytes:(index+1)*scalarBytes])
	}
	return out, nil
}

func DeriveDatasetPathIV(base []byte, dataset string, path Path) ([]byte, error) {
	if len(base) != SM4BlockBytes {
		return nil, fmt.Errorf("SM4 IV must be %d bytes, got %d", SM4BlockBytes, len(base))
	}
	digest := sha256.New()
	_, _ = digest.Write(base)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(dataset))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(path))
	return digest.Sum(nil)[:SM4BlockBytes], nil
}

func AddCTRBlocks(iv []byte, blocks uint64) ([]byte, error) {
	if len(iv) != SM4BlockBytes {
		return nil, fmt.Errorf("SM4 IV must be %d bytes, got %d", SM4BlockBytes, len(iv))
	}
	out := append([]byte(nil), iv...)
	low := binary.BigEndian.Uint64(out[8:])
	high := binary.BigEndian.Uint64(out[:8])
	newLow := low + blocks
	if newLow < low {
		high++
	}
	binary.BigEndian.PutUint64(out[:8], high)
	binary.BigEndian.PutUint64(out[8:], newLow)
	return out, nil
}

func CTRBlocksForBytes(bytes int) uint64 {
	if bytes <= 0 {
		return 0
	}
	return uint64((bytes + SM4BlockBytes - 1) / SM4BlockBytes)
}

func PlanCTROffsets(dataset Dataset, path Path) ([]uint64, uint64, error) {
	offsets := make([]uint64, len(dataset.Transactions))
	var total uint64
	for index, transaction := range dataset.Transactions {
		offsets[index] = total
		payloadBytes, err := sm4PayloadBytes(transaction, dataset.ScalarBytes, path)
		if err != nil {
			return nil, 0, err
		}
		total += CTRBlocksForBytes(payloadBytes)
	}
	return offsets, total, nil
}

func sm4PayloadBytes(transaction Transaction, scalarBytes int, path Path) (int, error) {
	switch path {
	case PathSM4CompactCTR:
		return len(transaction.Raw), nil
	case PathSM4SlotReadyCTR:
		if scalarBytes <= 0 || len(transaction.Raw)%scalarBytes != 0 {
			return 0, fmt.Errorf("raw bytes=%d are not divisible by scalar bytes=%d", len(transaction.Raw), scalarBytes)
		}
		return len(transaction.Raw) / scalarBytes * SM4BlockBytes, nil
	default:
		return 0, fmt.Errorf("path %q is not an SM4 layout", path)
	}
}
