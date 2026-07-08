package ckks_cipher

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
)

func TestSetBootModeValidation(t *testing.T) {
	sm4 := &SM4Ctr{bootMode: sm4BootModePair}

	if err := sm4.SetBootMode(sm4BootModeMany); err != nil {
		t.Fatalf("SetBootMode(many) returned error: %v", err)
	}
	if sm4.bootMode != sm4BootModeMany {
		t.Fatalf("boot mode mismatch: got %q, want %q", sm4.bootMode, sm4BootModeMany)
	}

	if err := sm4.SetBootMode("invalid"); err == nil {
		t.Fatalf("SetBootMode(invalid) expected error")
	}
	if sm4.bootMode != sm4BootModeMany {
		t.Fatalf("boot mode should remain unchanged on error: got %q", sm4.bootMode)
	}
}

func TestSetWorkerConfigResetsEvalPools(t *testing.T) {
	sm4 := &SM4Ctr{}
	sm4.bootstrapEvalPool = make([]*bootstrapping.Evaluator, 2)
	sm4.sboxEvalPool = make([]*bootstrapping.Evaluator, 2)

	sm4.SetWorkerConfig(3, 4)

	if sm4.bootstrapWorkers != 3 || sm4.sboxWorkers != 4 {
		t.Fatalf("worker config mismatch: bootstrap=%d sbox=%d", sm4.bootstrapWorkers, sm4.sboxWorkers)
	}
	if sm4.bootstrapEvalPool != nil || sm4.sboxEvalPool != nil {
		t.Fatalf("SetWorkerConfig should reset eval pools")
	}
}

func TestEncryptKeyUsesCacheFastPath(t *testing.T) {
	sm4 := &SM4Ctr{keyCacheReady: true}

	// Should be a no-op and must not panic even without encoder/encryptor.
	sm4.EncryptKey()
	sm4.WarmupKeySchedule()
}
