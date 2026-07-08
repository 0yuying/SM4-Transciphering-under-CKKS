package ckks_cipher

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// applySboxStageEager is a reference/test-only eager S-box path.
// Production code uses the lazy path via applySboxStage/applySboxStageLazy.
func (sm4 *SM4Ctr) applySboxStageEager(tmp []*rlwe.Ciphertext) error {
	sboxTasks := 4
	sboxWorkers := sm4.sboxWorkerCount(sboxTasks)
	if sboxWorkers <= 1 {
		evalCopy := sm4.ensureEvalPool(&sm4.sboxEvalPool, 1)[0]
		for byteIdx := 0; byteIdx < sboxTasks; byteIdx++ {
			if err := sm4.sm4SubbyteLUTEager(evalCopy, tmp[byteIdx*8:(byteIdx+1)*8]); err != nil {
				return err
			}
		}
		return nil
	}

	evals := sm4.ensureEvalPool(&sm4.sboxEvalPool, sboxWorkers)
	var next int64
	var sboxWG sync.WaitGroup
	var once sync.Once
	var firstErr error
	sboxWG.Add(sboxWorkers)
	for w := 0; w < sboxWorkers; w++ {
		evalCopy := evals[w]
		go func(evalCopy *bootstrapping.Evaluator) {
			defer sboxWG.Done()
			for {
				byteIdx := int(atomic.AddInt64(&next, 1) - 1)
				if byteIdx >= sboxTasks {
					return
				}
				if err := sm4.sm4SubbyteLUTEager(evalCopy, tmp[byteIdx*8:(byteIdx+1)*8]); err != nil {
					once.Do(func() {
						firstErr = fmt.Errorf("eager SBox byte %d failed: %w", byteIdx, err)
					})
				}
			}
		}(evalCopy)
	}
	sboxWG.Wait()
	return firstErr
}

// sm4SubbyteLUTEager is a reference/test-only eager ANF LUT implementation kept for validation.
func (sm4 *SM4Ctr) sm4SubbyteLUTEager(eval *bootstrapping.Evaluator, sboxIn []*rlwe.Ciphertext) error {
	if len(sboxIn) != 8 {
		return fmt.Errorf("The input length of the Sbox is wrong (8bit)")
	}
	sboxMonomials, err := LayeredCombine(eval, sboxIn)
	if err != nil {
		return fmt.Errorf("LayeredCombine failed: %w", err)
	}
	for bit := 0; bit < 8; bit++ {
		sboxIn[bit] = sm4.coefficientMultMonomial(eval, sboxMonomials, sm4.sboxSparseTerms[bit], sm4.sboxConstBits[bit])
	}
	return nil
}
