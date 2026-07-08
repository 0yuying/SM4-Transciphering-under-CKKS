package ckks_cipher

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type sm4OptimizedBucketKey struct {
	level        int
	logScaleBits uint64
}

type sm4OptimizedBucket struct {
	perBit [8]*rlwe.Ciphertext
}

func (sm4 *SM4Ctr) applySboxStage(tmp []*rlwe.Ciphertext) (sm4SboxOpStats, error) {
	return sm4.applySboxStageOptimized(tmp)
}

func (sm4 *SM4Ctr) applySboxStageOptimized(tmp []*rlwe.Ciphertext) (sm4SboxOpStats, error) {
	sboxTasks := 4
	sboxWorkers := sm4.sboxWorkerCount(sboxTasks)

	byteOut := make([][8]*rlwe.Ciphertext, sboxTasks)
	byteStats := make([]sm4SboxOpStats, sboxTasks)

	if sboxWorkers <= 1 {
		evalCopy := sm4.ensureEvalPool(&sm4.sboxEvalPool, 1)[0]
		for byteIdx := 0; byteIdx < sboxTasks; byteIdx++ {
			out, stats, err := sm4.sm4SubbyteLUTOptimized(evalCopy, tmp[byteIdx*8:(byteIdx+1)*8])
			if err != nil {
				return sm4SboxOpStats{}, fmt.Errorf("optimized SBox byte %d failed: %w", byteIdx, err)
			}
			byteOut[byteIdx] = out
			byteStats[byteIdx] = stats
		}
	} else {
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
					out, stats, err := sm4.sm4SubbyteLUTOptimized(evalCopy, tmp[byteIdx*8:(byteIdx+1)*8])
					if err != nil {
						once.Do(func() {
							firstErr = fmt.Errorf("optimized SBox byte %d failed: %w", byteIdx, err)
						})
						continue
					}
					byteOut[byteIdx] = out
					byteStats[byteIdx] = stats
				}
			}(evalCopy)
		}
		sboxWG.Wait()

		if firstErr != nil {
			return sm4SboxOpStats{}, firstErr
		}
	}

	var total sm4SboxOpStats
	for byteIdx := 0; byteIdx < sboxTasks; byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			if byteOut[byteIdx][bit] == nil {
				return sm4SboxOpStats{}, fmt.Errorf("optimized SBox byte %d bit %d has nil output", byteIdx, bit)
			}
			tmp[byteIdx*8+bit] = byteOut[byteIdx][bit]
		}
		total.add(byteStats[byteIdx])
	}

	return total, nil
}

func (sm4 *SM4Ctr) sm4SubbyteLUTOptimized(eval *bootstrapping.Evaluator, sboxIn []*rlwe.Ciphertext) (out [8]*rlwe.Ciphertext, stats sm4SboxOpStats, err error) {
	if len(sboxIn) != 8 {
		return out, stats, fmt.Errorf("input length must be 8, got %d", len(sboxIn))
	}

	mulRelinRescaleNew := func(a, b *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
		prod, err := eval.MulRelinNew(a, b)
		if err != nil {
			return nil, err
		}
		stats.relin++
		if err = eval.Rescale(prod, prod); err != nil {
			return nil, err
		}
		stats.rescale++
		return prod, nil
	}

	group := make([][]*rlwe.Ciphertext, 4)
	for i := 0; i < 4; i++ {
		a := sboxIn[2*i]
		b := sboxIn[2*i+1]
		ab, err := mulRelinRescaleNew(a, b)
		if err != nil {
			return out, stats, fmt.Errorf("pair product[%d] failed: %w", i, err)
		}
		group[i] = []*rlwe.Ciphertext{a, b, ab}
	}

	left, err := sm4.combineMonomialReusable(eval, group[0], group[1], &stats)
	if err != nil {
		return out, stats, fmt.Errorf("left reusable combine failed: %w", err)
	}
	right, err := sm4.combineMonomialReusable(eval, group[2], group[3], &stats)
	if err != nil {
		return out, stats, fmt.Errorf("right reusable combine failed: %w", err)
	}
	if len(left) != 15 || len(right) != 15 {
		return out, stats, fmt.Errorf("unexpected reusable sizes: left=%d right=%d", len(left), len(right))
	}

	leftMinBefore := sm4MinLevel(left)
	rightMinBefore := sm4MinLevel(right)
	targetLevel, err := sm4.normalizeToTargetLevel(eval, left, right)
	if err != nil {
		return out, stats, fmt.Errorf("level normalization failed: %w", err)
	}
	stats.leftMinLevelBefore = leftMinBefore
	stats.rightMinLevelBefore = rightMinBefore
	stats.targetLevel = targetLevel

	buckets := make(map[sm4OptimizedBucketKey]*sm4OptimizedBucket)
	bucketKeys := make([]sm4OptimizedBucketKey, 0, 8)

	for i := 0; i < len(left); i++ {
		for j := 0; j < len(right); j++ {
			monomialIdx := i*len(right) + j
			contrib := sm4.sboxMonomialCoeff[monomialIdx]
			if len(contrib) == 0 {
				continue
			}

			prod, err := eval.MulNew(left[i], right[j])
			if err != nil {
				return out, stats, fmt.Errorf("optimized cross product(%d,%d) failed: %w", i, j, err)
			}

			key := sm4OptimizedBucketKey{
				level:        prod.Level(),
				logScaleBits: sm4QuantizedLogScaleBitsHalf(prod.LogScale()),
			}
			bucket := buckets[key]
			if bucket == nil {
				bucket = &sm4OptimizedBucket{}
				buckets[key] = bucket
				bucketKeys = append(bucketKeys, key)
			}

			coeffCache := make(map[int]*rlwe.Ciphertext)
			for _, bc := range contrib {
				if bc.coeff > 1 || bc.coeff < -1 {
					stats.coeffMulBaseline++
				}
				if err := sm4AddScaledTermCached(eval, &bucket.perBit[bc.bit], prod, bc.coeff, coeffCache, &stats); err != nil {
					return out, stats, fmt.Errorf("bucket accumulation failed for monomial %d (bit=%d): %w", monomialIdx, bc.bit, err)
				}
			}
		}
	}
	stats.bucketCount = len(bucketKeys)

	linearSums := [8]*rlwe.Ciphertext{}
	for idx := 0; idx < len(left); idx++ {
		monomialIdx := 225 + idx
		for _, bc := range sm4.sboxMonomialCoeff[monomialIdx] {
			if err := sm4AddScaledTerm(eval, &linearSums[bc.bit], left[idx], bc.coeff); err != nil {
				return out, stats, fmt.Errorf("left tail accumulation failed for monomial %d (bit=%d): %w", monomialIdx, bc.bit, err)
			}
		}
	}
	for idx := 0; idx < len(right); idx++ {
		monomialIdx := 240 + idx
		for _, bc := range sm4.sboxMonomialCoeff[monomialIdx] {
			if err := sm4AddScaledTerm(eval, &linearSums[bc.bit], right[idx], bc.coeff); err != nil {
				return out, stats, fmt.Errorf("right tail accumulation failed for monomial %d (bit=%d): %w", monomialIdx, bc.bit, err)
			}
		}
	}

	sort.Slice(bucketKeys, func(i, j int) bool {
		if bucketKeys[i].level != bucketKeys[j].level {
			return bucketKeys[i].level > bucketKeys[j].level
		}
		return math.Float64frombits(bucketKeys[i].logScaleBits) > math.Float64frombits(bucketKeys[j].logScaleBits)
	})

	for _, key := range bucketKeys {
		bucket := buckets[key]
		for bit := 0; bit < 8; bit++ {
			term := bucket.perBit[bit]
			if term == nil {
				continue
			}

			if term.Degree() == 2 {
				if err := eval.Relinearize(term, term); err != nil {
					return out, stats, fmt.Errorf("bucket relin failed (bit=%d, level=%d): %w", bit, key.level, err)
				}
				stats.relin++
			}

			if err := eval.Rescale(term, term); err != nil {
				return out, stats, fmt.Errorf("bucket rescale failed (bit=%d, level=%d): %w", bit, key.level, err)
			}
			stats.rescale++

			if err := sm4AddScaledTerm(eval, &linearSums[bit], term, 1); err != nil {
				return out, stats, fmt.Errorf("merge partial sum failed (bit=%d): %w", bit, err)
			}
		}
	}

	for bit := 0; bit < 8; bit++ {
		if linearSums[bit] == nil {
			zero := sboxIn[0].CopyNew()
			if err := eval.Mul(zero, 0, zero); err != nil {
				return out, stats, fmt.Errorf("zero init failed (bit=%d): %w", bit, err)
			}
			linearSums[bit] = zero
		}

		if sm4.sboxConstBits[bit] != 0 {
			if err := eval.Add(linearSums[bit], sm4.sboxConstBits[bit], linearSums[bit]); err != nil {
				return out, stats, fmt.Errorf("constant add failed (bit=%d): %w", bit, err)
			}
		}

		out[bit] = linearSums[bit]
	}

	return out, stats, nil
}

func (sm4 *SM4Ctr) combineMonomialReusable(eval *bootstrapping.Evaluator, left, right []*rlwe.Ciphertext, stats *sm4SboxOpStats) ([]*rlwe.Ciphertext, error) {
	combined := make([]*rlwe.Ciphertext, 0, len(left)*len(right))
	for i := 0; i < len(left); i++ {
		for j := 0; j < len(right); j++ {
			prod, err := eval.MulRelinNew(left[i], right[j])
			if err != nil {
				return nil, err
			}
			stats.relin++
			if err := eval.Rescale(prod, prod); err != nil {
				return nil, err
			}
			stats.rescale++
			combined = append(combined, prod)
		}
	}

	merged := make([]*rlwe.Ciphertext, 0, len(combined)+len(left)+len(right))
	merged = append(merged, combined...)
	merged = append(merged, left...)
	merged = append(merged, right...)
	return merged, nil
}

func sm4MinLevel(cts []*rlwe.Ciphertext) int {
	minLvl := math.MaxInt
	for _, ct := range cts {
		if ct != nil && ct.Level() < minLvl {
			minLvl = ct.Level()
		}
	}
	if minLvl == math.MaxInt {
		return 0
	}
	return minLvl
}

func sm4QuantizedLogScaleBitsHalf(logScale float64) uint64 {
	return math.Float64bits(math.Round(logScale*2) / 2)
}

func (sm4 *SM4Ctr) normalizeToTargetLevel(eval *bootstrapping.Evaluator, left, right []*rlwe.Ciphertext) (int, error) {
	if len(left) == 0 || len(right) == 0 {
		return 0, fmt.Errorf("left/right monomial sets must be non-empty")
	}

	target := sm4MinLevel(left)
	rightMin := sm4MinLevel(right)
	if rightMin < target {
		target = rightMin
	}

	dropTo := func(cts []*rlwe.Ciphertext) error {
		for _, ct := range cts {
			if ct == nil {
				continue
			}
			if ct.Level() < target {
				return fmt.Errorf("ciphertext level %d below target %d", ct.Level(), target)
			}
			if ct.Level() > target {
				eval.DropLevel(ct, ct.Level()-target)
			}
		}
		return nil
	}

	if err := dropTo(left); err != nil {
		return 0, err
	}
	if err := dropTo(right); err != nil {
		return 0, err
	}

	return target, nil
}

func sm4AddScaledTermCached(eval *bootstrapping.Evaluator, acc **rlwe.Ciphertext, src *rlwe.Ciphertext, coeff int, cache map[int]*rlwe.Ciphertext, stats *sm4SboxOpStats) error {
	if coeff == 0 || src == nil {
		return nil
	}

	switch coeff {
	case 1:
		return sm4AddScaledTerm(eval, acc, src, 1)
	case -1:
		return sm4AddScaledTerm(eval, acc, src, -1)
	default:
		tmp := cache[coeff]
		if tmp == nil {
			tmp = src.CopyNew()
			if err := eval.Mul(tmp, coeff, tmp); err != nil {
				return err
			}
			cache[coeff] = tmp
			if stats != nil {
				stats.coeffMul++
			}
		}
		return sm4AddScaledTerm(eval, acc, tmp, 1)
	}
}

func sm4AddScaledTerm(eval *bootstrapping.Evaluator, acc **rlwe.Ciphertext, src *rlwe.Ciphertext, coeff int) error {
	if coeff == 0 || src == nil {
		return nil
	}

	if *acc == nil {
		tmp := src.CopyNew()
		if coeff != 1 {
			if err := eval.Mul(tmp, coeff, tmp); err != nil {
				return err
			}
		}
		*acc = tmp
		return nil
	}

	switch coeff {
	case 1:
		return eval.Add(*acc, src, *acc)
	case -1:
		return eval.Sub(*acc, src, *acc)
	default:
		tmp := src.CopyNew()
		if err := eval.Mul(tmp, coeff, tmp); err != nil {
			return err
		}
		return eval.Add(*acc, tmp, *acc)
	}
}
