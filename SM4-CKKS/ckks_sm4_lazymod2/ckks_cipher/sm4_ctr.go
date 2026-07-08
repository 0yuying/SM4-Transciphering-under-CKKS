package ckks_cipher

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// 结构体定义
type SM4Ctr struct {
	*RtBCipher
	iv        []byte
	blockSize int
	keySize   int
	rounds    int
	progress  bool
	logWriter io.Writer

	// instanceMu serializes configuration updates and worker snapshot creation.
	// HEDecrypt runs on a worker-local SM4Ctr copy prepared under this lock.
	instanceMu sync.Mutex

	bitSbox           []*BitSet
	sboxMonomialOrder []*BitSet
	sboxSparseTerms   [8][]sm4SboxTerm
	sboxMonomialCoeff [255][]sm4SboxBitCoeff
	sboxConstBits     [8]int
	allZeroIn         bool

	// ===== SM4 round keys (32 rounds × 32 bits) =====
	rkEncrypted [][]*rlwe.Ciphertext

	// key schedule cache
	keyCacheMu    sync.Mutex
	keyCacheReady bool

	// reusable scratch buffers
	scratchMu         sync.Mutex
	slotFloatScratch  []float64
	slotCmplxScratch  []complex128
	inputBitScratch   []*BitSet
	cipherBitScratch  []*BitSet
	bootstrapEvalPool []*bootstrapping.Evaluator
	sboxEvalPool      []*bootstrapping.Evaluator

	// perf knobs
	bootstrapWorkers    int
	sboxWorkers         int
	legacyTwoBootRounds bool
}

type roundTiming struct {
	tmpXOR         time.Duration
	tmpBootstrap   time.Duration
	sbox           time.Duration
	linear         time.Duration
	x4XORAndCheck  time.Duration
	x4BootAndSplit time.Duration
	shift          time.Duration
}

type sm4CiphertextInventory struct {
	roundKeys         int
	inputCounters     int
	encodedCiphertext int
	state             int
	output            int
	logical           int
	unique            int
}

type sm4HEDecryptMetrics struct {
	bits       int
	bytes      int
	blocks     int
	total      time.Duration
	sm4Runtime time.Duration
	rounds     time.Duration
	memStart   runtime.MemStats
	memEnd     runtime.MemStats
	cts        sm4CiphertextInventory
}

type sm4SboxTerm struct {
	monomialIdx int
	coeff       int
}

type sm4SboxBitCoeff struct {
	bit   int
	coeff int
}

type sm4SboxOpStats struct {
	relin               int
	rescale             int
	coeffMul            int
	coeffMulBaseline    int
	bucketCount         int
	leftMinLevelBefore  int
	rightMinLevelBefore int
	targetLevel         int
}

func (s *sm4SboxOpStats) add(other sm4SboxOpStats) {
	s.relin += other.relin
	s.rescale += other.rescale
	s.coeffMul += other.coeffMul
	s.coeffMulBaseline += other.coeffMulBaseline
	s.bucketCount += other.bucketCount
	s.leftMinLevelBefore += other.leftMinLevelBefore
	s.rightMinLevelBefore += other.rightMinLevelBefore
	s.targetLevel += other.targetLevel
}

const (
	sm4SboxEagerRelinPerByte   = 247
	sm4SboxEagerRescalePerByte = 247
	sm4OneBootTmpBound         = 124
	sm4OneBootFinalBound       = 41
	sm4SboxLFusedLazyMode      = "sbox-l-fused-lazy"
)

func (t roundTiming) total() time.Duration {
	return t.tmpXOR + t.tmpBootstrap + t.sbox + t.linear + t.x4XORAndCheck + t.x4BootAndSplit + t.shift
}

func (t *roundTiming) add(other roundTiming) {
	t.tmpXOR += other.tmpXOR
	t.tmpBootstrap += other.tmpBootstrap
	t.sbox += other.sbox
	t.linear += other.linear
	t.x4XORAndCheck += other.x4XORAndCheck
	t.x4BootAndSplit += other.x4BootAndSplit
	t.shift += other.shift
}

func pct(part, total time.Duration) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
}

// 结构体方法
func NewSM4Ctr(key_ []uint8, params_ ckks.Parameters, btpParams_ bootstrapping.Parameters, btpKey_ *bootstrapping.EvaluationKeys,
	encoder_ *ckks.Encoder, encryptor_ *rlwe.Encryptor, decryptor_ *rlwe.Decryptor, iv_ []byte) (*SM4Ctr, error) {

	rtb, err := NewRtBCipher(key_, params_, btpParams_, btpKey_, encoder_, encryptor_, decryptor_)
	if err != nil {
		return nil, err
	}

	if len(iv_) == 0 {
		iv_ = make([]byte, 16)
	}
	if len(iv_) != 16 {
		return nil, fmt.Errorf("NewSM4Ctr: iv must be 16 bytes, got %d", len(iv_))
	}
	ivCopy := make([]byte, 16)
	copy(ivCopy, iv_)

	sm4 := &SM4Ctr{
		RtBCipher: rtb,
		blockSize: 128,
		keySize:   128,
		rounds:    32,
		iv:        ivCopy,
		allZeroIn: false, // default to normal CTR input; debug mode must be enabled explicitly
		progress:  true,  // print progress by default to observe long HE execution
	}

	var monomialOrder []*BitSet
	for i := 0; i < 8; i++ {
		x := NewBitSet(8)
		x.Set(1 << i)
		monomialOrder = append(monomialOrder, x)
	}
	sm4.sboxMonomialOrder, _ = LayeredCombineBin(monomialOrder)

	for i := 0; i < 256; i++ {
		tmp := NewBitSet(8)
		tmp.Set(int(SM4Sbox[i]))
		sm4.bitSbox = append(sm4.bitSbox, tmp)
	}
	sm4.precomputeSboxSparseTerms()
	sm4.SetWorkerConfig(0, 0)

	return sm4, nil
}

func (sm4 *SM4Ctr) precomputeSboxSparseTerms() {
	coeffs := [8][]int{
		Sbox0[:], Sbox1[:], Sbox2[:], Sbox3[:],
		Sbox4[:], Sbox5[:], Sbox6[:], Sbox7[:],
	}

	for i := range sm4.sboxMonomialCoeff {
		sm4.sboxMonomialCoeff[i] = sm4.sboxMonomialCoeff[i][:0]
	}

	for bit := 0; bit < 8; bit++ {
		sm4.sboxConstBits[bit] = int(sm4.bitSbox[0].bits[bit])
		terms := make([]sm4SboxTerm, 0, len(sm4.sboxMonomialOrder))
		for monIdx := 0; monIdx < len(sm4.sboxMonomialOrder); monIdx++ {
			ind := int(sm4.sboxMonomialOrder[monIdx].ToULong()) - 1
			if ind < 0 || ind >= len(coeffs[bit]) {
				panic("sbox monomial index out of range")
			}
			coeff := coeffs[bit][ind]
			if coeff == 0 {
				continue
			}
			terms = append(terms, sm4SboxTerm{
				monomialIdx: monIdx,
				coeff:       coeff,
			})
			sm4.sboxMonomialCoeff[monIdx] = append(sm4.sboxMonomialCoeff[monIdx], sm4SboxBitCoeff{
				bit:   bit,
				coeff: coeff,
			})
		}
		sm4.sboxSparseTerms[bit] = terms
	}
}

// SetAllZeroInput toggles debug input mode.
// true  -> every input block is zero (debug)
// false -> use CTR(iv, blockIndex) inputs
func (sm4 *SM4Ctr) SetAllZeroInput(allZero bool) {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.allZeroIn = allZero
}

// SetProgressLog toggles progress logs for long-running HE evaluation.
func (sm4 *SM4Ctr) SetProgressLog(enabled bool) {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.progress = enabled
}

// SetLogWriter redirects SM4 runtime logs. A nil writer restores stdout.
func (sm4 *SM4Ctr) SetLogWriter(writer io.Writer) {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.logWriter = writer
}

// SetWorkerConfig sets worker counts used by bootstrap and S-box stages.
// value <= 0 means "auto" (runtime.GOMAXPROCS).
func (sm4 *SM4Ctr) SetWorkerConfig(bootstrapWorkers, sboxWorkers int) {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.scratchMu.Lock()
	defer sm4.scratchMu.Unlock()

	sm4.bootstrapWorkers = bootstrapWorkers
	sm4.sboxWorkers = sboxWorkers
	sm4.bootstrapEvalPool = nil
	sm4.sboxEvalPool = nil
}

// SetLegacyTwoBootRounds restores the previous lazy schedule that bootstraps both tmp and x4 every round.
func (sm4 *SM4Ctr) SetLegacyTwoBootRounds(enabled bool) {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.legacyTwoBootRounds = enabled
}

func (sm4 *SM4Ctr) useLazyMod2() bool {
	// Fixed strategy: short params use eager-mod2; larger params use lazy-mod2.
	return sm4.params.LogN() > 9
}

func (sm4 *SM4Ctr) useOneBootRounds() bool {
	return sm4.useLazyMod2() && !sm4.legacyTwoBootRounds
}

// WarmupKeySchedule precomputes and caches encrypted round keys used by the production round function.
func (sm4 *SM4Ctr) WarmupKeySchedule() {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.ensureEncryptedKeySchedule()
}

func levelRange(cts []*rlwe.Ciphertext) (minLevel, maxLevel int) {
	if len(cts) == 0 {
		return 0, 0
	}
	minLevel = cts[0].Level()
	maxLevel = cts[0].Level()
	for i := 1; i < len(cts); i++ {
		lvl := cts[i].Level()
		if lvl < minLevel {
			minLevel = lvl
		}
		if lvl > maxLevel {
			maxLevel = lvl
		}
	}
	return
}

func pickWorkerCount(configured, taskCount int) int {
	if taskCount <= 0 {
		return 0
	}
	workers := configured
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	if workers > taskCount {
		workers = taskCount
	}
	return workers
}

func (sm4 *SM4Ctr) bootstrapWorkerCount(taskCount int) int {
	return pickWorkerCount(sm4.bootstrapWorkers, taskCount)
}

func (sm4 *SM4Ctr) sboxWorkerCount(taskCount int) int {
	return pickWorkerCount(sm4.sboxWorkers, taskCount)
}

func (sm4 *SM4Ctr) finalOutputBitCount(bits, numBlock int) int {
	if bits > 0 && numBlock == 1 && bits < sm4.blockSize {
		return bits
	}
	return sm4.blockSize
}

func evenBootstrapBitCount(bitCount, maxBits int) int {
	if bitCount <= 0 {
		return 0
	}
	if bitCount > maxBits {
		bitCount = maxBits
	}
	if bitCount%2 != 0 {
		bitCount++
	}
	if bitCount > maxBits {
		bitCount = maxBits
	}
	return bitCount
}

func (sm4 *SM4Ctr) ensureScratch() {
	slots := sm4.params.MaxSlots()
	if len(sm4.slotFloatScratch) != slots {
		sm4.slotFloatScratch = make([]float64, slots)
	}
	if len(sm4.slotCmplxScratch) != slots {
		sm4.slotCmplxScratch = make([]complex128, slots)
	}

	if len(sm4.inputBitScratch) != slots {
		sm4.inputBitScratch = make([]*BitSet, slots)
		for i := range sm4.inputBitScratch {
			sm4.inputBitScratch[i] = NewBitSet(sm4.blockSize)
		}
	}

	if len(sm4.cipherBitScratch) != slots {
		sm4.cipherBitScratch = make([]*BitSet, slots)
		for i := range sm4.cipherBitScratch {
			sm4.cipherBitScratch[i] = NewBitSet(sm4.blockSize)
		}
	}
}

func (sm4 *SM4Ctr) ensureEvalPool(pool *[]*bootstrapping.Evaluator, workers int) []*bootstrapping.Evaluator {
	sm4.scratchMu.Lock()
	defer sm4.scratchMu.Unlock()

	if workers < 1 {
		workers = 1
	}
	if cap(*pool) < workers {
		newPool := make([]*bootstrapping.Evaluator, workers)
		copy(newPool, *pool)
		*pool = newPool
	} else {
		*pool = (*pool)[:workers]
	}
	for i := 0; i < workers; i++ {
		if (*pool)[i] == nil {
			(*pool)[i] = sm4.Evaluator.ShallowCopy()
		}
	}
	return *pool
}

func (sm4 *SM4Ctr) ensureEncryptedKeySchedule() {
	sm4.keyCacheMu.Lock()
	defer sm4.keyCacheMu.Unlock()
	if sm4.keyCacheReady {
		return
	}
	sm4.encryptKeyNoCache()
	sm4.keyCacheReady = true
}

func (sm4 *SM4Ctr) shallowCopyForWorkerLocked() *SM4Ctr {
	worker := &SM4Ctr{
		RtBCipher: &RtBCipher{
			params:         sm4.params,
			totalLevel:     sm4.totalLevel,
			remainingLevel: sm4.remainingLevel,
			symmetricKey:   sm4.symmetricKey,
		},
		iv:                  append([]byte(nil), sm4.iv...),
		blockSize:           sm4.blockSize,
		keySize:             sm4.keySize,
		rounds:              sm4.rounds,
		progress:            sm4.progress,
		logWriter:           sm4.logWriter,
		bitSbox:             sm4.bitSbox,
		sboxMonomialOrder:   sm4.sboxMonomialOrder,
		sboxSparseTerms:     sm4.sboxSparseTerms,
		sboxMonomialCoeff:   sm4.sboxMonomialCoeff,
		sboxConstBits:       sm4.sboxConstBits,
		allZeroIn:           sm4.allZeroIn,
		rkEncrypted:         sm4.rkEncrypted,
		keyCacheReady:       true,
		bootstrapWorkers:    sm4.bootstrapWorkers,
		sboxWorkers:         sm4.sboxWorkers,
		legacyTwoBootRounds: sm4.legacyTwoBootRounds,
	}

	if sm4.Evaluator != nil {
		worker.RtBCipher.Evaluator = sm4.Evaluator.ShallowCopy()
	}
	if sm4.encoder != nil {
		worker.RtBCipher.encoder = sm4.encoder.ShallowCopy()
	}
	if sm4.encryptor != nil {
		worker.RtBCipher.encryptor = sm4.encryptor.ShallowCopy()
	}
	if sm4.decryptor != nil {
		worker.RtBCipher.decryptor = sm4.decryptor.ShallowCopy()
	}

	return worker
}

// ShallowCopy returns a worker-local SM4Ctr that can be used concurrently with the original instance.
// It shares immutable lookup tables and encrypted round-key cache, while allocating fresh runtime helpers.
func (sm4 *SM4Ctr) ShallowCopy() *SM4Ctr {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	sm4.ensureEncryptedKeySchedule()
	return sm4.shallowCopyForWorkerLocked()
}

func (sm4 *SM4Ctr) prepareHEDecryptWorker(ciphertexts []uint8, bits int) (worker *SM4Ctr, useCipherXOR bool, effectiveBits int, numBlock int, keyScheduleDur time.Duration, err error) {
	sm4.instanceMu.Lock()
	defer sm4.instanceMu.Unlock()

	useCipherXOR = !sm4.allZeroIn && len(ciphertexts) > 0
	effectiveBits = bits
	if useCipherXOR && effectiveBits <= 0 {
		effectiveBits = len(ciphertexts) * 8
	}
	if sm4.allZeroIn {
		effectiveBits = sm4.params.MaxSlots() * sm4.blockSize
	}
	numBlock = int(math.Ceil(float64(effectiveBits) / float64(sm4.blockSize)))
	if numBlock > sm4.params.MaxSlots() {
		err = fmt.Errorf("SM4 HEDecrypt: numBlock=%d exceeds max slots=%d", numBlock, sm4.params.MaxSlots())
		return
	}

	startKeySchedule := time.Now()
	sm4.ensureEncryptedKeySchedule()
	keyScheduleDur = time.Since(startKeySchedule)
	worker = sm4.shallowCopyForWorkerLocked()
	return
}

func (sm4 *SM4Ctr) bootstrapBitsCmplxThenDivide(cts []*rlwe.Ciphertext, roundNo int, stage string) {
	if len(cts) == 0 {
		return
	}
	if len(cts)%2 != 0 {
		panic(fmt.Sprintf("SM4 RoundFunction(round=%d): %s requires even number of ciphertexts, got %d", roundNo, stage, len(cts)))
	}

	sm4.bootstrapBitsPair(cts, roundNo, stage)
}

func (sm4 *SM4Ctr) bootstrapBitsCmplxThenDivideLazyMod2(cts []*rlwe.Ciphertext, roundNo int, stage string) error {
	if len(cts) == 0 {
		return nil
	}
	if len(cts)%2 != 0 {
		return fmt.Errorf("SM4 RoundFunction(round=%d): %s requires even number of ciphertexts, got %d", roundNo, stage, len(cts))
	}
	if !sm4.useLazyMod2() {
		return fmt.Errorf("lazy-mod2 unsupported for short parameters (logN=%d)", sm4.params.LogN())
	}
	return sm4.bootstrapBitsPairLazyMod2(cts, roundNo, stage)
}

type sm4BootstrapPairFunc func(eval *bootstrapping.Evaluator, cts []*rlwe.Ciphertext, i, half, roundNo int, stage string) (*rlwe.Ciphertext, *rlwe.Ciphertext, error)

func (sm4 *SM4Ctr) bootstrapBitsPairWith(cts []*rlwe.Ciphertext, roundNo int, stage string, pairFn sm4BootstrapPairFunc) error {
	half := len(cts) / 2
	workers := sm4.bootstrapWorkerCount(half)
	evals := sm4.ensureEvalPool(&sm4.bootstrapEvalPool, workers)
	if workers == 1 {
		eval := evals[0]
		for i := 0; i < half; i++ {
			out0, out1, err := pairFn(eval, cts, i, half, roundNo, stage)
			if err != nil {
				return err
			}
			cts[i] = out0
			cts[half+i] = out1
		}
		return nil
	}

	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	var idx int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		eval := evals[w]
		go func(eval *bootstrapping.Evaluator) {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&idx, 1) - 1)
				if i >= half {
					return
				}
				out0, out1, err := pairFn(eval, cts, i, half, roundNo, stage)
				if err != nil {
					once.Do(func() {
						firstErr = err
					})
					continue
				}
				cts[i] = out0
				cts[half+i] = out1
			}
		}(eval)
	}
	wg.Wait()

	return firstErr
}

func (sm4 *SM4Ctr) bootstrapBitsPair(cts []*rlwe.Ciphertext, roundNo int, stage string) {
	if err := sm4.bootstrapBitsPairWith(cts, roundNo, stage, sm4.bootstrapPairAt); err != nil {
		panic(err)
	}
}

func (sm4 *SM4Ctr) bootstrapPairAt(eval *bootstrapping.Evaluator, cts []*rlwe.Ciphertext, i, half, roundNo int, stage string) (*rlwe.Ciphertext, *rlwe.Ciphertext, error) {
	out0, out1, err := eval.BootstrapCmplxThenDivide(cts[i], cts[half+i])
	if err != nil {
		return nil, nil, fmt.Errorf("SM4 RoundFunction(round=%d): %s bootstrap pair[%d,%d] failed: %w", roundNo, stage, i, half+i, err)
	}
	CleanReal(eval, out0)
	CleanReal(eval, out1)
	return out0, out1, nil
}

func (sm4 *SM4Ctr) bootstrapPairAtLazyMod2(eval *bootstrapping.Evaluator, cts []*rlwe.Ciphertext, i, half, roundNo int, stage string) (*rlwe.Ciphertext, *rlwe.Ciphertext, error) {
	out0, out1, err := eval.BootstrapCmplxThenDivideLazyMod2(cts[i], cts[half+i])
	if err != nil {
		return nil, nil, fmt.Errorf("SM4 RoundFunction(round=%d): %s lazy bootstrap pair[%d,%d] failed: %w", roundNo, stage, i, half+i, err)
	}
	// BootstrapCmplxThenDivideLazyMod2 already maps parity back to a bit with squareToBit.
	// Skipping CleanReal avoids two extra MulRelin/Rescale pairs per bit.
	return out0, out1, nil
}

func (sm4 *SM4Ctr) bootstrapBitsPairLazyMod2(cts []*rlwe.Ciphertext, roundNo int, stage string) error {
	return sm4.bootstrapBitsPairWith(cts, roundNo, stage, sm4.bootstrapPairAtLazyMod2)
}

// 同态解密：对 counter 做 SM4 加密，返回请求范围内需要读取的 bit-sliced 输出。
// 每次调用都会基于当前配置生成一个 worker-local SM4Ctr 运行态，因此同一模板实例可被并发复用。
func (sm4 *SM4Ctr) HEDecrypt(ciphertexts []uint8, bits int) ([]*rlwe.Ciphertext, error) {
	return sm4.heDecryptWithIV(ciphertexts, bits, nil)
}

// HEDecryptWithIV is equivalent to HEDecrypt but uses iv for this invocation.
// The IV is applied to the worker-local runtime copy, keeping the reusable
// template safe for concurrent callers.
func (sm4 *SM4Ctr) HEDecryptWithIV(ciphertexts []uint8, bits int, iv []byte) ([]*rlwe.Ciphertext, error) {
	if len(iv) != sm4.blockSize/8 {
		return nil, fmt.Errorf("SM4 HEDecryptWithIV: iv must be %d bytes, got %d", sm4.blockSize/8, len(iv))
	}
	return sm4.heDecryptWithIV(ciphertexts, bits, iv)
}

func (sm4 *SM4Ctr) heDecryptWithIV(ciphertexts []uint8, bits int, iv []byte) ([]*rlwe.Ciphertext, error) {
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	worker, useCipherXOR, effectiveBits, numBlock, keyScheduleDur, err := sm4.prepareHEDecryptWorker(ciphertexts, bits)
	if err != nil {
		return nil, err
	}
	if iv != nil {
		worker.iv = append(worker.iv[:0], iv...)
	}

	return worker.heDecryptPrepared(ciphertexts, effectiveBits, useCipherXOR, numBlock, keyScheduleDur, memStart)
}

func (sm4 *SM4Ctr) heDecryptPrepared(ciphertexts []uint8, bits int, useCipherXOR bool, numBlock int, keyScheduleDur time.Duration, memStart runtime.MemStats) ([]*rlwe.Ciphertext, error) {
	sm4.logHEDecryptMode(useCipherXOR, bits, numBlock)

	iv := NewBitSet(sm4.blockSize)
	if len(sm4.iv) != sm4.blockSize/8 {
		panic(fmt.Sprintf("SM4 HEDecrypt: iv must be %d bytes, got %d", sm4.blockSize/8, len(sm4.iv)))
	}
	iv.SetBlockBytesBE(sm4.iv)

	// 1) key schedule (32 round keys)
	sm4.logHEDecryptStage("key schedule encrypted", keyScheduleDur)

	// 2) encrypt input counters -> sm4.inputEncrypted
	startEncode := time.Now()
	sm4.EncryptInput(iv, numBlock)
	if useCipherXOR {
		sm4.EncodeCiphertext(ciphertexts, numBlock)
	}
	encodeDur := time.Since(startEncode)
	sm4.logHEDecryptStage("input/ciphertext encoded", encodeDur)

	// 3) Drop levels：给 32 轮留一点余量
	startDrop := time.Now()
	keep := 0
	if keep < 1 {
		keep = 1
	}
	for i := 0; i < len(sm4.inputEncrypted); i++ {
		ct := sm4.inputEncrypted[i]
		target := sm4.remainingLevel - keep
		if target < 0 {
			target = 0
		}
		if ct.Level() > target {
			sm4.Evaluator.DropLevel(ct, ct.Level()-target)
		}
	}
	dropDur := time.Since(startDrop)
	sm4.logHEDecryptStage("level alignment done", dropDur)

	startSM4 := time.Now()
	roundAgg := roundTiming{}

	// state layout: [0:32]=X0, [32:64]=X1, [64:96]=X2, [96:128]=X3
	// LSB-first：bit i 就是 word 的第 i 位（bit0=LSB）
	state := sm4.InitStateWords(sm4.inputEncrypted) // len=128

	for i := 0; i < 32; i++ {
		roundNo := i + 1
		roundStart := time.Now()
		sm4.logRoundStart(roundNo)
		rt := sm4.RoundFunction(state, sm4.rkEncrypted[i], roundNo) // rkEncrypted[i] len=32
		roundAgg.add(rt)
		minLvl, maxLvl := levelRange(state[96:128]) // x4 in current state
		sm4.logRoundDone(roundNo, time.Since(roundStart), minLvl, maxLvl, rt)
	}
	roundsDur := time.Since(startSM4)

	startFinalize := time.Now()
	out := sm4.Finalize(state) // (X35,X34,X33,X32)
	outputBits := sm4.finalOutputBitCount(bits, numBlock)
	finalizeDur := time.Since(startFinalize)

	startFinalBoot := time.Now()
	if sm4.useOneBootRounds() {
		finalBootBits := evenBootstrapBitCount(outputBits, len(out))
		if finalBootBits > 0 {
			if err := sm4.bootstrapBitsCmplxThenDivideLazyMod2(out[:finalBootBits], sm4.rounds+1, "final"); err != nil {
				panic(err)
			}
			finalEval := sm4.Evaluator.ShallowCopy()
			sm4.dropBitsLevelInPlace(finalEval, out[:finalBootBits], 3)
		}
	}
	out = out[:outputBits]
	finalBootDur := time.Since(startFinalBoot)

	sm4RuntimeDur := time.Since(startSM4)
	sm4.logSM4Runtime(sm4RuntimeDur)

	// CTR plaintext = ciphertext XOR keystream.
	startOutXOR := time.Now()
	if useCipherXOR {
		eval := sm4.Evaluator.ShallowCopy()
		for i := 0; i < len(out); i++ {
			sum := FXORNew(eval, out[i], sm4.encodeCipher[i])
			out[i] = Mod2Reduce2New(eval, sum)
		}
	}
	outXORDur := time.Since(startOutXOR)

	total := keyScheduleDur + encodeDur + dropDur + roundsDur + finalizeDur + finalBootDur + outXORDur
	sm4.logHEDecryptProfile(total, keyScheduleDur, encodeDur, dropDur, roundsDur, finalizeDur, finalBootDur, outXORDur, roundAgg)

	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)
	sm4.logHEDecryptMetrics(sm4HEDecryptMetrics{
		bits:       bits,
		bytes:      (bits + 7) / 8,
		blocks:     numBlock,
		total:      total,
		sm4Runtime: sm4RuntimeDur,
		rounds:     roundsDur,
		memStart:   memStart,
		memEnd:     memEnd,
		cts:        sm4.ciphertextInventory(state, out),
	})

	return out, nil
}

// InitStateWords: 直接取前 128 个 bit（bit-sliced）作为初始状态
func (sm4 *SM4Ctr) InitStateWords(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(in) < 128 {
		panic("InitStateWords: need at least 128 ciphertext bits")
	}
	out := make([]*rlwe.Ciphertext, 128)
	copy(out, in[:128])
	return out
}

func checkWordPair(a, b []*rlwe.Ciphertext, name string) {
	if len(a) != 32 || len(b) != 32 {
		panic(name + ": inputs must be len=32")
	}
}

func checkWord(in []*rlwe.Ciphertext, name string) {
	if len(in) != 32 {
		panic(name + ": input must be len=32")
	}
}

func countCiphertexts(cts []*rlwe.Ciphertext) int {
	count := 0
	for _, ct := range cts {
		if ct != nil {
			count++
		}
	}
	return count
}

func countNestedCiphertexts(cts [][]*rlwe.Ciphertext) int {
	count := 0
	for _, row := range cts {
		count += countCiphertexts(row)
	}
	return count
}

func collectCiphertexts(seen map[*rlwe.Ciphertext]struct{}, cts []*rlwe.Ciphertext) {
	for _, ct := range cts {
		if ct != nil {
			seen[ct] = struct{}{}
		}
	}
}

func collectNestedCiphertexts(seen map[*rlwe.Ciphertext]struct{}, cts [][]*rlwe.Ciphertext) {
	for _, row := range cts {
		collectCiphertexts(seen, row)
	}
}

func (sm4 *SM4Ctr) ciphertextInventory(state, out []*rlwe.Ciphertext) sm4CiphertextInventory {
	inv := sm4CiphertextInventory{
		roundKeys:         countNestedCiphertexts(sm4.rkEncrypted),
		inputCounters:     countCiphertexts(sm4.inputEncrypted),
		encodedCiphertext: countCiphertexts(sm4.encodeCipher),
		state:             countCiphertexts(state),
		output:            countCiphertexts(out),
	}
	inv.logical = inv.roundKeys + inv.inputCounters + inv.encodedCiphertext + inv.state + inv.output

	seen := make(map[*rlwe.Ciphertext]struct{}, inv.logical)
	collectNestedCiphertexts(seen, sm4.rkEncrypted)
	collectCiphertexts(seen, sm4.inputEncrypted)
	collectCiphertexts(seen, sm4.encodeCipher)
	collectCiphertexts(seen, state)
	collectCiphertexts(seen, out)
	inv.unique = len(seen)
	return inv
}

func (sm4 *SM4Ctr) dropBitsLevelInPlace(eval *bootstrapping.Evaluator, in []*rlwe.Ciphertext, levels int) {
	if levels <= 0 {
		return
	}
	for i := range in {
		if in[i].Level() >= levels {
			eval.DropLevel(in[i], levels)
		}
	}
}

func (sm4 *SM4Ctr) dropWordLevelInPlace(eval *bootstrapping.Evaluator, in []*rlwe.Ciphertext, levels int) {
	checkWord(in, "dropWordLevelInPlace")
	sm4.dropBitsLevelInPlace(eval, in, levels)
}

func (sm4 *SM4Ctr) wordXORNewWithEval(eval *bootstrapping.Evaluator, a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	checkWordPair(a, b, "wordXORNewWithEval")
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = XORNew(eval, a[i], b[i])
	}
	return out
}

func (sm4 *SM4Ctr) wordFXORNewWithEval(eval *bootstrapping.Evaluator, a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	checkWordPair(a, b, "wordFXORNewWithEval")
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = FXORNew(eval, a[i], b[i])
	}
	return out
}

func (sm4 *SM4Ctr) wordMod2Reduce2NewWithEval(eval *bootstrapping.Evaluator, in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	checkWord(in, "wordMod2Reduce2NewWithEval")
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = Mod2Reduce2New(eval, in[i])
	}
	return out
}

func (sm4 *SM4Ctr) wordMod2Reduce4NewWithEval(eval *bootstrapping.Evaluator, in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	checkWord(in, "wordMod2Reduce4NewWithEval")
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = Mod2Reduce4New(eval, in[i])
	}
	return out
}

func (sm4 *SM4Ctr) wordMod2Reduce6NewWithEval(eval *bootstrapping.Evaluator, in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	checkWord(in, "wordMod2Reduce6NewWithEval")
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = Mod2Reduce6New(eval, in[i])
	}
	return out
}

// WordXORNew: 32-bit word XOR（bit-sliced），返回新 slice
func (sm4 *SM4Ctr) WordXORNew(a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	eval := sm4.Evaluator.ShallowCopy()
	return sm4.wordXORNewWithEval(eval, a, b)
}

// WordFXORNew performs additive aggregation (x+y) per bit.
// Cleanup to boolean values is deferred to the bootstrapping boundary.
func (sm4 *SM4Ctr) WordFXORNew(a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	eval := sm4.Evaluator.ShallowCopy()
	return sm4.wordFXORNewWithEval(eval, a, b)
}

func (sm4 *SM4Ctr) WordMod2Reduce2New(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	eval := sm4.Evaluator.ShallowCopy()
	return sm4.wordMod2Reduce2NewWithEval(eval, in)
}

func (sm4 *SM4Ctr) WordMod2Reduce4New(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	eval := sm4.Evaluator.ShallowCopy()
	return sm4.wordMod2Reduce4NewWithEval(eval, in)
}

func (sm4 *SM4Ctr) WordMod2Reduce6New(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	eval := sm4.Evaluator.ShallowCopy()
	return sm4.wordMod2Reduce6NewWithEval(eval, in)
}

// rotlWordBits: 32-bit word 内循环左移（LSB-first 约定）
// 约定：in[j] 表示 word 的 bit j（bit0=LSB, bit31=MSB）
// ROTL(k): out[j] = in[(j-k)&31]
func rotlWordBits(in []*rlwe.Ciphertext, k int) []*rlwe.Ciphertext {
	if len(in) != 32 {
		panic("rotlWordBits: input must be len=32")
	}
	k &= 31
	out := make([]*rlwe.Ciphertext, 32)
	for j := 0; j < 32; j++ {
		out[j] = in[(j-k)&31]
	}
	return out
}

// RoundFunction: SM4 word-based round
// x4 = x0 XOR L( Sbox( x1 XOR x2 XOR x3 XOR rk ) )
// L(b)=b^(b<<<2)^(b<<<10)^(b<<<18)^(b<<<24)
// state layout: [0:32]=x0, [32:64]=x1, [64:96]=x2, [96:128]=x3
func (sm4 *SM4Ctr) RoundFunction(state []*rlwe.Ciphertext, rk []*rlwe.Ciphertext, roundNo int) (rt roundTiming) {
	if len(state) != 128 {
		panic("SM4 RoundFunction: state must be len=128 (4x32 bits)")
	}
	if len(rk) != 32 {
		panic("SM4 RoundFunction: rk must be len=32 (32-bit word bit-sliced)")
	}

	x0 := state[0:32]
	x1 := state[32:64]
	x2 := state[64:96]
	x3 := state[96:128]
	arithEval := sm4.Evaluator.ShallowCopy()
	if roundNo == 1 {
		switch {
		case sm4.useOneBootRounds():
			sm4.logf(true, "[SM4][Round %02d] mod2 strategy=lazy schedule=one-boot fusion=%s tmpBound=0..%d finalBound=0..%d (LogN=%d)\n",
				roundNo, sm4SboxLFusedLazyMode, sm4OneBootTmpBound, sm4OneBootFinalBound, sm4.params.LogN())
		case sm4.useLazyMod2():
			sm4.logf(true, "[SM4][Round %02d] mod2 strategy=lazy schedule=legacy-two-boot fusion=%s (LogN=%d)\n",
				roundNo, sm4SboxLFusedLazyMode, sm4.params.LogN())
		default:
			sm4.logf(true, "[SM4][Round %02d] mod2 strategy=eager schedule=legacy-two-boot fusion=eager-clean (LogN=%d)\n", roundNo, sm4.params.LogN())
		}
	}

	// tmp = x1 + x2 + x3 + rk (additive path over Z)
	stageStart := time.Now()
	u0 := sm4.wordFXORNewWithEval(arithEval, x1, x2)
	u1 := sm4.wordFXORNewWithEval(arithEval, x3, rk)
	tmp := sm4.wordFXORNewWithEval(arithEval, u0, u1)
	rt.tmpXOR = time.Since(stageStart)

	// === Bootstrap BEFORE SBox: cleanup + replenish levels ===
	stageStart = time.Now()
	if sm4.useLazyMod2() {
		if err := sm4.bootstrapBitsCmplxThenDivideLazyMod2(tmp, roundNo, "tmp"); err != nil {
			panic(err)
		}
		sm4.dropWordLevelInPlace(arithEval, tmp, 3)
		// LazyMod2 bootstrap already evaluates parity; DropLevel keeps the old depth budget
		// without paying for an extra Mod2Reduce2 polynomial.
	} else {
		tmp = sm4.wordMod2Reduce4NewWithEval(arithEval, tmp)
		sm4.bootstrapBitsCmplxThenDivide(tmp, roundNo, "tmp")
	}
	rt.tmpBootstrap = time.Since(stageStart)

	// === SBox: 4 bytes ===
	stageStart = time.Now()
	sboxStats, err := sm4.applySboxStage(tmp)
	if err != nil {
		panic(err)
	}
	sm4.logSboxOpStats(roundNo, true, sboxStats, 4*sm4SboxEagerRelinPerByte)
	rt.sbox = time.Since(stageStart)

	// The lazy S-box returns integer parity carriers, not freshly reduced bits.
	// SM4's L-layer is linear, so we intentionally fuse those carriers directly
	// into the ROTL/XOR aggregation and defer LazyMod2 to the next boundary.
	// === L linear transform with additive path over Z ===
	stageStart = time.Now()
	r2 := rotlWordBits(tmp, 2)
	r10 := rotlWordBits(tmp, 10)
	r18 := rotlWordBits(tmp, 18)
	r24 := rotlWordBits(tmp, 24)

	v0 := sm4.wordFXORNewWithEval(arithEval, tmp, r2)
	v1 := sm4.wordFXORNewWithEval(arithEval, r10, r18)
	v2 := sm4.wordFXORNewWithEval(arithEval, v0, v1)
	t := sm4.wordFXORNewWithEval(arithEval, v2, r24)
	rt.linear = time.Since(stageStart)

	// x4 = x0 + t, then single pull-back at bootstrap boundary.
	stageStart = time.Now()
	x4 := sm4.wordFXORNewWithEval(arithEval, x0, t)
	if !sm4.useLazyMod2() {
		x4 = sm4.wordMod2Reduce6NewWithEval(arithEval, x4)
	}

	minBootstrapLevel := sm4.SlotsToCoeffsParameters.LevelQ
	for i := 0; i < 32; i++ {
		if x4[i].Level() < minBootstrapLevel {
			panic(fmt.Sprintf("SM4 RoundFunction(round=%d): x4[%d] level=%d < bootstrap minimum level=%d", roundNo, i, x4[i].Level(), minBootstrapLevel))
		}
	}
	rt.x4XORAndCheck = time.Since(stageStart)

	// === Optional x4 bootstrap boundary ===
	stageStart = time.Now()
	if sm4.useLazyMod2() {
		if sm4.legacyTwoBootRounds {
			if err := sm4.bootstrapBitsCmplxThenDivideLazyMod2(x4, roundNo, "x4"); err != nil {
				panic(err)
			}
			sm4.dropWordLevelInPlace(arithEval, x4, 3)
		}
		// In the default one-boot schedule, x4 stays as an integer parity carrier and is
		// reduced by the next round's tmp bootstrap or by the final 128-bit cleanup.
	} else {
		sm4.bootstrapBitsCmplxThenDivide(x4, roundNo, "x4")
	}
	rt.x4BootAndSplit = time.Since(stageStart)

	// shift words
	stageStart = time.Now()
	copy(state[0:32], x1)
	copy(state[32:64], x2)
	copy(state[64:96], x3)
	copy(state[96:128], x4)
	rt.shift = time.Since(stageStart)
	return
}

// Finalize: 输出反序 (X35,X34,X33,X32)
func (sm4 *SM4Ctr) Finalize(state []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(state) != 128 {
		panic("Finalize: state must be len=128")
	}
	out := make([]*rlwe.Ciphertext, 128)
	copy(out[0:32], state[96:128]) // X35
	copy(out[32:64], state[64:96]) // X34
	copy(out[64:96], state[32:64]) // X33
	copy(out[96:128], state[0:32]) // X32
	return out
}

// Deprecated: EncryptKey is kept for compatibility. Use WarmupKeySchedule instead.
func (sm4 *SM4Ctr) EncryptKey() {
	sm4.WarmupKeySchedule()
}

func (sm4 *SM4Ctr) encryptKeyNoCache() {
	if sm4.encoder == nil || sm4.encryptor == nil {
		panic("encoder or encryptor is not initialized")
	}
	sm4.ensureScratch()

	sm4.rounds = 32

	// Key schedule in plaintext -> rkPlain[32], then encrypt -> rkEncrypted
	rkPlain := sm4.sm4KeySchedulePlain(sm4.symmetricKey) // [32]uint32

	sm4.rkEncrypted = make([][]*rlwe.Ciphertext, 32)
	for r := 0; r < 32; r++ {
		sm4.rkEncrypted[r] = make([]*rlwe.Ciphertext, 32)

		for i := 0; i < 32; i++ {
			// LSB-first per word：bit i = (rk >> i) & 1
			bit := (rkPlain[r] >> uint(i)) & 1

			fill := float64(bit)
			for j := range sm4.slotFloatScratch {
				sm4.slotFloatScratch[j] = fill
			}

			pt := ckks.NewPlaintext(sm4.params, sm4.remainingLevel)
			sm4.encoder.Encode(sm4.slotFloatScratch, pt)
			if pt == nil {
				panic("rk pt is nil after encoding")
			}

			ct, err := sm4.encryptor.EncryptNew(pt)
			if err != nil {
				panic(err)
			}
			if ct == nil {
				panic("rk ct is nil after encryption")
			}

			sm4.rkEncrypted[r][i] = ct
		}
	}
}

// EncryptInput: 把 counter blocks 做 bit-sliced SIMD 编码并加密到 inputEncrypted
func (sm4 *SM4Ctr) EncryptInput(iv *BitSet, numBlock int) {
	sm4.ensureScratch()
	inputData := sm4.inputBitScratch

	for i := range inputData {
		if sm4.allZeroIn {
			inputData[i].Clear()
		} else {
			if i < numBlock {
				// ctr(iv, i): first block uses counter=iv, then 128-bit big-endian increment.
				counter := ctr(iv, uint64(i))
				copy(inputData[i].bits, counter.bits)
			} else {
				inputData[i].Clear()
			}
		}
	}

	if len(sm4.inputEncrypted) != sm4.blockSize {
		sm4.inputEncrypted = make([]*rlwe.Ciphertext, sm4.blockSize)
	}

	for i := 0; i < sm4.blockSize; i++ {
		for j := 0; j < sm4.params.MaxSlots(); j++ {
			sm4.slotCmplxScratch[j] = complex(float64(inputData[j].bits[i]), 0)
		}

		pt := ckks.NewPlaintext(*sm4.GetParameters(), sm4.remainingLevel)
		sm4.encoder.Encode(sm4.slotCmplxScratch, pt)

		ct := sm4.inputEncrypted[i]
		if ct == nil || ct.Level() != sm4.remainingLevel {
			ct = ckks.NewCiphertext(*sm4.GetParameters(), 1, sm4.remainingLevel)
			sm4.inputEncrypted[i] = ct
		}
		if err := sm4.encryptor.Encrypt(pt, ct); err != nil {
			panic(err)
		}
	}

	if sm4.inputEncrypted[0] == nil {
		panic("input is not stored in sm4Struct")
	}
}

// EncodeCiphertext: bit-sliced 的 SIMD 批处理密文（修复 append bug）
func (sm4 *SM4Ctr) EncodeCiphertext(ciphertexts []uint8, numBlock int) {
	sm4.ensureScratch()
	if len(sm4.encodeCipher) != sm4.blockSize {
		sm4.encodeCipher = make([]*rlwe.Ciphertext, sm4.blockSize)
	}

	if numBlock < sm4.params.MaxSlots() {
		sm4.logCipherPackFill()
	}

	encryptedData := sm4.cipherBitScratch

	for i := range encryptedData {
		if i < numBlock {
			encryptedData[i].Clear()
			if !sm4.allZeroIn {
				var block [16]byte
				blockOffset := i * len(block)
				if blockOffset < len(ciphertexts) {
					blockEnd := blockOffset + len(block)
					if blockEnd > len(ciphertexts) {
						blockEnd = len(ciphertexts)
					}
					copy(block[:], ciphertexts[blockOffset:blockEnd])
				}
				encryptedData[i].SetBlockBytesBE(block[:])
			}
		} else {
			encryptedData[i].Clear()
		}
	}

	for i := 0; i < sm4.blockSize; i++ {
		for j := 0; j < sm4.params.MaxSlots(); j++ {
			sm4.slotCmplxScratch[j] = complex(float64(encryptedData[j].bits[i]), 0.0)
		}

		pt := ckks.NewPlaintext(*sm4.GetParameters(), sm4.remainingLevel)
		sm4.encoder.Encode(sm4.slotCmplxScratch, pt)

		ct := sm4.encodeCipher[i]
		if ct == nil || ct.Level() != sm4.remainingLevel {
			ct = ckks.NewCiphertext(*sm4.GetParameters(), 1, sm4.remainingLevel)
			sm4.encodeCipher[i] = ct
		}
		if err := sm4.encryptor.Encrypt(pt, ct); err != nil {
			panic(err)
		}
	}
}

// 系数 × 单项式，再求和，ANF 处理（稀疏项版）
func (sm4 *SM4Ctr) coefficientMultMonomial(eval *bootstrapping.Evaluator, mon []*rlwe.Ciphertext, terms []sm4SboxTerm, constBit int) (ctOut *rlwe.Ciphertext) {
	if len(mon) != len(sm4.sboxMonomialOrder) {
		panic("monomial size must equal to sbox_monomial_order!")
	}
	ctOut = mon[0].CopyNew()
	eval.Mul(ctOut, 0, ctOut)

	for i := range terms {
		term := terms[i]
		src := mon[term.monomialIdx]
		switch term.coeff {
		case 1:
			eval.Add(ctOut, src, ctOut)
		case -1:
			eval.Sub(ctOut, src, ctOut)
		default:
			if err := eval.MulThenAdd(src, complex(float64(term.coeff), 0), ctOut); err != nil {
				// Fallback path for uncommon scale mismatch cases.
				tmp := src.CopyNew()
				eval.Mul(tmp, term.coeff, tmp)
				eval.Add(ctOut, tmp, ctOut)
			}
		}
	}

	if constBit != 0 {
		eval.Add(ctOut, constBit, ctOut)
	}
	return
}

// ===== SM4 Key Schedule (plaintext) =====

var sm4FK = [4]uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

var sm4CK = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

// loadU32BE interprets b as a standard big-endian 32-bit word.
// Internally, words are still bit-sliced LSB-first within each 32-bit lane.
func loadU32BE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// τ applies the S-box to each byte of a 32-bit word.
// The word value follows standard SM4 big-endian semantics; the bit-sliced lanes remain LSB-first.
func (sm4 *SM4Ctr) tau(a uint32) uint32 {
	b0 := uint32(SM4Sbox[a&0xff])
	b1 := uint32(SM4Sbox[(a>>8)&0xff])
	b2 := uint32(SM4Sbox[(a>>16)&0xff])
	b3 := uint32(SM4Sbox[(a>>24)&0xff])
	return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

func rotl32(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

// L'：b ^ (b<<<13) ^ (b<<<23)
func (sm4 *SM4Ctr) lPrime(b uint32) uint32 {
	return b ^ rotl32(b, 13) ^ rotl32(b, 23)
}

// 生成 32 个 round key（明文）
func (sm4 *SM4Ctr) sm4KeySchedulePlain(key []byte) [32]uint32 {
	if len(key) != 16 {
		panic("sm4KeySchedulePlain: key must be 16 bytes")
	}

	mk0 := loadU32BE(key[0:4])
	mk1 := loadU32BE(key[4:8])
	mk2 := loadU32BE(key[8:12])
	mk3 := loadU32BE(key[12:16])

	K := make([]uint32, 36)
	K[0] = mk0 ^ sm4FK[0]
	K[1] = mk1 ^ sm4FK[1]
	K[2] = mk2 ^ sm4FK[2]
	K[3] = mk3 ^ sm4FK[3]

	var rk [32]uint32
	for i := 0; i < 32; i++ {
		t := K[i+1] ^ K[i+2] ^ K[i+3] ^ sm4CK[i]
		t = sm4.tau(t)
		t = sm4.lPrime(t)
		K[i+4] = K[i] ^ t
		rk[i] = K[i+4]
	}
	return rk
}
