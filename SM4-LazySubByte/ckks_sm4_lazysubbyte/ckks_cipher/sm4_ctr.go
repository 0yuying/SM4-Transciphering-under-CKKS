package ckks_cipher

import (
	"fmt"
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

	bitSbox           []*BitSet
	sboxMonomialOrder []*BitSet
	sboxSparseTerms   [8][]sm4SboxTerm
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
	bootstrapWorkers int
	sboxWorkers      int
	bootMode         string
	bootFallback     bool
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

type sm4SboxTerm struct {
	monomialIdx int
	coeff       int
}

const (
	sm4BootModePair = "pair"
	sm4BootModeMany = "many"
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
		allZeroIn: true, // debug mode
		progress:  true, // print progress by default to observe long HE execution
		bootMode:  sm4BootModePair,
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
		}
		sm4.sboxSparseTerms[bit] = terms
	}
}

// SetAllZeroInput toggles debug input mode.
// true  -> every input block is zero (debug)
// false -> use CTR(iv, blockIndex) inputs
func (sm4 *SM4Ctr) SetAllZeroInput(allZero bool) {
	sm4.allZeroIn = allZero
}

// SetProgressLog toggles progress logs for long-running HE evaluation.
func (sm4 *SM4Ctr) SetProgressLog(enabled bool) {
	sm4.progress = enabled
}

// SetWorkerConfig sets worker counts used by bootstrap and S-box stages.
// value <= 0 means "auto" (runtime.GOMAXPROCS).
func (sm4 *SM4Ctr) SetWorkerConfig(bootstrapWorkers, sboxWorkers int) {
	sm4.scratchMu.Lock()
	defer sm4.scratchMu.Unlock()

	sm4.bootstrapWorkers = bootstrapWorkers
	sm4.sboxWorkers = sboxWorkers
	sm4.bootstrapEvalPool = nil
	sm4.sboxEvalPool = nil
}

// SetBootMode switches bootstrap strategy: "pair" or "many".
func (sm4 *SM4Ctr) SetBootMode(mode string) error {
	switch mode {
	case sm4BootModePair, sm4BootModeMany:
		sm4.bootMode = mode
		sm4.bootFallback = false
		return nil
	default:
		return fmt.Errorf("invalid boot mode %q: expected %q or %q", mode, sm4BootModePair, sm4BootModeMany)
	}
}

// WarmupKeySchedule precomputes and caches encrypted round keys.
func (sm4 *SM4Ctr) WarmupKeySchedule() {
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

func (sm4 *SM4Ctr) bootstrapBitsCmplxThenDivide(cts []*rlwe.Ciphertext, roundNo int, stage string) {
	if len(cts) == 0 {
		return
	}
	if len(cts)%2 != 0 {
		panic(fmt.Sprintf("SM4 RoundFunction(round=%d): %s requires even number of ciphertexts, got %d", roundNo, stage, len(cts)))
	}

	switch sm4.bootMode {
	case sm4BootModePair:
		sm4.bootstrapBitsPair(cts, roundNo, stage)
	case sm4BootModeMany:
		if err := sm4.bootstrapBitsMany(cts); err != nil {
			if sm4.progress {
				fmt.Printf("[SM4][Round %02d] bootstrap-many fallback to pair at stage=%s: %v\n", roundNo, stage, err)
			}
			sm4.bootMode = sm4BootModePair
			sm4.bootFallback = true
			sm4.bootstrapBitsPair(cts, roundNo, stage)
		}
	default:
		panic(fmt.Sprintf("SM4 RoundFunction(round=%d): unknown boot mode %q", roundNo, sm4.bootMode))
	}
}

func (sm4 *SM4Ctr) bootstrapBitsPair(cts []*rlwe.Ciphertext, roundNo int, stage string) {
	half := len(cts) / 2
	workers := sm4.bootstrapWorkerCount(half)
	if workers == 1 {
		eval := sm4.Evaluator.ShallowCopy()
		for i := 0; i < half; i++ {
			var err error
			cts[i], cts[half+i], err = eval.BootstrapCmplxThenDivide(cts[i], cts[half+i])
			if err != nil {
				panic(fmt.Sprintf("SM4 RoundFunction(round=%d): %s bootstrap pair[%d,%d] failed: %v", roundNo, stage, i, half+i, err))
			}
			CleanReal(eval, cts[i])
			CleanReal(eval, cts[half+i])
		}
		return
	}

	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	var idx int64
	evals := sm4.ensureEvalPool(&sm4.bootstrapEvalPool, workers)
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
				out0, out1, err := eval.BootstrapCmplxThenDivide(cts[i], cts[half+i])
				if err != nil {
					once.Do(func() {
						firstErr = fmt.Errorf("SM4 RoundFunction(round=%d): %s bootstrap pair[%d,%d] failed: %w", roundNo, stage, i, half+i, err)
					})
					continue
				}
				CleanReal(eval, out0)
				CleanReal(eval, out1)
				cts[i] = out0
				cts[half+i] = out1
			}
		}(eval)
	}
	wg.Wait()

	if firstErr != nil {
		panic(firstErr)
	}
}

func (sm4 *SM4Ctr) bootstrapBitsMany(cts []*rlwe.Ciphertext) error {
	eval := sm4.Evaluator.ShallowCopy()
	in := make([]rlwe.Ciphertext, len(cts))
	for i := range cts {
		in[i] = *cts[i].CopyNew()
	}

	out, err := eval.BootstrapMany(in)
	if err != nil {
		return err
	}
	minLevel := sm4.SlotsToCoeffsParameters.LevelQ
	for i := range out {
		if out[i].Level() < minLevel {
			return fmt.Errorf("bootstrap-many produced low level ct[%d]=%d (< %d)", i, out[i].Level(), minLevel)
		}
		cts[i] = &out[i]
		// BootstrapMany already returns real ciphertexts for this path.
		// Additional clean-up costs levels and can underflow on short params.
	}
	return nil
}

// 同态解密：对 counter 做 SM4 加密，返回 keystream bits
func (sm4 *SM4Ctr) HEDecrypt(ciphertexts []uint8, bits int) []*rlwe.Ciphertext {
	useCipherXOR := !sm4.allZeroIn && len(ciphertexts) > 0
	if useCipherXOR && bits <= 0 {
		bits = len(ciphertexts) * 8
	}
	if sm4.allZeroIn {
		bits = sm4.params.MaxSlots() * sm4.blockSize
	}
	numBlock := int(math.Ceil(float64(bits) / float64(sm4.blockSize)))
	if sm4.progress {
		fmt.Printf("[SM4][HEDecrypt] mode(allZeroIn=%v, useCipherXOR=%v), bits=%d, numBlock=%d\n", sm4.allZeroIn, useCipherXOR, bits, numBlock)
	}

	iv := NewBitSet(sm4.blockSize)
	if len(sm4.iv) != sm4.blockSize/8 {
		panic(fmt.Sprintf("SM4 HEDecrypt: iv must be %d bytes, got %d", sm4.blockSize/8, len(sm4.iv)))
	}
	iv.SetBytesLE(sm4.iv)

	// 1) key schedule (32 round keys)
	startKeySchedule := time.Now()
	sm4.ensureEncryptedKeySchedule()
	keyScheduleDur := time.Since(startKeySchedule)
	if sm4.progress {
		fmt.Printf("[SM4][HEDecrypt] key schedule encrypted in %d ms\n", int(keyScheduleDur.Milliseconds()))
	}

	// 2) encrypt input counters -> sm4.inputEncrypted
	startEncode := time.Now()
	sm4.EncryptInput(iv, numBlock)
	if useCipherXOR {
		sm4.EncodeCiphertext(ciphertexts, numBlock)
	}
	encodeDur := time.Since(startEncode)
	if sm4.progress {
		fmt.Printf("[SM4][HEDecrypt] input/ciphertext encoded in %d ms\n", int(encodeDur.Milliseconds()))
	}

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
	if sm4.progress {
		fmt.Printf("[SM4][HEDecrypt] level alignment done in %d ms\n", int(dropDur.Milliseconds()))
	}

	startSM4 := time.Now()
	roundAgg := roundTiming{}

	// state layout: [0:32]=X0, [32:64]=X1, [64:96]=X2, [96:128]=X3
	// LSB-first：bit i 就是 word 的第 i 位（bit0=LSB）
	state := sm4.InitStateWords(sm4.inputEncrypted) // len=128

	for i := 0; i < 32; i++ {
		roundNo := i + 1
		roundStart := time.Now()
		if sm4.progress {
			fmt.Printf("[SM4][Round %02d] start\n", roundNo)
		}
		rt := sm4.RoundFunction(state, sm4.rkEncrypted[i], roundNo) // rkEncrypted[i] len=32
		roundAgg.add(rt)
		if sm4.progress {
			minLvl, maxLvl := levelRange(state[96:128]) // x4 in current state
			roundDur := time.Since(roundStart)
			fmt.Printf("[SM4][Round %02d] done in %d ms, x4 level range=[%d,%d] | tmpXor=%dms(%.1f%%) tmpBoot=%dms(%.1f%%) sbox=%dms(%.1f%%) L=%dms(%.1f%%) x4=%dms(%.1f%%) x4BootSplit=%dms(%.1f%%) shift=%dms(%.1f%%)\n",
				roundNo, int(roundDur.Milliseconds()), minLvl, maxLvl,
				int(rt.tmpXOR.Milliseconds()), pct(rt.tmpXOR, rt.total()),
				int(rt.tmpBootstrap.Milliseconds()), pct(rt.tmpBootstrap, rt.total()),
				int(rt.sbox.Milliseconds()), pct(rt.sbox, rt.total()),
				int(rt.linear.Milliseconds()), pct(rt.linear, rt.total()),
				int(rt.x4XORAndCheck.Milliseconds()), pct(rt.x4XORAndCheck, rt.total()),
				int(rt.x4BootAndSplit.Milliseconds()), pct(rt.x4BootAndSplit, rt.total()),
				int(rt.shift.Milliseconds()), pct(rt.shift, rt.total()))
		}
	}

	startFinalize := time.Now()
	out := sm4.Finalize(state) // (X35,X34,X33,X32)
	finalizeDur := time.Since(startFinalize)

	endSM4 := time.Now()
	d := endSM4.Sub(startSM4)
	fmt.Printf("SM4 Running %d s :: %d ms\n", int(d.Seconds()), int(d.Milliseconds())%1000)

	// CTR plaintext = ciphertext XOR keystream.
	startOutXOR := time.Now()
	if useCipherXOR {
		eval := sm4.Evaluator.ShallowCopy()
		for i := 0; i < 128; i++ {
			sum := FXORNew(eval, out[i], sm4.encodeCipher[i])
			out[i] = Mod2Reduce2New(eval, sum)
		}
	}
	outXORDur := time.Since(startOutXOR)

	if sm4.progress {
		total := keyScheduleDur + encodeDur + dropDur + d + finalizeDur + outXORDur
		fmt.Printf("[SM4][Profile] total=%d ms | key=%dms(%.1f%%) encode=%dms(%.1f%%) drop=%dms(%.1f%%) rounds=%dms(%.1f%%) finalize=%dms(%.1f%%) outXor=%dms(%.1f%%)\n",
			int(total.Milliseconds()),
			int(keyScheduleDur.Milliseconds()), pct(keyScheduleDur, total),
			int(encodeDur.Milliseconds()), pct(encodeDur, total),
			int(dropDur.Milliseconds()), pct(dropDur, total),
			int(d.Milliseconds()), pct(d, total),
			int(finalizeDur.Milliseconds()), pct(finalizeDur, total),
			int(outXORDur.Milliseconds()), pct(outXORDur, total))
		fmt.Printf("[SM4][Profile][RoundsSum] tmpXor=%dms(%.1f%%) tmpBoot=%dms(%.1f%%) sbox=%dms(%.1f%%) L=%dms(%.1f%%) x4=%dms(%.1f%%) x4BootSplit=%dms(%.1f%%) shift=%dms(%.1f%%)\n",
			int(roundAgg.tmpXOR.Milliseconds()), pct(roundAgg.tmpXOR, roundAgg.total()),
			int(roundAgg.tmpBootstrap.Milliseconds()), pct(roundAgg.tmpBootstrap, roundAgg.total()),
			int(roundAgg.sbox.Milliseconds()), pct(roundAgg.sbox, roundAgg.total()),
			int(roundAgg.linear.Milliseconds()), pct(roundAgg.linear, roundAgg.total()),
			int(roundAgg.x4XORAndCheck.Milliseconds()), pct(roundAgg.x4XORAndCheck, roundAgg.total()),
			int(roundAgg.x4BootAndSplit.Milliseconds()), pct(roundAgg.x4BootAndSplit, roundAgg.total()),
			int(roundAgg.shift.Milliseconds()), pct(roundAgg.shift, roundAgg.total()))
	}

	return out
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

// WordXORNew: 32-bit word XOR（bit-sliced），返回新 slice
func (sm4 *SM4Ctr) WordXORNew(a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(a) != 32 || len(b) != 32 {
		panic("WordXORNew: inputs must be len=32")
	}
	eval := sm4.Evaluator.ShallowCopy()
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = XORNew(eval, a[i], b[i])
	}
	return out
}

// WordFXORNew performs additive aggregation (x+y) per bit.
// Cleanup to boolean values is deferred to the bootstrapping boundary.
func (sm4 *SM4Ctr) WordFXORNew(a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(a) != 32 || len(b) != 32 {
		panic("WordFXORNew: inputs must be len=32")
	}
	eval := sm4.Evaluator.ShallowCopy()
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = FXORNew(eval, a[i], b[i])
	}
	return out
}

func (sm4 *SM4Ctr) WordMod2Reduce2New(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(in) != 32 {
		panic("WordMod2Reduce2New: input must be len=32")
	}
	eval := sm4.Evaluator.ShallowCopy()
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = Mod2Reduce2New(eval, in[i])
	}
	return out
}

func (sm4 *SM4Ctr) WordMod2Reduce4New(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(in) != 32 {
		panic("WordMod2Reduce4New: input must be len=32")
	}
	eval := sm4.Evaluator.ShallowCopy()
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = Mod2Reduce4New(eval, in[i])
	}
	return out
}

func (sm4 *SM4Ctr) WordMod2Reduce6New(in []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	if len(in) != 32 {
		panic("WordMod2Reduce6New: input must be len=32")
	}
	eval := sm4.Evaluator.ShallowCopy()
	out := make([]*rlwe.Ciphertext, 32)
	for i := 0; i < 32; i++ {
		out[i] = Mod2Reduce6New(eval, in[i])
	}
	return out
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

	// tmp = x1 + x2 + x3 + rk (additive path over Z)
	stageStart := time.Now()
	u0 := sm4.WordFXORNew(x1, x2)
	u1 := sm4.WordFXORNew(x3, rk)
	tmp := sm4.WordFXORNew(u0, u1)
	rt.tmpXOR = time.Since(stageStart)

	// Pull back to bits only at bootstrap boundary.
	tmp = sm4.WordMod2Reduce4New(tmp)

	// === Bootstrap BEFORE SBox: cleanup + replenish levels ===
	stageStart = time.Now()
	sm4.bootstrapBitsCmplxThenDivide(tmp, roundNo, "tmp")
	rt.tmpBootstrap = time.Since(stageStart)

	// === SBox: 4 bytes ===
	stageStart = time.Now()
	sboxTasks := 4
	sboxWorkers := sm4.sboxWorkerCount(sboxTasks)
	if sboxWorkers <= 1 {
		evalCopy := sm4.Evaluator.ShallowCopy()
		for byteIdx := 0; byteIdx < sboxTasks; byteIdx++ {
			sm4.sm4SubbyteLUT(evalCopy, tmp[byteIdx*8:(byteIdx+1)*8])
		}
	} else {
		evals := sm4.ensureEvalPool(&sm4.sboxEvalPool, sboxWorkers)
		var next int64
		var sboxWG sync.WaitGroup
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
					sm4.sm4SubbyteLUT(evalCopy, tmp[byteIdx*8:(byteIdx+1)*8])
				}
			}(evalCopy)
		}
		sboxWG.Wait()
	}
	rt.sbox = time.Since(stageStart)

	// === L linear transform with additive path over Z ===
	stageStart = time.Now()
	r2 := rotlWordBits(tmp, 2)
	r10 := rotlWordBits(tmp, 10)
	r18 := rotlWordBits(tmp, 18)
	r24 := rotlWordBits(tmp, 24)

	v0 := sm4.WordFXORNew(tmp, r2)
	v1 := sm4.WordFXORNew(r10, r18)
	v2 := sm4.WordFXORNew(v0, v1)
	t := sm4.WordFXORNew(v2, r24)
	rt.linear = time.Since(stageStart)

	// x4 = x0 + t, then single pull-back at bootstrap boundary.
	stageStart = time.Now()
	x4 := sm4.WordFXORNew(x0, t)
	x4 = sm4.WordMod2Reduce6New(x4)

	minBootstrapLevel := sm4.SlotsToCoeffsParameters.LevelQ
	for i := 0; i < 32; i++ {
		if x4[i].Level() < minBootstrapLevel {
			panic(fmt.Sprintf("SM4 RoundFunction(round=%d): x4[%d] level=%d < bootstrap minimum level=%d", roundNo, i, x4[i].Level(), minBootstrapLevel))
		}
	}
	rt.x4XORAndCheck = time.Since(stageStart)

	// === Bootstrap x4: cleanup + replenish levels for next round ===
	stageStart = time.Now()
	sm4.bootstrapBitsCmplxThenDivide(x4, roundNo, "x4")
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

// 对称密钥放进 slot，然后同态加密得到 ciphertext（同时生成并加密 32 个 round key）
func (sm4 *SM4Ctr) EncryptKey() {
	sm4.ensureEncryptedKeySchedule()
}

func (sm4 *SM4Ctr) encryptKeyNoCache() {
	if sm4.encoder == nil || sm4.encryptor == nil {
		panic("encoder or encryptor is not initialized")
	}
	sm4.ensureScratch()

	sm4.rounds = 32

	// (1) Encrypt master key bits (128 bits) -> keyEncrypted
	sm4.keyEncrypted = make([]*rlwe.Ciphertext, sm4.keySize)

	for i := 0; i < sm4.keySize; i++ {
		if i >= len(sm4.symmetricKey)*8 {
			panic("input symmetric key size is not match!")
		}

		// LSB-first per byte（你当前实现就是这样）
		bit := (sm4.symmetricKey[i/8] >> uint(i%8)) & 1

		fill := float64(bit)
		for j := range sm4.slotFloatScratch {
			sm4.slotFloatScratch[j] = fill
		}

		pt := ckks.NewPlaintext(sm4.params, sm4.remainingLevel)
		sm4.encoder.Encode(sm4.slotFloatScratch, pt)
		if pt == nil {
			panic("pt is nil after encoding")
		}

		ct, err := sm4.encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		if ct == nil {
			panic("ct is nil after encryption")
		}

		sm4.keyEncrypted[i] = ct
	}

	// (2) Key schedule in plaintext -> rkPlain[32], then encrypt -> rkEncrypted
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
				// ctr(iv, i): first block uses counter=iv, then 128-bit LE increment.
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
		fmt.Println("data is not full pack, fill with 0...")
	}

	encryptedData := sm4.cipherBitScratch

	for i := range encryptedData {
		if i < numBlock {
			if sm4.allZeroIn {
				encryptedData[i].Clear()
			} else {
				totalBits := len(ciphertexts) * 8
				maxBitsByBlocks := numBlock * sm4.blockSize
				if totalBits > maxBitsByBlocks {
					totalBits = maxBitsByBlocks
				}

				slotBase := i * sm4.blockSize
				for k := 0; k < sm4.blockSize && slotBase+k < totalBits; k++ {
					ind := slotBase + k
					encryptedData[i].bits[k] = (ciphertexts[ind/8] >> uint(ind%8)) & 1
				}
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

// SM4 Sbox（ANF LUT）
func (sm4 *SM4Ctr) sm4SubbyteLUT(eval *bootstrapping.Evaluator, SBoxIn []*rlwe.Ciphertext) {
	if len(SBoxIn) != 8 {
		panic("The input length of the Sbox is wrong (8bit)!!")
	}
	sboxMonomials, _ := LayeredCombine(eval, SBoxIn)
	for bit := 0; bit < 8; bit++ {
		SBoxIn[bit] = sm4.coefficientMultMonomial(eval, sboxMonomials, sm4.sboxSparseTerms[bit], sm4.sboxConstBits[bit])
	}
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

// 注意：为保持你整个工程的 LSB-first/byte0=低字节 的切片方式一致，
// 这里“按 LE 读取 uint32”。
func loadU32BE(b []byte) uint32 {
	// LE: b[0]=最低字节
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// τ：对 32-bit word 的每个字节过 Sbox
// 这里也按 LE 视角：byte0=a&0xff（最低字节）对应 tmp[0:8]
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
