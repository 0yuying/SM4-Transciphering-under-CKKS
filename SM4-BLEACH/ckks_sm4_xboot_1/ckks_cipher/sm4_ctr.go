package ckks_cipher

import (
	"fmt"
	"math"
	"runtime"
	"sync"
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
	allZeroIn         bool

	// ===== SM4 round keys (32 rounds × 32 bits) =====
	rkEncrypted [][]*rlwe.Ciphertext
}

type roundTiming struct {
	tmpXOR         time.Duration
	tmpBootstrap   time.Duration
	sbox           time.Duration
	linear         time.Duration
	x4XORAndCheck  time.Duration
	x4BootAndClean time.Duration
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

func (t roundTiming) total() time.Duration {
	return t.tmpXOR + t.tmpBootstrap + t.sbox + t.linear + t.x4XORAndCheck + t.x4BootAndClean + t.shift
}

func (t *roundTiming) add(other roundTiming) {
	t.tmpXOR += other.tmpXOR
	t.tmpBootstrap += other.tmpBootstrap
	t.sbox += other.sbox
	t.linear += other.linear
	t.x4XORAndCheck += other.x4XORAndCheck
	t.x4BootAndClean += other.x4BootAndClean
	t.shift += other.shift
}

func pct(part, total time.Duration) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
}

func mib(bytes uint64) float64 {
	return float64(bytes) / (1024 * 1024)
}

func mibDelta(after, before uint64) float64 {
	return float64(int64(after)-int64(before)) / (1024 * 1024)
}

func ratePerSecond(amount float64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return amount / d.Seconds()
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

func (sm4 *SM4Ctr) logHEDecryptMetrics(m sm4HEDecryptMetrics) {
	if !sm4.progress {
		return
	}
	fmt.Printf("[SM4][Metrics][Throughput] bits=%d bytes=%d blocks=%d | total=%.2f bit/s %.2f B/s %.4f block/s | sm4=%.2f bit/s %.2f B/s %.4f block/s | rounds=%.2f bit/s %.2f B/s %.4f block/s\n",
		m.bits, m.bytes, m.blocks,
		ratePerSecond(float64(m.bits), m.total), ratePerSecond(float64(m.bytes), m.total), ratePerSecond(float64(m.blocks), m.total),
		ratePerSecond(float64(m.bits), m.sm4Runtime), ratePerSecond(float64(m.bytes), m.sm4Runtime), ratePerSecond(float64(m.blocks), m.sm4Runtime),
		ratePerSecond(float64(m.bits), m.rounds), ratePerSecond(float64(m.bytes), m.rounds), ratePerSecond(float64(m.blocks), m.rounds))
	fmt.Printf("[SM4][Metrics][Memory] heapAlloc=%.2f MiB delta=%+.2f MiB heapSys=%.2f MiB sys=%.2f MiB totalAllocDelta=%.2f MiB gcDelta=%d\n",
		mib(m.memEnd.HeapAlloc), mibDelta(m.memEnd.HeapAlloc, m.memStart.HeapAlloc),
		mib(m.memEnd.HeapSys), mib(m.memEnd.Sys),
		mib(m.memEnd.TotalAlloc-m.memStart.TotalAlloc), m.memEnd.NumGC-m.memStart.NumGC)
	fmt.Printf("[SM4][Metrics][Ciphertexts] logical=%d unique=%d | roundKeys=%d inputCounters=%d encodedCipher=%d state=%d output=%d\n",
		m.cts.logical, m.cts.unique,
		m.cts.roundKeys, m.cts.inputCounters, m.cts.encodedCiphertext, m.cts.state, m.cts.output)
}

// 结构体方法
func NewSM4Ctr(key_ []uint8, params_ ckks.Parameters, btpParams_ bootstrapping.Parameters, btpKey_ *bootstrapping.EvaluationKeys,
	encoder_ *ckks.Encoder, encryptor_ *rlwe.Encryptor, decryptor_ *rlwe.Decryptor, iv_ []byte) (*SM4Ctr, error) {

	rtb, err := NewRtBCipher(key_, params_, btpParams_, btpKey_, encoder_, encryptor_, decryptor_)
	if err != nil {
		return nil, err
	}

	sm4 := &SM4Ctr{
		RtBCipher: rtb,
		blockSize: 128,
		keySize:   128,
		rounds:    32,
		iv:        iv_,
		allZeroIn: true, // debug mode
		progress:  true, // print progress by default to observe long HE execution
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

	return sm4, nil
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

func bootstrapWorkerCount(taskCount int) int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	// Avoid over-parallelizing bootstrapping, which can spike memory usage.
	if workers > 8 {
		workers = 8
	}
	if workers > taskCount {
		workers = taskCount
	}
	return workers
}

func (sm4 *SM4Ctr) bootstrapBitsReal(cts []*rlwe.Ciphertext, roundNo int, stage string, clean bool) {
	if len(cts) == 0 {
		return
	}

	workers := bootstrapWorkerCount(len(cts))
	if workers == 1 {
		eval := sm4.Evaluator.ShallowCopy()
		for i := 0; i < len(cts); i++ {
			var err error
			cts[i], err = eval.BootstrapReal(cts[i])
			if err != nil {
				panic(fmt.Sprintf("SM4 RoundFunction(round=%d): %s bootstrap[%d] failed: %v", roundNo, stage, i, err))
			}
			if clean {
				CleanReal(eval, cts[i])
			}
		}
		return
	}

	jobs := make(chan int, len(cts))
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eval := sm4.Evaluator.ShallowCopy()
			for i := range jobs {
				out, err := eval.BootstrapReal(cts[i])
				if err != nil {
					once.Do(func() {
						firstErr = fmt.Errorf("SM4 RoundFunction(round=%d): %s bootstrap[%d] failed: %w", roundNo, stage, i, err)
					})
					continue
				}
				if clean {
					CleanReal(eval, out)
				}
				cts[i] = out
			}
		}()
	}

	for i := 0; i < len(cts); i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		panic(firstErr)
	}
}

// 同态解密（CTR keystream 生成）：对 counter 做 SM4 加密，返回 keystream bits
func (sm4 *SM4Ctr) HEDecrypt(ciphertexts []uint8, bits int) []*rlwe.Ciphertext {
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

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
	iv.Set(0) // all-zero IV/counter start

	// 1) key schedule (32 round keys)
	startKeySchedule := time.Now()
	sm4.EncryptKey()
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
	// 这里采用与你编码一致的 LSB-first：bit i 就是 word 的第 i 位（bit0=LSB）
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
			fmt.Printf("[SM4][Round %02d] done in %d ms, x4 level range=[%d,%d] | tmpXor=%dms(%.1f%%) tmpBoot=%dms(%.1f%%) sbox=%dms(%.1f%%) L=%dms(%.1f%%) x4=%dms(%.1f%%) x4BootClean=%dms(%.1f%%) shift=%dms(%.1f%%)\n",
				roundNo, int(roundDur.Milliseconds()), minLvl, maxLvl,
				int(rt.tmpXOR.Milliseconds()), pct(rt.tmpXOR, rt.total()),
				int(rt.tmpBootstrap.Milliseconds()), pct(rt.tmpBootstrap, rt.total()),
				int(rt.sbox.Milliseconds()), pct(rt.sbox, rt.total()),
				int(rt.linear.Milliseconds()), pct(rt.linear, rt.total()),
				int(rt.x4XORAndCheck.Milliseconds()), pct(rt.x4XORAndCheck, rt.total()),
				int(rt.x4BootAndClean.Milliseconds()), pct(rt.x4BootAndClean, rt.total()),
				int(rt.shift.Milliseconds()), pct(rt.shift, rt.total()))
		}
	}
	roundsDur := time.Since(startSM4)

	startFinalize := time.Now()
	out := sm4.Finalize(state) // (X35,X34,X33,X32)
	finalizeDur := time.Since(startFinalize)

	sm4RuntimeDur := time.Since(startSM4)
	fmt.Printf("SM4 Running %d s :: %d ms\n", int(sm4RuntimeDur.Seconds()), int(sm4RuntimeDur.Milliseconds())%1000)

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

	total := keyScheduleDur + encodeDur + dropDur + roundsDur + finalizeDur + outXORDur
	if sm4.progress {
		fmt.Printf("[SM4][Profile] total=%d ms | key=%dms(%.1f%%) encode=%dms(%.1f%%) drop=%dms(%.1f%%) rounds=%dms(%.1f%%) finalize=%dms(%.1f%%) outXor=%dms(%.1f%%)\n",
			int(total.Milliseconds()),
			int(keyScheduleDur.Milliseconds()), pct(keyScheduleDur, total),
			int(encodeDur.Milliseconds()), pct(encodeDur, total),
			int(dropDur.Milliseconds()), pct(dropDur, total),
			int(roundsDur.Milliseconds()), pct(roundsDur, total),
			int(finalizeDur.Milliseconds()), pct(finalizeDur, total),
			int(outXORDur.Milliseconds()), pct(outXORDur, total))
		fmt.Printf("[SM4][Profile][RoundsSum] tmpXor=%dms(%.1f%%) tmpBoot=%dms(%.1f%%) sbox=%dms(%.1f%%) L=%dms(%.1f%%) x4=%dms(%.1f%%) x4BootClean=%dms(%.1f%%) shift=%dms(%.1f%%)\n",
			int(roundAgg.tmpXOR.Milliseconds()), pct(roundAgg.tmpXOR, roundAgg.total()),
			int(roundAgg.tmpBootstrap.Milliseconds()), pct(roundAgg.tmpBootstrap, roundAgg.total()),
			int(roundAgg.sbox.Milliseconds()), pct(roundAgg.sbox, roundAgg.total()),
			int(roundAgg.linear.Milliseconds()), pct(roundAgg.linear, roundAgg.total()),
			int(roundAgg.x4XORAndCheck.Milliseconds()), pct(roundAgg.x4XORAndCheck, roundAgg.total()),
			int(roundAgg.x4BootAndClean.Milliseconds()), pct(roundAgg.x4BootAndClean, roundAgg.total()),
			int(roundAgg.shift.Milliseconds()), pct(roundAgg.shift, roundAgg.total()))
	}

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

// WordFXORNew performs additive aggregation (x+y) per bit and requires explicit mod2 reduction later.
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

// WordAddMod2New computes (a+b) mod 2 per bit via add + Mod2Reduce2.
func (sm4 *SM4Ctr) WordAddMod2New(a, b []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	sum := sm4.WordFXORNew(a, b)
	return sm4.WordMod2Reduce2New(sum)
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

	// tmp = (x1 + x2 + x3 + rk) mod 2 with a balanced add-mod2 tree.
	stageStart := time.Now()
	u0 := sm4.WordAddMod2New(x1, x2)
	u1 := sm4.WordAddMod2New(x3, rk)
	tmp := sm4.WordAddMod2New(u0, u1)
	rt.tmpXOR = time.Since(stageStart)

	// === Bootstrap BEFORE SBox: 保证 SBox 入口 level 足够 ===
	stageStart = time.Now()
	sm4.bootstrapBitsReal(tmp, roundNo, "tmp", false)
	rt.tmpBootstrap = time.Since(stageStart)

	// === SBox: 4 bytes ===
	stageStart = time.Now()
	for b := 0; b < 4; b++ {
		evalCopy := sm4.Evaluator.ShallowCopy()
		sm4.sm4SubbyteLUT(evalCopy, tmp[b*8:(b+1)*8])
	}
	rt.sbox = time.Since(stageStart)

	// === L linear transform (add-mod2 path, balanced tree) ===
	stageStart = time.Now()
	r2 := rotlWordBits(tmp, 2)
	r10 := rotlWordBits(tmp, 10)
	r18 := rotlWordBits(tmp, 18)
	r24 := rotlWordBits(tmp, 24)

	v0 := sm4.WordAddMod2New(tmp, r2)
	v1 := sm4.WordAddMod2New(r10, r18)
	v2 := sm4.WordAddMod2New(v0, v1)
	t := sm4.WordAddMod2New(v2, r24)
	rt.linear = time.Since(stageStart)

	// x4 = x0 + t, then mod2 reduction.
	stageStart = time.Now()
	x4 := sm4.WordAddMod2New(x0, t)

	minBootstrapLevel := sm4.SlotsToCoeffsParameters.LevelQ
	for i := 0; i < 32; i++ {
		if x4[i].Level() < minBootstrapLevel {
			panic(fmt.Sprintf("SM4 RoundFunction(round=%d): x4[%d] level=%d < bootstrap minimum level=%d", roundNo, i, x4[i].Level(), minBootstrapLevel))
		}
	}
	rt.x4XORAndCheck = time.Since(stageStart)

	// === Bootstrap x4，恢复层数供下一轮继续计算 ===
	stageStart = time.Now()
	sm4.bootstrapBitsReal(x4, roundNo, "x4", true)
	rt.x4BootAndClean = time.Since(stageStart)

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
	if sm4.encoder == nil || sm4.encryptor == nil {
		panic("encoder or encryptor is not initialized")
	}

	sm4.rounds = 32

	// (1) Encrypt master key bits (128 bits) -> keyEncrypted
	sm4.keyEncrypted = make([]*rlwe.Ciphertext, 0, sm4.keySize)

	for i := 0; i < sm4.keySize; i++ {
		if i >= len(sm4.symmetricKey)*8 {
			panic("input symmetric key size is not match!")
		}

		// LSB-first per byte（你当前实现就是这样）
		bit := (sm4.symmetricKey[i/8] >> uint(i%8)) & 1

		dup := make([]float64, sm4.params.MaxSlots())
		for j := 0; j < sm4.params.MaxSlots(); j++ {
			dup[j] = float64(bit)
		}

		pt := ckks.NewPlaintext(sm4.params, sm4.remainingLevel)
		sm4.encoder.Encode(dup, pt)
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

		sm4.keyEncrypted = append(sm4.keyEncrypted, ct)
	}

	// (2) Key schedule in plaintext -> rkPlain[32], then encrypt -> rkEncrypted
	rkPlain := sm4.sm4KeySchedulePlain(sm4.symmetricKey) // [32]uint32

	sm4.rkEncrypted = make([][]*rlwe.Ciphertext, 32)
	for r := 0; r < 32; r++ {
		sm4.rkEncrypted[r] = make([]*rlwe.Ciphertext, 0, 32)

		for i := 0; i < 32; i++ {
			// LSB-first per word：bit i = (rk >> i) & 1
			bit := (rkPlain[r] >> uint(i)) & 1

			dup := make([]float64, sm4.params.MaxSlots())
			for j := 0; j < sm4.params.MaxSlots(); j++ {
				dup[j] = float64(bit)
			}

			pt := ckks.NewPlaintext(sm4.params, sm4.remainingLevel)
			sm4.encoder.Encode(dup, pt)
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

			sm4.rkEncrypted[r] = append(sm4.rkEncrypted[r], ct)
		}
	}
}

// EncryptInput: 把 counter blocks 做 bit-sliced SIMD 编码并加密到 inputEncrypted
func (sm4 *SM4Ctr) EncryptInput(iv *BitSet, numBlock int) {
	sm4.inputEncrypted = make([]*rlwe.Ciphertext, 0, sm4.blockSize)

	inputData := make([]*BitSet, sm4.params.MaxSlots())
	for i := range inputData {
		inputData[i] = NewBitSet(sm4.blockSize)
	}

	for i := range inputData {
		if sm4.allZeroIn {
			inputData[i].Set(0)
		} else {
			if i < numBlock {
				// ctr(iv, i): first block uses counter=iv.
				// BitSet.Set uses LSB-first storage.
				inputData[i].Set(int(ctr(iv, uint64(i)).ToULong()))
			} else {
				inputData[i].Set(0)
			}
		}
	}

	for i := 0; i < sm4.blockSize; i++ {
		stateBatched := make([]complex128, sm4.params.MaxSlots())
		for j := 0; j < sm4.params.MaxSlots(); j++ {
			stateBatched[j] = complex(float64(inputData[j].bits[i]), 0)
		}

		pt := ckks.NewPlaintext(*sm4.GetParameters(), sm4.remainingLevel)
		sm4.encoder.Encode(stateBatched, pt)

		ct := ckks.NewCiphertext(*sm4.GetParameters(), 1, sm4.remainingLevel)
		if err := sm4.encryptor.Encrypt(pt, ct); err != nil {
			panic(err)
		}
		sm4.inputEncrypted = append(sm4.inputEncrypted, ct)
	}

	if sm4.inputEncrypted[0] == nil {
		panic("input is not stored in sm4Struct")
	}
}

// EncodeCiphertext: bit-sliced 的 SIMD 批处理密文（修复 append bug）
func (sm4 *SM4Ctr) EncodeCiphertext(ciphertexts []uint8, numBlock int) {
	sm4.encodeCipher = make([]*rlwe.Ciphertext, sm4.blockSize)

	if numBlock < sm4.params.MaxSlots() {
		fmt.Println("data is not full pack, fill with 0...")
	}

	encryptedData := make([]*BitSet, sm4.params.MaxSlots())
	for i := range encryptedData {
		encryptedData[i] = NewBitSet(sm4.blockSize)
	}

	for i := range encryptedData {
		if i < numBlock {
			if sm4.allZeroIn {
				encryptedData[i].Set(0)
			} else {
				for k := 0; k < sm4.blockSize && i*sm4.blockSize+k < numBlock*sm4.blockSize; k++ {
					ind := i*sm4.blockSize + k
					bit := (ciphertexts[ind/8] >> uint(ind%8)) & 1
					encryptedData[i].bits[k] = uint8(bit)
				}
			}
		} else {
			encryptedData[i].Set(0)
		}
	}

	for i := 0; i < sm4.blockSize; i++ {
		dataBatched := make([]complex128, sm4.params.MaxSlots())
		for j := 0; j < sm4.params.MaxSlots(); j++ {
			dataBatched[j] = complex(float64(encryptedData[j].bits[i]), 0.0)
		}

		pt := ckks.NewPlaintext(*sm4.GetParameters(), sm4.remainingLevel)
		sm4.encoder.Encode(dataBatched, pt)

		ct, err := sm4.encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		sm4.encodeCipher[i] = ct
	}
}

// 系数 × 单项式，再求和，ANF 处理
func (sm4 *SM4Ctr) coefficientMultMonomial(eval *bootstrapping.Evaluator, mon []*rlwe.Ciphertext, coeffArr []int, pos int) (ctOut *rlwe.Ciphertext) {
	if len(mon) != len(sm4.sboxMonomialOrder) {
		panic("monomial size must equal to sbox_monomial_order!")
	}
	ctOut = mon[0].CopyNew()
	i := 0
	for i < len(mon) {
		ind := int(sm4.sboxMonomialOrder[i].ToULong()) - 1
		coeff := coeffArr[ind]
		if coeff == 0 {
			i++
			continue
		}
		eval.Mul(mon[i], coeff, ctOut)
		i++
		break
	}

	for i < len(mon) {
		ind := int(sm4.sboxMonomialOrder[i].ToULong()) - 1
		coeff := coeffArr[ind]
		if coeff == 0 {
			i++
			continue
		}
		tmp := ctOut.CopyNew()
		eval.Mul(mon[i], coeff, tmp)
		eval.Add(tmp, ctOut, ctOut)
		i++
	}
	eval.Add(ctOut, int(sm4.bitSbox[0].bits[pos]), ctOut)
	return
}

// SM4 Sbox（ANF LUT）
func (sm4 *SM4Ctr) sm4SubbyteLUT(eval *bootstrapping.Evaluator, SBoxIn []*rlwe.Ciphertext) {
	if len(SBoxIn) != 8 {
		panic("The input length of the Sbox is wrong (8bit)!!")
	}
	sboxMonomials, _ := LayeredCombine(eval, SBoxIn)
	SBoxIn[0] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox0[:], 0)
	SBoxIn[1] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox1[:], 1)
	SBoxIn[2] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox2[:], 2)
	SBoxIn[3] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox3[:], 3)
	SBoxIn[4] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox4[:], 4)
	SBoxIn[5] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox5[:], 5)
	SBoxIn[6] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox6[:], 6)
	SBoxIn[7] = sm4.coefficientMultMonomial(eval, sboxMonomials, Sbox7[:], 7)
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
