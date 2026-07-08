package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/ckks_cipher"
	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/lazymod2params"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var flagShort = flag.Bool("short", false, "run the example with a smaller and insecure ring degree.")
var flagLogN = flag.Int("logN", 12, "CKKS LogN to use for the example and optional full-slot throughput test")
var flagThreads = flag.Int("threads", runtime.NumCPU(), "max number of OS threads to use")
var flagBootWorkers = flag.Int("boot-workers", 0, "bootstrap worker count (<=0 means auto)")
var flagSboxWorkers = flag.Int("sbox-workers", 0, "sbox worker count (<=0 means auto)")
var flagProfile = flag.String("profile", "default", "LazyMod2 parameter profile: default or baseline")
var flagLegacyTwoBootRounds = flag.Bool("legacy-two-boot-rounds", false, "restore previous lazy schedule that bootstraps both tmp and x4 every round")
var flagThroughputFullSlots = flag.Bool("throughput-full-slots", false, "run the optional full-slot SM4-CKKS throughput test instead of the default 1-block check")
var flagThroughput2048 = flag.Bool("throughput-2048", false, "deprecated alias for -throughput-full-slots; logN=12 full slots are 2048 blocks")

func effectiveWorkerCount(configured, taskCount, gomax int) int {
	if taskCount <= 0 {
		return 0
	}
	workers := configured
	if workers <= 0 {
		workers = gomax
	}
	if workers < 1 {
		workers = 1
	}
	if workers > taskCount {
		workers = taskCount
	}
	return workers
}

func readLoadAverage1() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected /proc/loadavg format")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func readCPUFreqGovernor() (string, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func logBenchmarkEnvironmentWarnings() {
	cpuCount := runtime.NumCPU()
	if load1, err := readLoadAverage1(); err == nil && load1 > float64(cpuCount) {
		fmt.Printf("[SM4][Env][WARN] loadavg1=%.2f exceeds logical CPUs=%d; runtime may fluctuate.\n", load1, cpuCount)
	}
	if governor, err := readCPUFreqGovernor(); err == nil && strings.EqualFold(governor, "powersave") {
		fmt.Printf("[SM4][Env][WARN] CPU governor=%s; benchmark may be slower/less stable than performance mode.\n", governor)
	}
}

func main() {

	flag.Parse()
	threads := *flagThreads
	if threads < 1 {
		threads = 1
	}
	runtime.GOMAXPROCS(threads)
	fmt.Printf("GOMAXPROCS=%d\n", threads)
	LogN := *flagLogN

	if *flagShort {
		LogN -= 3
	}
	if LogN < 2 {
		panic(fmt.Sprintf("logN must be at least 2 after applying -short, got %d", LogN))
	}

	lazyMod2 := LogN > 9
	lazySubByte := true
	roundSchedule := "eager-legacy-two-boot"
	fusionMode := "eager-clean"
	tmpBound := 4
	finalBound := 1
	if lazyMod2 {
		roundSchedule = "one-boot"
		fusionMode = "sbox-l-fused-lazy"
		tmpBound = 124
		finalBound = 41
		if *flagLegacyTwoBootRounds {
			roundSchedule = "legacy-two-boot"
			tmpBound = 4
			finalBound = 1
		}
	}
	effectiveBootWorkers := effectiveWorkerCount(*flagBootWorkers, 16, threads)
	effectiveSboxWorkers := effectiveWorkerCount(*flagSboxWorkers, 4, threads)
	fmt.Printf("[SM4][Config] logN=%d short=%v lazyMod2=%v lazySubByte=%v roundSchedule=%s fusion=%s tmpBound=0..%d finalBound=0..%d\n",
		LogN, *flagShort, lazyMod2, lazySubByte, roundSchedule, fusionMode, tmpBound, finalBound)
	fmt.Printf("[SM4][Config] workers requested(boot=%d,sbox=%d) effective(boot=%d/16,sbox=%d/4) GOMAXPROCS=%d\n",
		*flagBootWorkers, *flagSboxWorkers, effectiveBootWorkers, effectiveSboxWorkers, threads)
	logBenchmarkEnvironmentWarnings()

	profile := lazymod2params.Default(LogN)
	switch *flagProfile {
	case "default":
		profile = lazymod2params.Default(LogN)
	case "baseline":
		profile = lazymod2params.Baseline(LogN)
	default:
		panic(fmt.Sprintf("unknown -profile %q (want default or baseline)", *flagProfile))
	}
	params, btpParams, err := profile.Build()
	if err != nil {
		panic(err)
	}
	fmt.Printf("[SM4][Config] profile=%s experimental=true security_claim=none\n", profile.Name)

	// We print some information about the residual parameters.
	fmt.Printf("Residual parameters: logN=%d, logSlots=%d, H=%d, sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.ResidualParameters.LogN(),
		btpParams.ResidualParameters.LogMaxSlots(),
		btpParams.ResidualParameters.XsHammingWeight(),
		btpParams.ResidualParameters.Xe(), params.LogQP(),
		btpParams.ResidualParameters.MaxLevel(),
		btpParams.ResidualParameters.LogDefaultScale())

	// And some information about the bootstrapping parameters.
	fmt.Printf("Bootstrapping parameters: logN=%d, logSlots=%d, H(%d; %d), sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.BootstrappingParameters.LogN(),
		btpParams.BootstrappingParameters.LogMaxSlots(),
		btpParams.BootstrappingParameters.XsHammingWeight(),
		btpParams.EphemeralSecretWeight,
		btpParams.BootstrappingParameters.Xe(),
		btpParams.BootstrappingParameters.LogQP(),
		btpParams.BootstrappingParameters.QCount(),
		btpParams.BootstrappingParameters.LogDefaultScale())

	//===========================
	//=== 4) KEYGEN & ENCRYPT ===
	//===========================

	// Now that both the residual and bootstrapping parameters are instantiated, we can
	// instantiate the usual necessary object to encode, encrypt and decrypt.

	// Scheme context and keys
	kgen := rlwe.NewKeyGenerator(params)

	sk, pk := kgen.GenKeyPairNew()

	encoder := ckks.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, pk)

	fmt.Println()
	fmt.Println("Generating bootstrapping evaluation keys...")
	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")

	//========================
	//=== 5) BOOTSTRAPPING ===
	//========================
	iv := make([]uint8, 16)
	symmetricKey := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	sm4, _ := ckks_cipher.NewSM4Ctr(symmetricKey, params, btpParams, evk, encoder, encryptor, decryptor, iv)
	sm4.SetLegacyTwoBootRounds(*flagLegacyTwoBootRounds)
	sm4.SetWorkerConfig(*flagBootWorkers, *flagSboxWorkers)
	if *flagThroughputFullSlots || *flagThroughput2048 {
		runSM4FullSlotThroughput(sm4, symmetricKey, iv, encoder, decryptor, params.LogN(), params.MaxSlots())
		return
	}

	// End-to-end check: plaintext -> plain CTR encrypt -> HE decrypt -> compare plaintext.
	plainIn := []byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,
	}
	cipherIn := ckks_cipher.SM4CTR(symmetricKey, iv, plainIn)
	sm4.SetAllZeroInput(false)
	plainHEBits, err := sm4.HEDecrypt(cipherIn, len(plainIn)*8)
	if err != nil {
		panic(err)
	}
	plainHE := decodeSlotBlockBitsToBytesBE(encoder, decryptor, plainHEBits, 0, len(plainIn)*8)

	match := bytes.Equal(plainHE, plainIn)
	fmt.Printf("HE decrypt round-trip (slot0, 1 block): %v\n", match)
	if !match {
		fmt.Printf("HE plaintext : %x\n", plainHE)
		fmt.Printf("Ref plaintext: %x\n", plainIn)
	}

}

func runSM4FullSlotThroughput(sm4 *ckks_cipher.SM4Ctr, symmetricKey, iv []byte, encoder *ckks.Encoder, decryptor *rlwe.Decryptor, logN, fullSlots int) {
	blocks := fullSlots
	if blocks <= 0 {
		panic(fmt.Sprintf("full-slot throughput test requires positive slot count, got %d", blocks))
	}

	plainIn := make([]byte, blocks*16)
	for i := range plainIn {
		plainIn[i] = byte((i*131 + 17) & 0xff)
	}

	cipherIn := ckks_cipher.SM4CTR(symmetricKey, iv, plainIn)
	sm4.SetAllZeroInput(false)

	fmt.Printf("[SM4][ThroughputFullSlots] start logN=%d fullSlots=%d blocks=%d bytes=%d bits=%d\n",
		logN, fullSlots, blocks, len(plainIn), len(plainIn)*8)
	start := time.Now()
	plainHEBits, err := sm4.HEDecrypt(cipherIn, len(plainIn)*8)
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)

	sampleSlots := []int{0, 1, blocks / 2, blocks - 1}
	allMatch := true
	for _, slot := range sampleSlots {
		got := decodeSlotBlockBitsToBytesBE(encoder, decryptor, plainHEBits, slot, 128)
		want := plainIn[slot*16 : slot*16+16]
		match := bytes.Equal(got, want)
		allMatch = allMatch && match
		fmt.Printf("[SM4][ThroughputFullSlots] verify slot=%d match=%v got=%x want=%x\n", slot, match, got, want)
	}

	seconds := elapsed.Seconds()
	fmt.Printf("[SM4][ThroughputFullSlots] elapsed=%s elapsed_ms=%d logN=%d fullSlots=%d blocks=%d block/s=%.4f B/s=%.2f bit/s=%.2f verify_samples=%v\n",
		elapsed.Round(time.Millisecond),
		elapsed.Milliseconds(),
		logN,
		fullSlots,
		blocks,
		float64(blocks)/seconds,
		float64(len(plainIn))/seconds,
		float64(len(plainIn)*8)/seconds,
		allMatch)
}

func decodeSlotBlockBitsToBytesBE(encoder *ckks.Encoder, decryptor *rlwe.Decryptor, bitCts []*rlwe.Ciphertext, slot, bitLen int) []byte {
	if bitLen <= 0 {
		return nil
	}
	if bitLen > len(bitCts) {
		bitLen = len(bitCts)
	}

	block := ckks_cipher.NewBitSet(len(bitCts))
	for i := 0; i < bitLen; i++ {
		values := make([]float64, bitCts[i].Slots())
		if err := encoder.Decode(decryptor.DecryptNew(bitCts[i]), values); err != nil {
			panic(err)
		}
		if values[slot] > 0.5 {
			block.SetBit(i, 1)
		}
	}

	out := block.BlockBytesBE()
	return out[:(bitLen+7)/8]
}
