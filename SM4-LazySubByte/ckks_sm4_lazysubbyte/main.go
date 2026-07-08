package main

import (
	"bytes"
	"flag"
	"fmt"
	"runtime"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/ckks_cipher"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var flagShort = flag.Bool("short", false, "run the example with a smaller and insecure ring degree.")
var flagThreads = flag.Int("threads", runtime.NumCPU(), "max number of OS threads to use")
var flagBootMode = flag.String("bootmode", "pair", "bootstrap mode: pair|many")
var flagBootWorkers = flag.Int("boot-workers", 0, "bootstrap worker count (<=0 means auto)")
var flagSboxWorkers = flag.Int("sbox-workers", 0, "sbox worker count (<=0 means auto)")

func main() {

	flag.Parse()
	threads := *flagThreads
	if threads < 1 {
		threads = 1
	}
	runtime.GOMAXPROCS(threads)
	fmt.Printf("GOMAXPROCS=%d\n", threads)
	// Default LogN, which with the following defined parameters
	// provides a security of 128-bit.
	LogN := 12

	if *flagShort {
		LogN -= 3
	}

	// Modulus Chain
	q0 := []int{58}
	qiSlotsToCoeffs := []int{42, 42, 42}
	qiCircuitSlots := []int{42, 42, 42, 42, 42, 42, 42, 42, 42} // 0) Circuit in the slot domain
	qiEvalMod := []int{58, 58, 58, 58, 58, 58, 58, 58}          // 6) EvalMod
	qiCoeffsToSlots := []int{58, 58, 58, 58}                    // 5) CoeffsToSlots

	logQ := append(q0, qiSlotsToCoeffs...)
	logQ = append(logQ, qiCircuitSlots...)
	logQ = append(logQ, qiEvalMod...)
	logQ = append(logQ, qiCoeffsToSlots...)

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            LogN,                      // Log2 of the ring degree
		LogQ:            logQ,                      // Log2 of the ciphertext prime moduli
		LogP:            []int{59, 59, 60, 60, 60}, // Log2 of the key-switch auxiliary prime moduli
		LogDefaultScale: 42,                        // Log2 of the scale
		Xs:              ring.Ternary{H: 192},
	})

	if err != nil {
		panic(err)
	}

	// CoeffsToSlots parameters (homomorphic encoding)
	CoeffsToSlotsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicEncode,
		Format:       dft.RepackImagAsReal, // Returns the real and imaginary part into separate ciphertexts
		LogSlots:     params.LogMaxSlots(),
		LevelQ:       params.MaxLevelQ(),
		LevelP:       params.MaxLevelP(),
		LogBSGSRatio: 1,
		Levels:       []int{1, 1, 1, 1}, //qiCoeffsToSlots
	}

	// Parameters of the homomorphic modular reduction x mod 1
	Mod1ParametersLiteral := mod1.ParametersLiteral{
		LevelQ:          params.MaxLevel() - CoeffsToSlotsParameters.Depth(true),
		LogScale:        58,               // Matches qiEvalMod
		Mod1Type:        mod1.CosDiscrete, // Multi-interval Chebyshev interpolation
		Mod1Degree:      30,               // Depth 5
		DoubleAngle:     3,                // Depth 3
		K:               16,               // With EphemeralSecretWeight = 32 and 2^{15} slots, ensures < 2^{-138.7} failure probability
		LogMessageRatio: 10,               // q/|m| = 2^10
		Mod1InvDegree:   0,                // Depth 0
	}

	// SlotsToCoeffs parameters (homomorphic decoding)
	SlotsToCoeffsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: 1,
		LevelP:       params.MaxLevelP(),
		Levels:       []int{1, 1, 1}, // qiSlotsToCoeffs
	}
	SlotsToCoeffsParameters.LevelQ = len(SlotsToCoeffsParameters.Levels)

	// Custom bootstrapping.Parameters.
	// All fields are public and can be manually instantiated.
	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: SlotsToCoeffsParameters,
		Mod1ParametersLiteral:   Mod1ParametersLiteral,
		CoeffsToSlotsParameters: CoeffsToSlotsParameters,
		EphemeralSecretWeight:   32, // > 128bit secure for LogN=16 and LogQP = 115.
		CircuitOrder:            bootstrapping.DecodeThenModUp,
	}

	if *flagShort {
		// Corrects the message ratio Q0/|m(X)| to take into account the smaller number of slots and keep the same precision
		btpParams.Mod1ParametersLiteral.LogMessageRatio += 16 - params.LogN()
		// Keep short-mode away from the ScaleDown boundary:
		// if LogMessageRatio is too high, BootstrapReal can fail with
		// "initial Q/Scale < 0.5*Q[0]/MessageRatio".
		if btpParams.Mod1ParametersLiteral.LogMessageRatio > 16 {
			btpParams.Mod1ParametersLiteral.LogMessageRatio = 16
		}
	}

	// We print some information about the residual parameters.
	fmt.Printf("Residual parameters: logN=%d, logSlots=%d, H=%d, sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.ResidualParameters.LogN(),
		btpParams.ResidualParameters.LogMaxSlots(),
		btpParams.ResidualParameters.XsHammingWeight(),
		btpParams.ResidualParameters.Xe(), params.LogQP(),
		btpParams.ResidualParameters.MaxLevel(),
		btpParams.ResidualParameters.LogDefaultScale())

	// And some information about the bootstrapping parameters.
	// We can notably check that the LogQP of the bootstrapping parameters is smaller than 1550, which ensures
	// 128-bit of security as explained above.
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
	if err := sm4.SetBootMode(*flagBootMode); err != nil {
		panic(err)
	}
	sm4.SetWorkerConfig(*flagBootWorkers, *flagSboxWorkers)
	// End-to-end check: plaintext -> plain CTR encrypt -> HE decrypt -> compare plaintext.
	plainIn := []byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,
	}
	cipherIn := ckks_cipher.SM4CTRLE(symmetricKey, iv, plainIn)
	sm4.SetAllZeroInput(false)
	plainHEBits := sm4.HEDecrypt(cipherIn, len(plainIn)*8)
	plainHE := decodeSlotBitsToBytes(encoder, decryptor, plainHEBits, 0, len(plainIn)*8)

	match := bytes.Equal(plainHE, plainIn)
	fmt.Printf("HE decrypt round-trip (slot0, 1 block): %v\n", match)
	if !match {
		fmt.Printf("HE plaintext : %x\n", plainHE)
		fmt.Printf("Ref plaintext: %x\n", plainIn)
	}

}

func decodeSlotBitsToBytes(encoder *ckks.Encoder, decryptor *rlwe.Decryptor, bitCts []*rlwe.Ciphertext, slot, bitLen int) []byte {
	if bitLen <= 0 {
		return nil
	}

	out := make([]byte, (bitLen+7)/8)
	for i := 0; i < bitLen; i++ {
		values := make([]float64, bitCts[i].Slots())
		if err := encoder.Decode(decryptor.DecryptNew(bitCts[i]), values); err != nil {
			panic(err)
		}
		bit := uint8(0)
		if values[slot] > 0.5 {
			bit = 1
		}
		out[i/8] |= bit << uint(i%8)
	}

	return out
}
