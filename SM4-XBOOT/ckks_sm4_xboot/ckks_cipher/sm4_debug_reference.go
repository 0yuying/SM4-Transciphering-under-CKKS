package ckks_cipher

import (
	"encoding/hex"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Deprecated: debug only; legacy LE variant; not standard CTR interoperable.
func DebugPlainSM4CTRLE() {
	key := mustHex("0123456789abcdeffedcba9876543210")
	iv := make([]byte, 16) // all-zero counter start (legacy LE variant)
	pt := mustHex("00112233445566778899aabbccddeeff")

	ct := SM4CTRLE(key, iv, pt)
	fmt.Printf("CT = %x\n", ct)

	pt2 := SM4CTRLE(key, iv, ct)
	fmt.Printf("PT = %x\n", pt2)
}

// Deprecated: debug only; not part of the production transcipher path.
func (rtb *RtBCipher) DebugPrint(ct *rlwe.Ciphertext, descriptor string) {
	fmt.Printf("Chain Index: %d, Scale: %.2f\n", ct.Level(), ct.LogScale())
	valuesTest := make([]float64, ct.Slots())
	if err := rtb.Decode(rtb.decryptor.DecryptNew(ct), valuesTest); err != nil {
		panic(err)
	}
	fmt.Println(descriptor)
	PrintVectorTrunc(valuesTest, 7, 4)
}

// Deprecated: debug only; use dedicated debug tooling instead of depending on this helper in production code.
func PrintVectorTrunc(vec interface{}, printSize, prec int) {
	switch v := vec.(type) {
	case []complex128:
		printComplexVectorTrunc(v, printSize, prec)
	case []float64:
		printFloatVectorTrunc(v, printSize, prec)
	default:
		fmt.Println("Unsupported type")
	}
	fmt.Println()
}

func extractComponents(value complex128) (float64, float64) {
	return real(value), imag(value)
}

func getDelimiter(i, maxIndex int) string {
	if i != maxIndex {
		return ", "
	}
	return " ]\n"
}

func printComplexVectorTrunc(v []complex128, printSize, prec int) {
	lenV := len(v)
	if lenV <= 2*printSize {
		fmt.Printf("[")
		for i, value := range v {
			cReal, cImag := extractComponents(value)
			fmt.Printf(" (%.*f,+ %.*fi)%s", prec, cReal, prec, cImag, getDelimiter(i, lenV-1))
		}
	} else {
		fmt.Printf("[")
		for i := 0; i < printSize; i++ {
			cReal, cImag := extractComponents(v[i])
			fmt.Printf(" (%.*f+%.*fi)%s", prec, cReal, prec, cImag, getDelimiter(i, printSize-1))
		}
		fmt.Printf(" ... ")
		for i := lenV - printSize; i < lenV; i++ {
			cReal, cImag := extractComponents(v[i])
			fmt.Printf(" (%.*f+%.*fi)%s", prec, cReal, prec, cImag, getDelimiter(i, lenV-1))
		}
	}
}

func printFloatVectorTrunc(v []float64, printSize, prec int) {
	lenV := len(v)
	if lenV <= 2*printSize {
		fmt.Printf("[")
		for i, value := range v {
			fmt.Printf(" %.*f%s", prec, value, getDelimiter(i, lenV-1))
		}
	} else {
		fmt.Printf("[")
		for i := 0; i < printSize; i++ {
			fmt.Printf(" %.*f%s", prec, v[i], getDelimiter(i, printSize-1))
		}
		fmt.Printf(" ...")
		for i := lenV - printSize; i < lenV; i++ {
			fmt.Printf(" %.*f%s", prec, v[i], getDelimiter(i, lenV-1))
		}
	}
}
