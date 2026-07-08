package ckks_cipher

import (
	"strings"
)

type BitSet struct {
	bits []uint8
	size int
}

func NewBitSet(size int) *BitSet {
	return &BitSet{
		bits: make([]uint8, size),
		size: size,
	}
}

func (b *BitSet) Set(x int) {
	if x < 0 {
		panic("x value must > 0")
	}
	for i := 0; i < b.size; i++ {
		b.bits[i] = uint8(x & 0x1)
		x >>= 1
	}
}

func (b *BitSet) Clear() {
	for i := range b.bits {
		b.bits[i] = 0
	}
}

func (b *BitSet) SetBit(i int, value uint8) {
	if i < 0 || i >= b.size {
		panic("SetBit: index out of range")
	}
	b.bits[i] = value & 1
}

// SetBytesLE fills BitSet from a generic little-endian byte slice.
// This helper is kept for legacy/reference paths and is not used by the default SM4-CTR flow.
// bit i maps to data[i/8]>>(i%8) & 1.
func (b *BitSet) SetBytesLE(data []byte) {
	b.Clear()
	limit := b.size
	if limit > len(data)*8 {
		limit = len(data) * 8
	}
	for i := 0; i < limit; i++ {
		b.bits[i] = (data[i/8] >> uint(i%8)) & 1
	}
}

// SetBlockBytesBE fills BitSet from big-endian 32-bit words.
// For word w, internal bit [32*w+j] stores the j-th bit of that numeric word value.
func (b *BitSet) SetBlockBytesBE(data []byte) {
	if b.size%32 != 0 {
		panic("SetBlockBytesBE: bitset size must be a multiple of 32")
	}
	if len(data)%4 != 0 {
		panic("SetBlockBytesBE: input byte length must be a multiple of 4")
	}

	b.Clear()

	wordCount := b.size / 32
	if maxWords := len(data) / 4; wordCount > maxWords {
		wordCount = maxWords
	}

	for wordIdx := 0; wordIdx < wordCount; wordIdx++ {
		word := loadU32BE(data[wordIdx*4 : wordIdx*4+4])
		base := wordIdx * 32
		for bit := 0; bit < 32; bit++ {
			b.bits[base+bit] = uint8((word >> uint(bit)) & 1)
		}
	}
}

// BlockBytesBE returns the BitSet as big-endian 32-bit words.
func (b *BitSet) BlockBytesBE() []byte {
	if b.size%32 != 0 {
		panic("BlockBytesBE: bitset size must be a multiple of 32")
	}

	out := make([]byte, b.size/8)
	for wordIdx := 0; wordIdx < b.size/32; wordIdx++ {
		base := wordIdx * 32
		var word uint32
		for bit := 0; bit < 32; bit++ {
			word |= uint32(b.bits[base+bit]&1) << uint(bit)
		}
		off := wordIdx * 4
		out[off] = byte(word >> 24)
		out[off+1] = byte(word >> 16)
		out[off+2] = byte(word >> 8)
		out[off+3] = byte(word)
	}
	return out
}

func (b *BitSet) ToULong() uint64 {
	var out uint64
	limit := b.size
	if limit > 64 {
		limit = 64
	}
	for i := 0; i < limit; i++ {
		out |= uint64(b.bits[i]&1) << uint(i)
	}
	return out
}

func (b *BitSet) ToString() string {
	var sb strings.Builder
	for _, byte := range b.bits {
		if byte == 1 {
			sb.WriteString("1")
		} else {
			sb.WriteString("0")
		}
	}
	return sb.String()
}

func (b *BitSet) Copy() *BitSet {
	out := NewBitSet(b.size)
	for i, bit := range b.bits {
		if bit == 1 {
			out.bits[i] = 1
		} else {
			out.bits[i] = 0
		}
	}
	return out
}

func Xor(v0, v1 *BitSet) *BitSet {

	if v0.size != v1.size {
		panic("bit sets have different sizes")
	}
	Out := NewBitSet(v0.size)
	for i := 0; i < v0.size; i++ {
		Out.bits[i] = v0.bits[i] ^ v1.bits[i]
	}
	return Out
}

func (b *BitSet) GetSize() int {
	return b.size
}

func ctr(iv *BitSet, ctr uint64) *BitSet {
	out := iv.Copy()
	block := out.BlockBytesBE()

	carry := ctr
	for i := len(block) - 1; i >= 0 && carry != 0; i-- {
		sum := uint64(block[i]) + (carry & 0xff)
		block[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}

	out.SetBlockBytesBE(block)
	return out
}

// MinInt returns the minimum value of the input of int values.
func MinInt(a, b int) (r int) {
	if a <= b {
		return a
	}
	return b
}
