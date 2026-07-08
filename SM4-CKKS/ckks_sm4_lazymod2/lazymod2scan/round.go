package lazymod2scan

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/ckks_cipher"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func (ctx *Context) ValidateOneRound() error {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	sm4, err := ckks_cipher.NewSM4Ctr(key, ctx.Params, ctx.BtpParams, ctx.EvaluationKeys, ctx.Encoder, ctx.Encryptor, ctx.Decryptor, iv)
	if err != nil {
		return err
	}
	sm4.SetProgressLog(false)
	sm4.SetWorkerConfig(1, 1)

	zero, err := ctx.Encrypt(constValues(ctx.Params.MaxSlots(), 0))
	if err != nil {
		return err
	}
	one, err := ctx.Encrypt(constValues(ctx.Params.MaxSlots(), 1))
	if err != nil {
		return err
	}
	state := make([]*rlwe.Ciphertext, 128)
	for i := range state {
		if i&1 == 0 {
			state[i] = zero.CopyNew()
		} else {
			state[i] = one.CopyNew()
		}
	}
	rk := make([]*rlwe.Ciphertext, 32)
	for i := range rk {
		if i%3 == 0 {
			rk[i] = one.CopyNew()
		} else {
			rk[i] = zero.CopyNew()
		}
	}

	sm4.RoundFunction(state, rk, 1)
	minLevel := state[96].Level()
	for _, ct := range state[96:128] {
		if ct.Level() < minLevel {
			minLevel = ct.Level()
		}
	}
	if minLevel < ctx.BtpParams.SlotsToCoeffsParameters.LevelQ {
		return fmt.Errorf("one-round x4 level=%d below StC LevelQ=%d", minLevel, ctx.BtpParams.SlotsToCoeffsParameters.LevelQ)
	}
	return nil
}

func constValues(slots int, value float64) []float64 {
	values := make([]float64, slots)
	for i := range values {
		values[i] = value
	}
	return values
}
