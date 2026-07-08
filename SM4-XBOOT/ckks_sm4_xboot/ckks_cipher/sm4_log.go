package ckks_cipher

import (
	"fmt"
	"io"
	"os"
	"time"
)

func (sm4 *SM4Ctr) logf(progressOnly bool, format string, args ...any) {
	if progressOnly && !sm4.progress {
		return
	}
	out := io.Writer(os.Stdout)
	if sm4.logWriter != nil {
		out = sm4.logWriter
	}
	_, _ = fmt.Fprintf(out, format, args...)
}

func (sm4 *SM4Ctr) logHEDecryptMode(useCipherXOR bool, bits, numBlock int) {
	sm4.logf(true, "[SM4][HEDecrypt] mode(allZeroIn=%v, useCipherXOR=%v), bits=%d, numBlock=%d\n", sm4.allZeroIn, useCipherXOR, bits, numBlock)
}

func (sm4 *SM4Ctr) logHEDecryptStage(stage string, d time.Duration) {
	sm4.logf(true, "[SM4][HEDecrypt] %s in %d ms\n", stage, int(d.Milliseconds()))
}

func (sm4 *SM4Ctr) logRoundStart(roundNo int) {
	sm4.logf(true, "[SM4][Round %02d] start\n", roundNo)
}

func (sm4 *SM4Ctr) logRoundDone(roundNo int, roundDur time.Duration, minLvl, maxLvl int, rt roundTiming) {
	sm4.logf(true, "[SM4][Round %02d] done in %d ms, x4 level range=[%d,%d] | tmpXor=%dms(%.1f%%) tmpBoot=%dms(%.1f%%) sbox=%dms(%.1f%%) L=%dms(%.1f%%) x4=%dms(%.1f%%) x4BootSplit=%dms(%.1f%%) shift=%dms(%.1f%%)\n",
		roundNo, int(roundDur.Milliseconds()), minLvl, maxLvl,
		int(rt.tmpXOR.Milliseconds()), pct(rt.tmpXOR, rt.total()),
		int(rt.tmpBootstrap.Milliseconds()), pct(rt.tmpBootstrap, rt.total()),
		int(rt.sbox.Milliseconds()), pct(rt.sbox, rt.total()),
		int(rt.linear.Milliseconds()), pct(rt.linear, rt.total()),
		int(rt.x4XORAndCheck.Milliseconds()), pct(rt.x4XORAndCheck, rt.total()),
		int(rt.x4BootAndSplit.Milliseconds()), pct(rt.x4BootAndSplit, rt.total()),
		int(rt.shift.Milliseconds()), pct(rt.shift, rt.total()))
}

func (sm4 *SM4Ctr) logSM4Runtime(d time.Duration) {
	sm4.logf(false, "SM4 Running %d s :: %d ms\n", int(d.Seconds()), int(d.Milliseconds())%1000)
}

func (sm4 *SM4Ctr) logHEDecryptProfile(total, keyScheduleDur, encodeDur, dropDur, roundsDur, finalizeDur, finalBootDur, outXORDur time.Duration, roundAgg roundTiming) {
	sm4.logf(true, "[SM4][Profile] total=%d ms | key=%dms(%.1f%%) encode=%dms(%.1f%%) drop=%dms(%.1f%%) rounds=%dms(%.1f%%) finalize=%dms(%.1f%%) finalBoot=%dms(%.1f%%) outXor=%dms(%.1f%%)\n",
		int(total.Milliseconds()),
		int(keyScheduleDur.Milliseconds()), pct(keyScheduleDur, total),
		int(encodeDur.Milliseconds()), pct(encodeDur, total),
		int(dropDur.Milliseconds()), pct(dropDur, total),
		int(roundsDur.Milliseconds()), pct(roundsDur, total),
		int(finalizeDur.Milliseconds()), pct(finalizeDur, total),
		int(finalBootDur.Milliseconds()), pct(finalBootDur, total),
		int(outXORDur.Milliseconds()), pct(outXORDur, total))
	sm4.logf(true, "[SM4][Profile][RoundsSum] tmpXor=%dms(%.1f%%) tmpBoot=%dms(%.1f%%) sbox=%dms(%.1f%%) L=%dms(%.1f%%) x4=%dms(%.1f%%) x4BootSplit=%dms(%.1f%%) shift=%dms(%.1f%%)\n",
		int(roundAgg.tmpXOR.Milliseconds()), pct(roundAgg.tmpXOR, roundAgg.total()),
		int(roundAgg.tmpBootstrap.Milliseconds()), pct(roundAgg.tmpBootstrap, roundAgg.total()),
		int(roundAgg.sbox.Milliseconds()), pct(roundAgg.sbox, roundAgg.total()),
		int(roundAgg.linear.Milliseconds()), pct(roundAgg.linear, roundAgg.total()),
		int(roundAgg.x4XORAndCheck.Milliseconds()), pct(roundAgg.x4XORAndCheck, roundAgg.total()),
		int(roundAgg.x4BootAndSplit.Milliseconds()), pct(roundAgg.x4BootAndSplit, roundAgg.total()),
		int(roundAgg.shift.Milliseconds()), pct(roundAgg.shift, roundAgg.total()))
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

func (sm4 *SM4Ctr) logHEDecryptMetrics(m sm4HEDecryptMetrics) {
	sm4.logf(true, "[SM4][Metrics][Throughput] bits=%d bytes=%d blocks=%d | total=%.2f bit/s %.2f B/s %.4f block/s | sm4=%.2f bit/s %.2f B/s %.4f block/s | rounds=%.2f bit/s %.2f B/s %.4f block/s\n",
		m.bits, m.bytes, m.blocks,
		ratePerSecond(float64(m.bits), m.total), ratePerSecond(float64(m.bytes), m.total), ratePerSecond(float64(m.blocks), m.total),
		ratePerSecond(float64(m.bits), m.sm4Runtime), ratePerSecond(float64(m.bytes), m.sm4Runtime), ratePerSecond(float64(m.blocks), m.sm4Runtime),
		ratePerSecond(float64(m.bits), m.rounds), ratePerSecond(float64(m.bytes), m.rounds), ratePerSecond(float64(m.blocks), m.rounds))
	sm4.logf(true, "[SM4][Metrics][Memory] heapAlloc=%.2f MiB delta=%+.2f MiB heapSys=%.2f MiB sys=%.2f MiB totalAllocDelta=%.2f MiB gcDelta=%d\n",
		mib(m.memEnd.HeapAlloc), mibDelta(m.memEnd.HeapAlloc, m.memStart.HeapAlloc),
		mib(m.memEnd.HeapSys), mib(m.memEnd.Sys),
		mib(m.memEnd.TotalAlloc-m.memStart.TotalAlloc), m.memEnd.NumGC-m.memStart.NumGC)
	sm4.logf(true, "[SM4][Metrics][Ciphertexts] logical=%d unique=%d | roundKeys=%d inputCounters=%d encodedCipher=%d state=%d output=%d\n",
		m.cts.logical, m.cts.unique,
		m.cts.roundKeys, m.cts.inputCounters, m.cts.encodedCiphertext, m.cts.state, m.cts.output)
}

func (sm4 *SM4Ctr) logSboxOpStats(roundNo int, optimizedUsed bool, stats sm4SboxOpStats, eagerBaseline int) {
	mode := "eager"
	if optimizedUsed {
		mode = "optimized"
	}
	sm4.logf(true, "[SM4][Round %02d][SBoxOps] mode=%s relin=%d rescale=%d baseline=%d deltaRelin=%d deltaRescale=%d\n",
		roundNo, mode,
		stats.relin, stats.rescale, eagerBaseline,
		eagerBaseline-stats.relin, eagerBaseline-stats.rescale)
}

func (sm4 *SM4Ctr) logCipherPackFill() {
	sm4.logf(true, "[SM4][EncodeCiphertext] data is not full pack, fill with 0...\n")
}
