package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/lazymod2params"
	"github.com/tuneinsight/lattigo/v6/ckks_sm4_xboot/lazymod2scan"
)

type profileWithCost struct {
	profile lazymod2params.Profile
	logQP   float64
	qCount  int
	err     error
}

func main() {
	logN := flag.Int("logN", lazymod2params.DefaultLogN, "experimental CKKS LogN")
	profilesFlag := flag.String("profiles", "default", "default, baseline, mod1-grid, or chain-grid")
	seedFlag := flag.String("seed", "default", "seed profile for chain-grid: default or baseline")
	customSlotScale := flag.Int("slot-scale", 30, "custom profile slot-domain scale")
	customHighScale := flag.Int("high-scale", 46, "custom profile q0/EvalMod/CtS scale")
	customStC := flag.String("stc-levels", "1", "custom profile StC levels separated by ':'")
	customCircuit := flag.Int("circuit-levels", 7, "custom profile circuit reserve levels")
	customCtS := flag.String("cts-levels", "1", "custom profile CtS levels separated by ':'")
	customPLog := flag.Int("p-log", 47, "custom profile P prime bit-size")
	customPCount := flag.Int("p-count", 2, "custom profile P prime count")
	customK := flag.Int("mod1-k", 16, "custom profile Mod1 K")
	customDegree := flag.Int("mod1-degree", 30, "custom profile Mod1 degree")
	customDoubleAngle := flag.Int("mod1-double-angle", 3, "custom profile Mod1 double-angle count")
	customRatio := flag.Int("log-message-ratio", 10, "custom profile LogMessageRatio")
	modesFlag := flag.String("modes", "direct,independent,correlated", "comma-separated scan modes")
	checkpointsFlag := flag.String("checkpoints", "41,124,256", "comma-separated carrier sizes")
	repeats := flag.Int("repeats", 1, "independent key generations")
	paired := flag.Bool("paired", true, "use production paired BootstrapCmplxThenDivideLazyMod2")
	threads := flag.Int("threads", runtime.NumCPU(), "GOMAXPROCS")
	maxCandidates := flag.Int("max-candidates", 0, "cap candidate count after sorting; zero means all")
	oneRound := flag.Bool("one-round", false, "run a single SM4 round level validation after boundary scans")
	output := flag.String("output", "", "optional CSV output path")
	resume := flag.Bool("resume", false, "skip measurement rows already present in output")
	flag.Parse()

	if *threads < 1 {
		*threads = 1
	}
	runtime.GOMAXPROCS(*threads)
	if *repeats < 1 {
		panic("repeats must be positive")
	}

	custom := customProfile(*logN, *customSlotScale, *customHighScale, *customStC, *customCircuit, *customCtS, *customPLog, *customPCount, *customK, *customDegree, *customDoubleAngle, *customRatio)
	profiles := sortProfiles(buildProfiles(*profilesFlag, *seedFlag, *logN, custom), *maxCandidates)
	modes := mustCSVStrings(*modesFlag)
	checkpoints := mustCSVInts(*checkpointsFlag)

	seen := map[string]bool{}
	if *resume && *output != "" {
		seen = readSeen(*output)
	}

	out := io.Writer(os.Stdout)
	var file *os.File
	if *output != "" {
		var err error
		file, err = os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		if stat, err := file.Stat(); err == nil && stat.Size() == 0 {
			writer := csv.NewWriter(file)
			writeHeader(writer)
			writer.Flush()
		}
		out = io.MultiWriter(os.Stdout, file)
	}

	writer := csv.NewWriter(out)
	if *output == "" {
		writeHeader(writer)
	}
	defer writer.Flush()

	for _, candidate := range profiles {
		if candidate.err != nil {
			writeBuildFailed(writer, candidate.profile, candidate.err)
			continue
		}
		for repeat := 1; repeat <= *repeats; repeat++ {
			ctx, err := lazymod2scan.NewContext(candidate.profile, *paired)
			if err != nil {
				writeBuildFailed(writer, candidate.profile, err)
				break
			}
			var all []lazymod2scan.Measurement
			for _, mode := range modes {
				pending := pendingCheckpoints(seen, repeat, candidate.profile.Name, mode, checkpoints)
				if len(pending) == 0 {
					continue
				}
				results, err := ctx.Scan(mode, pending)
				if err != nil {
					writeFailure(writer, repeat, candidate.profile, mode, err)
					continue
				}
				for _, result := range results {
					writeMeasurement(writer, repeat, ctx, result)
					seen[rowKey(repeat, candidate.profile.Name, result.Mode, result.Terms)] = true
				}
				all = append(all, results...)
				writer.Flush()
			}
			if *oneRound && ctx.PassesRequired(all) {
				err := ctx.ValidateOneRound()
				writeOneRound(writer, repeat, ctx, err)
				writer.Flush()
			}
		}
	}
}

func pendingCheckpoints(seen map[string]bool, repeat int, profile, mode string, checkpoints []int) []int {
	pending := make([]int, 0, len(checkpoints))
	for _, terms := range checkpoints {
		if !seen[rowKey(repeat, profile, mode, terms)] {
			pending = append(pending, terms)
		}
	}
	return pending
}

func buildProfiles(kind, seed string, logN int, custom lazymod2params.Profile) []lazymod2params.Profile {
	switch kind {
	case "default":
		return []lazymod2params.Profile{lazymod2params.Default(logN)}
	case "baseline":
		return []lazymod2params.Profile{lazymod2params.Baseline(logN)}
	case "custom":
		return []lazymod2params.Profile{custom}
	case "mod1-grid":
		return lazymod2params.Mod1Grid(logN)
	case "chain-grid":
		return lazymod2params.ChainGrid(seedProfile(seed, logN))
	default:
		panic("unknown profiles mode: " + kind)
	}
}

func customProfile(logN, slotScale, highScale int, stcText string, circuit int, ctsText string, pLog, pCount, k, degree, doubleAngle, ratio int) lazymod2params.Profile {
	p := lazymod2params.Baseline(logN)
	p.Name = fmt.Sprintf("custom-s%d-h%d-stc%s-c%d-cts%s-p%dx%d-k%d-d%d-da%d-r%d",
		slotScale, highScale, strings.ReplaceAll(stcText, ":", ""), circuit, strings.ReplaceAll(ctsText, ":", ""), pCount, pLog, k, degree, doubleAngle, ratio)
	p.LogDefaultScale = slotScale
	p.Q0LogScale = highScale
	p.SlotLogScale = slotScale
	p.HighLogScale = highScale
	p.SlotsToCoeffsLevels = mustColonInts(stcText)
	p.CircuitLevels = circuit
	p.CoeffsToSlotsLevels = mustColonInts(ctsText)
	p.LogP = nil
	p.PLogScale = pLog
	p.PCount = pCount
	p.Mod1K = k
	p.Mod1Degree = degree
	p.Mod1DoubleAngle = doubleAngle
	p.LogMessageRatio = ratio
	return p
}

func seedProfile(seed string, logN int) lazymod2params.Profile {
	switch seed {
	case "default":
		return lazymod2params.Default(logN)
	case "baseline":
		return lazymod2params.Baseline(logN)
	default:
		panic("unknown seed profile: " + seed)
	}
}

func sortProfiles(profiles []lazymod2params.Profile, limit int) []profileWithCost {
	candidates := make([]profileWithCost, 0, len(profiles))
	for _, profile := range profiles {
		logQP, qCount := approximateCost(profile)
		candidates = append(candidates, profileWithCost{profile: profile, logQP: logQP, qCount: qCount})
		if limit > 0 && len(candidates) > limit*4 {
			candidates = trimCandidates(candidates, limit)
		}
	}
	return trimCandidates(candidates, limit)
}

func approximateCost(profile lazymod2params.Profile) (float64, int) {
	logQ := profile.LogQ()
	logP := profile.LogPList()
	total := 0
	for _, value := range logQ {
		total += value
	}
	for _, value := range logP {
		total += value
	}
	return float64(total), len(logQ)
}

func trimCandidates(candidates []profileWithCost, limit int) []profileWithCost {
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if (a.err == nil) != (b.err == nil) {
			return a.err == nil
		}
		if a.logQP != b.logQP {
			return a.logQP < b.logQP
		}
		if a.qCount != b.qCount {
			return a.qCount < b.qCount
		}
		return a.profile.Name < b.profile.Name
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func writeHeader(writer *csv.Writer) {
	_ = writer.Write([]string{
		"record", "repeat", "profile", "logN", "q_count", "log_qp", "mode", "terms",
		"pre_max_error", "pre_avg_error", "post_max_error", "post_avg_error",
		"wrong_slots", "over_tolerance_slots", "output_level", "duration",
		"log_default_scale", "q0_log_scale", "slot_log_scale", "high_log_scale",
		"stc_levels", "circuit_levels", "cts_levels", "log_p",
		"mod1_k", "mod1_degree", "mod1_double_angle", "log_message_ratio", "error",
	})
}

func writeBuildFailed(writer *csv.Writer, profile lazymod2params.Profile, err error) {
	row := baseRow("build-failed", 0, profile, 0, 0, "", 0)
	row[len(row)-1] = err.Error()
	_ = writer.Write(row)
	writer.Flush()
}

func writeFailure(writer *csv.Writer, repeat int, profile lazymod2params.Profile, mode string, err error) {
	row := baseRow("scan-failed", repeat, profile, 0, 0, mode, 0)
	row[len(row)-1] = err.Error()
	_ = writer.Write(row)
	writer.Flush()
}

func writeOneRound(writer *csv.Writer, repeat int, ctx *lazymod2scan.Context, err error) {
	row := baseRow("one-round", repeat, ctx.Profile, ctx.Params.QCount(), ctx.Params.LogQP(), "", 0)
	if err != nil {
		row[len(row)-1] = err.Error()
	} else {
		row[len(row)-1] = "pass"
	}
	_ = writer.Write(row)
}

func writeMeasurement(writer *csv.Writer, repeat int, ctx *lazymod2scan.Context, result lazymod2scan.Measurement) {
	row := baseRow("measurement", repeat, ctx.Profile, ctx.Params.QCount(), ctx.Params.LogQP(), result.Mode, result.Terms)
	row[8] = fmt.Sprintf("%.8e", result.PreMaxError)
	row[9] = fmt.Sprintf("%.8e", result.PreAvgError)
	row[10] = fmt.Sprintf("%.8e", result.PostMaxError)
	row[11] = fmt.Sprintf("%.8e", result.PostAvgError)
	row[12] = strconv.Itoa(result.WrongSlots)
	row[13] = strconv.Itoa(result.OverTolerance)
	row[14] = strconv.Itoa(result.OutputLevel)
	row[15] = result.Duration.String()
	_ = writer.Write(row)
}

func baseRow(record string, repeat int, profile lazymod2params.Profile, qCount int, logQP float64, mode string, terms int) []string {
	fields := profile.CSVFields()
	return []string{
		record,
		strconv.Itoa(repeat),
		profile.Name,
		strconv.Itoa(profile.LogN),
		strconv.Itoa(qCount),
		fmt.Sprintf("%.6f", logQP),
		mode,
		strconv.Itoa(terms),
		"", "", "", "", "", "", "", "",
		fields[2],
		fields[3],
		fields[4],
		fields[5],
		fields[6],
		fields[7],
		fields[8],
		fields[9],
		fields[10],
		fields[11],
		fields[12],
		fields[13],
		"",
	}
}

func readSeen(path string) map[string]bool {
	seen := map[string]bool{}
	file, err := os.Open(path)
	if err != nil {
		return seen
	}
	defer file.Close()
	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil || len(rows) < 2 {
		return seen
	}
	for _, row := range rows[1:] {
		if len(row) < 8 || row[0] != "measurement" {
			continue
		}
		repeat, _ := strconv.Atoi(row[1])
		terms, _ := strconv.Atoi(row[7])
		seen[rowKey(repeat, row[2], row[6], terms)] = true
	}
	return seen
}

func rowKey(repeat int, profile, mode string, terms int) string {
	return fmt.Sprintf("%d/%s/%s/%d", repeat, profile, mode, terms)
}

func mustCSVStrings(text string) []string {
	var out []string
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		panic("list must not be empty")
	}
	return out
}

func mustCSVInts(text string) []int {
	var out []int
	for _, item := range mustCSVStrings(text) {
		value, err := strconv.Atoi(item)
		if err != nil || value < 1 {
			panic("checkpoints must be positive integers")
		}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func mustColonInts(text string) []int {
	text = strings.ReplaceAll(text, ",", ":")
	var out []int
	for _, item := range strings.Split(text, ":") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		value, err := strconv.Atoi(item)
		if err != nil || value < 1 {
			panic("levels must be positive integers: " + text)
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		panic("levels must not be empty")
	}
	return out
}
