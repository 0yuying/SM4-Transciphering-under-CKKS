#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${PROJECT_DIR}/benchmarks"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
REPORT="${OUT_DIR}/sm4_n12_bench_${STAMP}.txt"

mkdir -p "${OUT_DIR}"

median3() {
  printf "%s\n%s\n%s\n" "$1" "$2" "$3" | sort -n | sed -n '2p'
}

extract_elapsed_seconds() {
  local logfile="$1"
  grep -Eo 'elapsed=[0-9]+(\.[0-9]+)?' "${logfile}" | tail -n 1 | cut -d'=' -f2
}

extract_round_avg_seconds() {
  local logfile="$1"
  awk '
    /\[SM4\]\[Round [0-9][0-9]\] done in / { sum += $5; cnt++ }
    END {
      if (cnt == 0) {
        print "NaN"
      } else {
        printf "%.3f", (sum / cnt) / 1000.0
      }
    }
  ' "${logfile}"
}

loadavg1="unknown"
if [[ -r /proc/loadavg ]]; then
  loadavg1="$(awk '{print $1}' /proc/loadavg)"
fi

governor="unknown"
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
  governor="$(tr -d '\n' < /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
fi

cat > "${REPORT}" <<EOF
# SM4-CKKS N=12 Benchmark
Timestamp (UTC): ${STAMP}
Host: $(hostname)
CPU logical: $(nproc)
LoadAvg1: ${loadavg1}
Governor: ${governor}

Command matrix (3 runs each):
1) go run . -threads 32 -boot-workers 16 -sbox-workers 4
2) go run . -threads 24 -boot-workers 16 -sbox-workers 4
3) go run . -threads 32 -boot-workers 8  -sbox-workers 4

Result columns:
- median_elapsed_s: median of total elapsed seconds from 'elapsed='
- median_round_avg_s: median of per-run average round time from '[Round xx] done in ...'

EOF

run_case() {
  local threads="$1"
  local boot="$2"
  local sbox="$3"

  local elapsed_vals=()
  local round_vals=()

  echo "== Case threads=${threads} boot-workers=${boot} sbox-workers=${sbox} ==" | tee -a "${REPORT}"

  for run in 1 2 3; do
    local logfile="${OUT_DIR}/raw_n12_t${threads}_b${boot}_s${sbox}_run${run}_${STAMP}.log"
    echo "  -> run ${run}/3 : ${logfile}" | tee -a "${REPORT}"

    (
      cd "${PROJECT_DIR}"
      TIMEFORMAT='elapsed=%3R'
      time go run . -threads "${threads}" -boot-workers "${boot}" -sbox-workers "${sbox}"
    ) > "${logfile}" 2>&1

    local elapsed
    local round_avg
    elapsed="$(extract_elapsed_seconds "${logfile}")"
    round_avg="$(extract_round_avg_seconds "${logfile}")"
    elapsed_vals+=("${elapsed}")
    round_vals+=("${round_avg}")
    echo "     elapsed_s=${elapsed} round_avg_s=${round_avg}" | tee -a "${REPORT}"
  done

  local med_elapsed
  local med_round
  med_elapsed="$(median3 "${elapsed_vals[0]}" "${elapsed_vals[1]}" "${elapsed_vals[2]}")"
  med_round="$(median3 "${round_vals[0]}" "${round_vals[1]}" "${round_vals[2]}")"

  echo "  => median_elapsed_s=${med_elapsed} median_round_avg_s=${med_round}" | tee -a "${REPORT}"
  echo | tee -a "${REPORT}"
}

run_case 32 16 4
run_case 24 16 4
run_case 32 8 4

echo "Benchmark report saved to: ${REPORT}"
