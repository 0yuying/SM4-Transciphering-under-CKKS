# SM4 XBOOT Experimental Profile

This module evaluates SM4-CTR with a single XBOOT schedule. The SM4 round
function, LSB-first layout, CTR APIs, and optimized ANF S-box are unchanged.
Integer parity carriers are reduced automatically by the
`DecodeThenModUp` bootstrapping path.

## Round Schedule

Each round executes:

1. `tmp = x1 + x2 + x3 + rk`
2. paired XBOOT on `tmp`
3. optimized ANF S-box
4. additive `L` layer and `x4 = x0 + L(Sbox(tmp))`
5. carry `x4` into the next round without a round-end bootstrap

The final stage adds each CTR ciphertext bit to the keystream carrier first,
then executes one paired XBOOT boundary.

| Carrier boundary | Maximum Boolean terms per output bit |
| --- | ---: |
| Round `tmp` before the S-box | `124` |
| Final keystream | `41` |
| Final CTR output before XBOOT | `42` |
| Double-load engineering checkpoint | `256` |

The 32-bit SM4 word width is not an XOR depth. The bound is counted per output
bit after following the actual linear aggregation path.

## Experimental Parameters

The shared builder is [`xbootparams/profile.go`](./xbootparams/profile.go).
Both the runtime and scanner use it so the modulus chain cannot drift.

| Setting | Value |
| --- | --- |
| Default profile | `LogN=12`, `LogScale=33` |
| Smoke profile | `LogN=9`, selected with `-short` |
| Circuit order | `DecodeThenModUp` |
| Mod1 | `CosDiscrete`, `K=12`, degree `120`, `LogMessageRatio=1` |
| Secret distributions | ephemeral weight `32`, `Xs.H=256` |
| StC levels | `[1]` |
| S-box reserve levels | `3` |
| CtS levels | `[1,1]` |

The default `LogN=12` profile is an experimental configuration. It is not
presented as a 128-bit security parameter set.

## Run

```bash
go test ./ckks_cipher ./xbootparams ./cmd/xboot_scan
go run . -short -threads 32 -boot-workers 16 -sbox-workers 4
go run . -threads 32 -boot-workers 16 -sbox-workers 4
```

## Boundary Scan

The scanner measures direct integer input, independently encrypted bit
accumulation, and correlated repeated-bit accumulation. CSV rows contain
pre-XBOOT and post-XBOOT error, wrong LSB slots, modulus-chain size, and time.

```bash
mkdir -p results
go run ./cmd/xboot_scan \
  -paired=true \
  -repeats 3 \
  -checkpoints 1,2,42,124,256 \
  -output results/xboot_boundary_summary.csv
```

To enumerate the two-stage profile grid:

```bash
go run ./cmd/xboot_scan -paired=true -grid -checkpoints 42,124,256
```

The grid covers scale `31,33,35,37,39,41`, StC `[1]` and `[1,1]`, S-box
reserve levels `3,4`, and CtS `[1,1]`, `[1,1,1]`, `[1,1,1,1]`.

## Default Profile Results

[`results/xboot_boundary_summary.csv`](./results/xboot_boundary_summary.csv)
contains three independent key generations. Every measured row has
`wrong_slots=0` and `over_1e-4_slots=0`. The table below records the most
conservative post-XBOOT maximum error across those repeats.

| Mode | `tau=42` | `tau=124` | `tau=256` |
| --- | ---: | ---: | ---: |
| direct integer input | `4.66390e-5` | `5.13727e-5` | `3.87203e-5` |
| independently encrypted bits | `3.58541e-5` | `3.82653e-5` | `3.66875e-5` |
| correlated repeated bit | `4.38003e-5` | `4.61853e-5` | `4.51971e-5` |

The 72-profile grid has 60 first-stage passes. Sorting by level count, `LogQP`,
and screening time selects `n12-s33-stc1-circuit3-cts2`: 14 Q levels,
`LogQP=635`, and a first-stage worst error of `4.68176e-5`.

The complete 32-round CTR round-trip passes for `LogN=9` smoke mode and for
three independent `LogN=12` default-profile key generations. The measured
`LogN=12` totals were `70.10s`, `70.76s`, and `70.35s`.

## Shared XBOOT Semantics

This branch changes the shared `mod1` approximation to the XBOOT LSB-recovery
transform. Generic upstream Lattigo precision tests that expect the original
continuous modular-reduction target are therefore not a compatibility oracle
for this branch. The module-level XBOOT regressions validate the intended
`tau=42,124,256` behavior directly.
