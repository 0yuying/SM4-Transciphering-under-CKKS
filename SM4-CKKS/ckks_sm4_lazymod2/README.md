# SM4 CKKS LazyMod2 Experimental Profile

This module keeps the existing SM4-CTR algorithm, bit order, one-boot LazyMod2
round schedule, and optimized ANF S-box. The parameter work here only changes
the CKKS bootstrapping/modulus chain used by `ckks_sm4_lazymod2`.

`LogN=12` is an experimental configuration and is not presented as a 128-bit
security parameter set.

## Profiles

The shared builder is `lazymod2params/profile.go`.

| Profile | Purpose | QCount | LogQP | Notes |
| --- | --- | ---: | ---: | --- |
| `lazymod2-default` | default runtime profile | 23 | 1472.000000 | selected for full SM4 speed and correctness |
| `lazymod2-baseline` | old parameter chain | 25 | 1556.000001 | available through `-profile baseline` |
| `lazymod2-critical-boundary` | smallest observed bare LazyMod2 boundary | 18 | 730.999692 | passes boundary scans but fails full SM4 |

Default profile:

| Setting | Value |
| --- | --- |
| `LogDefaultScale` | 42 |
| q0 / EvalMod / CtS scale | 58 |
| slot-domain scale | 42 |
| StC levels | `[1,1,1]` |
| circuit reserve levels | 7 |
| CtS levels | `[1,1,1,1]` |
| `LogP` | `[59,59,60,60,60]` |
| Mod1 | `CosDiscrete`, `K=16`, degree `30`, double-angle `3`, `LogMessageRatio=10` |
| secret distributions | `Xs.H=192`, ephemeral secret weight `32` |

## LazyMod2 Boundary

The SM4 one-boot carrier bounds are unchanged:

| Boundary | Maximum integer carrier |
| --- | ---: |
| round `tmp = x1 + x2 + x3 + rk` | 124 |
| final keystream before final LazyMod2 bootstrap | 41 |
| final CTR XOR after bootstrap | `{0,1,2}` through explicit `Mod2Reduce2New` |

The slot-packed scanner checks three modes:

- `direct`: encrypted integer carriers
- `independent`: accumulated independent encrypted bits
- `correlated`: repeated addition of the same encrypted bit

The pass gate is LSB recoverability: all slots must round to the correct bit
and the target bit distance must stay below `0.45`. `tau=256` is recorded as a
non-blocking double-load margin.

Key findings:

| Candidate | LogQP | Result |
| --- | ---: | --- |
| `slot=29, high=46, P=2x47` | 786.000462 | fails boundary |
| `slot=30, high=45, P=2x46` | 781.999637 | fails boundary |
| `slot=30, high=46, P=1x30` | 729.999945 | first observed `P` failure |
| `slot=30, high=46, P=1x31` | 730.999692 | passes boundary and one-round level validation, but fails full SM4 |
| default `slot=42, high=58, circuit=7` | 1472.000000 | passes boundary and full SM4 |

The conclusion is that the bare LazyMod2 bootstrap has a much smaller numerical
boundary than the complete 32-round SM4 circuit can safely use. For production
runtime in this module, the default is therefore the fastest full-SM4-verified
profile, not the smallest bare-bootstrap profile.

## Results

Summary CSV: `results/lazymod2_search_summary.csv`

Full 32-round SM4-CTR, `-threads 32 -boot-workers 16 -sbox-workers 4`:

| Profile | Total | Rounds | Final boot | Round-trip |
| --- | ---: | ---: | ---: | --- |
| baseline | 80.515s | 67.737s | 5.688s | true |
| default run 1 | 65.781s | 54.991s | 4.826s | true |
| default run 2 | 65.825s | 55.095s | 4.776s | true |
| default run 3 | 66.127s | 55.359s | 4.840s | true |
| critical boundary | 262.474s | 230.562s | 27.178s | false |

Default vs baseline:

- LogQP: `1556.000001 -> 1472.000000`
- QCount: `25 -> 23`
- median total runtime: `80.515s -> 65.825s`
- median round runtime: `67.737s -> 55.095s`

## Run

```bash
go test ./lazymod2params ./lazymod2scan ./cmd/lazymod2_scan ./ckks_cipher
go run . -threads 32 -boot-workers 16 -sbox-workers 4
go run . -profile baseline -threads 32 -boot-workers 16 -sbox-workers 4
go run . -short -threads 32 -boot-workers 16 -sbox-workers 4
```

Boundary scan examples:

```bash
go run ./cmd/lazymod2_scan \
  -profiles default \
  -modes direct,independent,correlated \
  -checkpoints 41,124,256 \
  -one-round=true

go run ./cmd/lazymod2_scan \
  -profiles chain-grid \
  -seed baseline \
  -modes direct \
  -checkpoints 41,124 \
  -max-candidates 80
```
