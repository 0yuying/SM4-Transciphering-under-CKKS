# SM4-CKKS Transciphering

This repository contains the artifact for the SM4-CKKS transciphering
experiments. The main implementation is `SM4-CKKS`, which evaluates SM4-CTR
under CKKS with Lazy-mod2 recovery. The other three implementations are kept as
isolated comparison baselines for the paper.

## Repository Layout

| Directory | Role in the paper | Purpose |
| --- | --- | --- |
| `SM4-BLEACH/ckks_sm4_xboot_1` | SM4-BLEACH comparison | Used to compare against the BLEACH-style baseline. |
| `SM4-XBOOT/ckks_sm4_xboot` | SM4-XBOOT comparison | Used to compare against XBOOT-based XOR recovery. |
| `SM4-LazySubByte/ckks_sm4_xboot_7` | SM4-LazySubByte comparison | Used to compare against the LazySubByte optimization. |
| `SM4-CKKS/ckks_sm4_lazymod2` | Main experiment | Our SM4-CKKS implementation with Lazy-mod2 recovery. |

The storage-oriented experiments associated with the main implementation are in
`SM4-CKKS/ckks_sm4_store`.

Each top-level experiment directory includes an isolated local copy of the
modified Lattigo dependency under `lattigo`. The Go modules use local `replace`
directives so that each implementation can be compiled from its own directory
without sharing dependency state with the other comparison variants.

## Main Contribution

The main artifact is **SM4-CKKS Transciphering: Lazy-mod2**. It is implemented
in `SM4-CKKS/ckks_sm4_lazymod2` and corresponds to the paper contribution.

- **LazyMod2 Recovery Mechanism.** We propose LazyMod2, which defers modular
  reduction to the CKKS bootstrapping stage in XOR evaluation. Instead of
  performing modular reduction after each homomorphic XOR accumulation,
  intermediate results are aggregated and the Least Significant Bit (LSB) is
  extracted only during the EvalMod step via a trigonometric approximation.
  This design reduces the computational overhead of chained XOR operations and
  is well suited to the long XOR accumulation paths encountered in SM4
  transciphering.
- **Optimized Lazy SubByte Evaluation for SM4.** We extend the Lazy SubByte
  technique to the SM4 round function by leveraging the structure of the
  nonlinear substitution `S` and the 32-bit linear diffusion layer. Instead of
  performing immediate relinearization and rescaling after each multiplication,
  we accumulate intermediate terms that contribute to the same output into
  shared buckets. This design reduces the latency of the SubByte component by
  approximately 30% compared with the LazySubByte baseline.
- **Packing Structure for SM4.** We design a bit-sliced SIMD packing strategy
  for SM4-CTR evaluation under CKKS, which enables homomorphic XOR via slot
  additions. For the nonlinear substitution, each 32-bit state is decomposed
  into four 8-bit words, allowing independent S-box instances to be evaluated
  in parallel across ciphertext slots. This packing strategy reduces redundant
  data reordering in homomorphic SM4 execution and improves the slot
  organization of SM4-CTR batching.

## Experimental Parameters

The main `SM4-CKKS` experiment uses the Lazy-mod2 profile documented in
`SM4-CKKS/ckks_sm4_lazymod2/README.md`.

Default `logN=12` profile:

| Parameter | Value |
| --- | --- |
| Scheme setting | CKKS, `LogN=12` |
| Main profile | `lazymod2-default` |
| `QCount` | `23` |
| `LogQP` | `1472.000000` |
| `LogDefaultScale` | `42` |
| q0 / EvalMod / CtS scale | `58` |
| Slot-domain scale | `42` |
| StC levels | `[1,1,1]` |
| CtS levels | `[1,1,1,1]` |
| Circuit reserve levels | `7` |
| `LogP` | `[59,59,60,60,60]` |
| Mod1 approximation | `CosDiscrete`, `K=16`, degree `30`, double-angle `3`, `LogMessageRatio=10` |
| Secret distributions | `Xs.H=192`, ephemeral secret weight `32` |

The `logN=12` profile is an experimental performance configuration for the
paper artifact. It is not presented as a 128-bit security parameter set.

## Go Installation and Configuration

Install Go 1.24.4 or a compatible newer Go release. The following commands
install the Go 1.24.4 binary distribution on Linux:

```bash
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
```

Add Go to your shell path if it is not already configured:

```bash
nano ~/.bashrc
```

Add:

```bash
export PATH=$PATH:/usr/local/go/bin
```

Reload the shell configuration:

```bash
source ~/.bashrc
go version
```

## Compile and Run

Run each experiment from its own module directory.

### SM4-CKKS, Lazy-mod2, `logN=12`

```bash
cd SM4-CKKS/ckks_sm4_lazymod2
go run main.go
```

Recommended benchmark command used for the main `logN=12` artifact:

```bash
cd SM4-CKKS/ckks_sm4_lazymod2
go run . -threads 32 -boot-workers 16 -sbox-workers 4
```

The included benchmark script runs several worker configurations and writes a
report under `benchmarks/`:

```bash
cd SM4-CKKS/ckks_sm4_lazymod2
./scripts/bench_sm4_n12.sh
```

### Comparison Experiments

```bash
cd SM4-BLEACH/ckks_sm4_xboot_1
go run main.go
```

```bash
cd SM4-XBOOT/ckks_sm4_xboot
go run main.go
```

```bash
cd SM4-LazySubByte/ckks_sm4_xboot_7
go run main.go
```

### Storage Experiments

```bash
cd SM4-CKKS/ckks_sm4_store
go run ./cmd/store_bench
```

Generated storage data and result files are intentionally ignored by Git. The
repository keeps only placeholder `.gitignore` files in generated data and
result directories.

## Notes for Reproducibility

- The four experiment directories are intentionally isolated because they
  correspond to different comparison targets and may depend on different local
  modifications of Lattigo.
- Large toolchain archives, paper PDFs, IDE files, notebook checkpoints, and
  unrelated experiments are excluded from this artifact repository.
- For detailed Lazy-mod2 boundary scans and profile descriptions, see
  `SM4-CKKS/ckks_sm4_lazymod2/README.md`.
