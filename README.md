# SM4-CKKS Transciphering with Lazy-mod2 Recovery

This is the code artifact for our SM4-CKKS transciphering experiments. The
main implementation is named ***SM4-CKKS Transciphering: Lazy-mod2*** and is
located in [`./SM4-CKKS/ckks_sm4_lazymod2`](./SM4-CKKS/ckks_sm4_lazymod2).

Our implementation is based on the open-source FHE library
[Lattigo v6.0](https://github.com/tuneinsight/lattigo). This repository keeps
isolated local copies of the modified Lattigo dependency for each experiment
group, so that the comparison implementations can be compiled independently.

## Golang installation and configuration

Downloading the Go binary distribution:

```PowerShell
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
```

Delete the existing Golang, and unzip the downloaded file into the environment:

```PowerShell
sudo rm -rf /usr/local/go        # delete old version if exists
sudo tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
```

Editing the shell file and adding the following command (if not existing):

```PowerShell
nano ~/.bashrc
export PATH=$PATH:/usr/local/go/bin
```

Saving and enabling:

```PowerShell
source ~/.bashrc
go version
```

## General information about the code structure

### SM4-CKKS main transciphering scheme

This part is located at

```
# Main SM4-CKKS Lazy-mod2 implementation
./SM4-CKKS/ckks_sm4_lazymod2

# LazyMod2 parameter profiles and boundary scans
./SM4-CKKS/ckks_sm4_lazymod2/lazymod2params
./SM4-CKKS/ckks_sm4_lazymod2/lazymod2scan

# SM4 circuit, S-box, and CKKS transciphering code
./SM4-CKKS/ckks_sm4_lazymod2/ckks_cipher

# Storage experiments associated with the main implementation
./SM4-CKKS/ckks_sm4_store
```

The main contribution includes the following functionalities.

- LazyMod2 recovery for homomorphic XOR evaluation in CKKS bootstrapping.
- LazySubByte-style bucketed evaluation adapted to the SM4 S-box and diffusion
  layer.
- Bit-sliced SIMD packing for SM4-CTR, where XOR operations are represented by
  slot additions.

### Comparison schemes

The repository contains three isolated comparison implementations.

```
# SM4-BLEACH experiment for comparison with BLEACH
./SM4-BLEACH/ckks_sm4_xboot_1

# SM4-XBOOT experiment for comparison with XBOOT
./SM4-XBOOT/ckks_sm4_xboot

# SM4-LazySubByte experiment for comparison with LazySubByte
./SM4-LazySubByte/ckks_sm4_xboot_7
```

Each experiment directory has its own `go.mod` and a local `../lattigo`
dependency. This separation avoids mixing the dependency changes used by
different baselines.

## Experimental parameters

The main `SM4-CKKS` experiment uses the default Lazy-mod2 profile with
`logN=12`.

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
artifact. It is not presented as a 128-bit security parameter set.

More detailed Lazy-mod2 profile information is given in
[`./SM4-CKKS/ckks_sm4_lazymod2/README.md`](./SM4-CKKS/ckks_sm4_lazymod2/README.md).

## Compile and Run SM4-CKKS

An example of running the `logN=12` SM4-CKKS Lazy-mod2 implementation is given
below.

```PowerShell
cd ./SM4-CKKS/ckks_sm4_lazymod2
go run main.go
```

Recommended benchmark command:

```PowerShell
cd ./SM4-CKKS/ckks_sm4_lazymod2
go run . -threads 32 -boot-workers 16 -sbox-workers 4
```

The benchmark script runs several worker configurations and writes reports
under `./SM4-CKKS/ckks_sm4_lazymod2/benchmarks`.

```PowerShell
cd ./SM4-CKKS/ckks_sm4_lazymod2
./scripts/bench_sm4_n12.sh
```

## Compile and Run comparison experiments

Running the SM4-BLEACH comparison:

```PowerShell
cd ./SM4-BLEACH/ckks_sm4_xboot_1
go run main.go
```

Running the SM4-XBOOT comparison:

```PowerShell
cd ./SM4-XBOOT/ckks_sm4_xboot
go run main.go
```

Running the SM4-LazySubByte comparison:

```PowerShell
cd ./SM4-LazySubByte/ckks_sm4_xboot_7
go run main.go
```

## Storage experiments

The storage experiments are kept with the main SM4-CKKS implementation.

```PowerShell
cd ./SM4-CKKS/ckks_sm4_store
go run ./cmd/store_bench
```

Generated storage data and result files are intentionally ignored by Git. The
repository keeps only placeholder `.gitignore` files in generated data and
result directories.

## References

[1] Lattigo v6.0. Online: https://github.com/tuneinsight/lattigo.

## Disclaimer

This repository is organized for paper artifact evaluation and experimental
comparison. The `logN=12` parameter set is used for performance experiments and
is not claimed as a 128-bit security parameter set.

## License

Lattigo is licensed under the Apache 2.0 License. See
[`LICENSE`](./SM4-CKKS/lattigo/LICENSE) for the local copy included with the
main implementation.
