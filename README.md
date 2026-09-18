# SM4 Transciphering under CKKS

This is the code artifact for our SM4-CKKS transciphering experiments. The
main implementation locates in [`./SM4-CKKS/ckks_sm4_lazymod2`](./SM4-CKKS/ckks_sm4_lazymod2).

Our implementation is based on the open-source FHE library
[Lattigo v6.0](https://github.com/tuneinsight/lattigo). This repository keeps
isolated local copies of the modified Lattigo dependency for each experiment
group, so that the comparison implementations can be compiled independently.

The main contributions include the following aspects.

- **LazyMod2 Recovery Mechanism:** Integrates LSB extraction into the CKKS bootstrapping EvalMod stage through trigonometric approximation, reducing the overhead of chained XOR evaluation in SM4 transciphering.

- **Optimized Lazy SubByte Evaluation:** Improves the Lazy SubByte technique for SM4 using a bucket accumulation strategy, reducing redundant Relin/Rescale operations and accelerating nonlinear substitution evaluation.

- **Bit-Sliced Representation for SM4 Transciphering.:** Designs a bit-sliced SIMD packing strategy for SM4-CTR under CKKS, enabling efficient slot-wise XOR evaluation and parallel S-box computation with reduced data reordering overhead.

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



### Comparison schemes

The repository contains three isolated comparison implementations.

```
# SM4-BLEACH experiment for comparison with BLEACH [2]
./SM4-BLEACH/ckks_sm4_bleach

# SM4-XBOOT experiment for comparison with XBOOT [3]
./SM4-XBOOT/ckks_sm4_xboot

# SM4-LazySubByte experiment for comparison with LazySubByte [4]
./SM4-LazySubByte/ckks_sm4_lazysubbyte
```

Each experiment directory has its own `go.mod` and a local `../lattigo`
dependency. This separation avoids mixing the dependency changes used by
different baselines.

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
go run . -threads 32 -boot-workers 16 -sbox-workers 4 -logN 16
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
cd ./SM4-BLEACH/ckks_sm4_bleach
go run main.go
```

Running the SM4-XBOOT comparison:

```PowerShell
cd ./SM4-XBOOT/ckks_sm4_xboot
go run main.go
```

Running the SM4-LazySubByte comparison:

```PowerShell
cd ./SM4-LazySubByte/ckks_sm4_lazysubbyte
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

[2] Nir Drucker, Guy Moshkowich, Tomer Pelleg, and Hayim Shaul.
**BLEACH: Cleaning Errors in Discrete Computations over CKKS.**
IACR Cryptology ePrint Archive, 2022/1298, 2022.
https://eprint.iacr.org/2022/1298.

[3] Chao Niu, Zhicong Huang, Zhaomin Yang, Yi Chen, Liang Kong, Cheng Hong,
and Tao Wei.
**XBOOT: Free-XOR Gates for CKKS with Applications to Transciphering.**
IACR Transactions on Cryptographic Hardware and Embedded Systems, 2025(4),
118-144, 2025. https://doi.org/10.46586/TCHES.V2025.I4.118-144.

[4] Youngjin Bae, Jung Hee Cheon, Minsik Kang, and Taeseong Kim.
**High-Throughput AES Transciphering using CKKS: Less than 1ms.**
IACR Cryptology ePrint Archive, 2025/1865, 2025.
https://eprint.iacr.org/2025/1865.

## Disclaimer

This repository is organized for paper artifact evaluation and experimental
comparison. The `logN=12` parameter set is used for performance experiments and
is not claimed as a 128-bit security parameter set.

## License

Lattigo is licensed under the Apache 2.0 License. See
[`LICENSE`](./SM4-CKKS/lattigo/LICENSE) for the local copy included with the
main implementation.
