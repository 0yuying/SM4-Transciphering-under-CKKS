# SM4-CKKS Transciphering

This repository contains the SM4 transciphering implementations used for the
paper experiments. `SM4-CKKS` is the main implementation and contribution; the
other directories are isolated comparison baselines.

## Implementations

| Directory | Implementation | Source |
| --- | --- | --- |
| `SM4-BLEACH/ckks_sm4_xboot_1` | SM4-BLEACH | `sm4-ckks-transciphering-baseline/BtR_framework/ckks_sm4_xboot_1` |
| `SM4-XBOOT/ckks_sm4_xboot` | SM4-XBOOT | `sm4-ckks-transciphering-sm4-ckks-60/ckks_sm4_xboot` |
| `SM4-LazySubByte/ckks_sm4_xboot_7` | SM4-LazySubByte | `sm4-ckks-transciphering-baseline/BtR_framework/ckks_sm4_xboot_7` |
| `SM4-CKKS/ckks_sm4_lazymod2` | SM4-CKKS | `sm4-ckks-transciphering-sm4-ckks-60/ckks_sm4_lazymod2` |
| `SM4-CKKS/ckks_sm4_store` | SM4-CKKS storage experiments | `sm4-ckks-transciphering-sm4-ckks-60/ckks_sm4_store` |

Each implementation group includes its own local `lattigo` copy. The
implementation `go.mod` files use local `replace` directives so experiments can
be built from their own directory without sharing modified dependency code with
another implementation.

## Running

Install Go 1.21 or newer. Then run commands from the implementation directory.

```bash
cd SM4-BLEACH/ckks_sm4_xboot_1
go test ./...
go run .
```

```bash
cd SM4-XBOOT/ckks_sm4_xboot
go test ./...
go run .
./scripts/bench_sm4_n12.sh
```

```bash
cd SM4-LazySubByte/ckks_sm4_xboot_7
go test ./...
go run .
```

```bash
cd SM4-CKKS/ckks_sm4_lazymod2
go test ./...
go test ./lazymod2params ./lazymod2scan ./ckks_cipher
go run .
./scripts/bench_sm4_n12.sh
```

```bash
cd SM4-CKKS/ckks_sm4_store
go test ./...
go run ./cmd/store_bench
```

## Repository Notes

- `SM4-CKKS` is the primary contribution implementation.
- `SM4-CKKS/ckks_sm4_store` is kept with the main implementation because it
  depends on the LazyMod2 SM4-CKKS code.
- Generated storage data and benchmark output are ignored. Only placeholder
  `.gitignore` files are kept under generated data/results directories.
- Large toolchain archives, paper PDFs, IDE files, notebook checkpoints, and
  unrelated experiments are intentionally excluded.
