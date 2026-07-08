# CKKS and SM4 Upload Storage Benchmark

本模块参考论文 `tfhe-aes.pdf` 的两套数据组织方式，比较客户端生成可上传密文时的
吞吐量、平均时延、通信量和存储量。它不执行模型推理、服务端 SM4-to-CKKS 同态转密、
数据库 CRUD 或真实网络传输。

比较三条路径：

- `direct_ckks`：每个逻辑事务独立进行 CKKS 编码、加密和序列化。
- `sm4_compact_ctr`：使用紧凑原始字节布局执行 SM4-CTR。
- `sm4_slot_ready_ctr`：每个标量占用一个 16-byte SM4 block，便于未来接入逐 slot 同态转密。

## Datasets

数据准备脚本读取 `../ckks_sm4_apply_data`：

- LendingClub：读取 `loan_data_2007_2014.csv` 的前 `10000` 个 `loan_amnt`。一个金额是一条事务。
- Olivetti Faces：读取 `olivettifaces.mat` 的全部 `400` 张 `64x64` 灰度图片。一张图片是一条事务。

生成的数据位于 `./data/generated`，默认不会提交到 Git：

```bash
cd ckks_sm4_store
python3 ./scripts/prepare_data.py
```

SM4 路径为每个数据集和布局派生独立 IV，并在事务之间连续推进 CTR counter。每条
SM4 路径额外计入一次 `16 B` IV 元数据。公共 ID、密钥和 CKKS 参数不计入路径特有
开销。

## Run

快速冒烟验证：

```bash
go run ./cmd/store_bench -preset quick
```

默认实验使用 `workers=1,4,8,16`，每组运行 `3` 次：

```bash
go run ./cmd/store_bench -preset default
```

论文风格实验使用相同 worker 矩阵，每组运行 `10` 次：

```bash
go run ./cmd/store_bench -preset paper
```

开发时可限制每套数据集的事务数量：

```bash
go run ./cmd/store_bench -preset quick -limit 8
```

可覆盖参数：

```text
-dataset   all, loan, faces
-workers   逗号分隔的 worker 数，例如 1,4,8,16
-runs      每个组合的运行次数
-limit     每套数据集最多处理的事务数
-logN      CKKS logN，默认 12
-key-hex   16-byte SM4 key
-iv-hex    16-byte SM4 base IV
-data-dir  数据准备目录
-out-dir   报告输出目录
```

## Metrics

终端会输出汇总行，完整结果写入 `./results/store_bench_<timestamp>.json` 和 `.csv`。

主要字段：

- `logical_transactions`：贷款金额数量或图片数量。
- `ciphertext_objects`：实际生成的密文对象数量。默认 `logN=12` 时，每张人脸拆为两个 CKKS 密文。
- `upload_bytes`、`stored_bytes`：可上传密文序列化后的真实字节数。
- `storage_expansion_ratio`：`stored_bytes / plaintext_bytes`。
- `average_latency`：并发执行时每条事务在客户端的平均处理时延。
- `transactions_per_second`：`logical_transactions / wall-clock total_duration`。
- `upload_preparation_mib_per_second`：客户端生成可上传密文的字节率，不代表真实网络带宽。

`direct_ckks` 使用 Lattigo `Ciphertext.BinarySize()` 和 `WriteTo(io.Discard)` 统计真实序列化
开销，不会在磁盘写入数 GB 密文。SM4 紧凑布局的理论总量为：

```text
loan:  10000 * 2 B    + 16 B IV = 20016 B
faces: 400 * 4096 B   + 16 B IV = 1638416 B
```

SM4 转密就绪布局的理论总量为：

```text
loan:  10000 * 16 B       + 16 B IV = 160016 B
faces: 400 * 4096 * 16 B  + 16 B IV = 26214416 B
```

## Verify

```bash
cd ../ckks_sm4_lazymod2
go test ./ckks_cipher

cd ../ckks_sm4_store
go test ./...
python3 ./scripts/prepare_data.py
go run ./cmd/store_bench -preset quick -limit 8
```

```bash
go run ./cmd/store_bench -preset quick
go run ./cmd/store_bench -preset default
go run ./cmd/store_bench -preset paper
```

quick:   6 组结果，每组运行 1 次
default: 24 组结果，每组运行 3 次后取平均
paper:   24 组结果，每组运行 10 次后取平均