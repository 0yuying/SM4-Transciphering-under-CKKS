#!/usr/bin/env python3
"""Prepare deterministic LendingClub and Olivetti payloads for store benchmarks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from decimal import Decimal
from pathlib import Path

import numpy as np
from scipy.io import loadmat


SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_DIR = SCRIPT_DIR.parent
REPO_DIR = MODULE_DIR.parent
DEFAULT_SOURCE_DIR = REPO_DIR / "ckks_sm4_apply_data"
DEFAULT_OUTPUT_DIR = MODULE_DIR / "data" / "generated"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_loan(path: Path, limit: int) -> tuple[bytes, dict[str, object]]:
    values: list[int] = []
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if "loan_amnt" not in (reader.fieldnames or []):
            raise ValueError(f"{path} does not contain loan_amnt")
        for row in reader:
            if len(values) == limit:
                break
            amount = Decimal(row["loan_amnt"])
            if amount != amount.to_integral_value():
                raise ValueError(f"loan_amnt must be integral, got {amount}")
            value = int(amount)
            if value < 0 or value > 0xFFFF:
                raise ValueError(f"loan_amnt must fit uint16, got {value}")
            values.append(value)
    if len(values) != limit:
        raise ValueError(f"{path} contains only {len(values)} rows, want {limit}")
    payload = b"".join(struct.pack(">H", value) for value in values)
    return payload, {
        "transactions": len(values),
        "scalar_bytes": 2,
        "scalars_per_transaction": 1,
        "plaintext_bytes": len(payload),
        "min": min(values),
        "max": max(values),
    }


def prepare_faces(path: Path) -> tuple[bytes, dict[str, object]]:
    mat = loadmat(path)
    if "faces" not in mat:
        raise ValueError(f"{path} does not contain faces")
    faces = np.asarray(mat["faces"])
    if faces.shape != (4096, 400):
        raise ValueError(f"faces shape={faces.shape}, want (4096, 400)")
    if not np.issubdtype(faces.dtype, np.integer):
        raise ValueError(f"faces dtype={faces.dtype}, want integer pixels")
    if int(faces.min()) < 0 or int(faces.max()) > 0xFF:
        raise ValueError("faces pixels must fit uint8")
    images = np.ascontiguousarray(faces.T, dtype=np.uint8)
    payload = images.tobytes(order="C")
    return payload, {
        "transactions": int(images.shape[0]),
        "scalar_bytes": 1,
        "scalars_per_transaction": int(images.shape[1]),
        "plaintext_bytes": len(payload),
        "min": int(images.min()),
        "max": int(images.max()),
    }


def write_dataset(output_dir: Path, filename: str, payload: bytes, metadata: dict[str, object]) -> dict[str, object]:
    path = output_dir / filename
    path.write_bytes(payload)
    written = path.read_bytes()
    if written != payload:
        raise RuntimeError(f"verification failed after writing {path}")
    return {
        "file": filename,
        **metadata,
        "sha256": sha256_bytes(payload),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--loan-limit", type=int, default=10000)
    args = parser.parse_args()
    if args.loan_limit <= 0:
        raise ValueError("--loan-limit must be positive")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    loan_source = args.source_dir / "loan_data_2007_2014.csv"
    faces_source = args.source_dir / "olivettifaces.mat"
    loan_payload, loan_metadata = prepare_loan(loan_source, args.loan_limit)
    faces_payload, faces_metadata = prepare_faces(faces_source)
    manifest = {
        "version": 1,
        "sources": {
            "loan": {"file": str(loan_source), "sha256": sha256_file(loan_source)},
            "faces": {"file": str(faces_source), "sha256": sha256_file(faces_source)},
        },
        "datasets": {
            "loan": write_dataset(args.out_dir, "loan_amnt_u16be.bin", loan_payload, loan_metadata),
            "faces": write_dataset(args.out_dir, "olivetti_faces_u8.bin", faces_payload, faces_metadata),
        },
    }
    manifest_path = args.out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    for name, metadata in manifest["datasets"].items():
        print(
            f"{name}: transactions={metadata['transactions']} "
            f"plaintext_bytes={metadata['plaintext_bytes']} sha256={metadata['sha256']}"
        )
    print(f"manifest={manifest_path}")


if __name__ == "__main__":
    main()
