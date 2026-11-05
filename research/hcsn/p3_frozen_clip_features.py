"""Acquire genuine frozen CLIP/CIFAR-10 features for a bounded P3 pilot.

The text modality consists of class-name prompts, not natural captions. Classes
8/9 are held out from the fusion learner, NOT from CLIP's unknown pretraining
corpus. This is a reproducible pilot, not four-modal or unseen-concept evidence.
Weights/data stay outside the repository; their identities enter the receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time
import urllib.request

import numpy as np
import torch

MODEL_SHA256 = "40d365715913c9da98579312b702a82c18be219cc2a73407c4526f58eba950af"
MODEL_URL = "https://openaipublic.azureedge.net/clip/models/" + MODEL_SHA256 + "/ViT-B-32.pt"
CIFAR_CLASSES = ("airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse", "ship", "truck")
MIRROR_REPOSITORY = "uoft-cs/cifar10"
MIRROR_REVISION = "0b2714987fa478483af9968de7c934580d0bb9a2"
MIRROR_FILES = {
    "train": ("plain_text/train-00000-of-00001.parquet", 119705255,
              "8428b53a88a11ac374111006708df51469e315a22ac6d66470afd9c78d2ae883"),
    "test": ("plain_text/test-00000-of-00001.parquet", 23940850,
             "841389e6f2d64f28bf17310e430aebac20ec3ba611a3c5e231dc93c645ce84de"),
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def download_verified(url: str, path: Path, expected_sha256: str, *, expected_size=None,
                      maximum_bytes=512 * 1024 * 1024):
    """Stream an immutable public asset; admit only a complete expected hash.

    Incomplete files are never used as data. A failed attempt leaves a .part
    checkpoint, which the next explicit attempt replaces. Existing final files
    with the wrong hash are rejected instead of silently consumed.
    """
    if path.exists():
        if not path.is_file() or (expected_size is not None and path.stat().st_size != expected_size):
            raise ValueError("invalid cached asset size: " + str(path))
        if sha256(path) != expected_sha256:
            raise ValueError("invalid cached asset digest: " + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "HCSN-frozen-feature-reference/1"})
    digest, count, reported = hashlib.sha256(), 0, 0
    with urllib.request.urlopen(request, timeout=45) as source, partial.open("wb") as target:
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            if count > maximum_bytes or (expected_size is not None and count > expected_size):
                raise ValueError("asset exceeded frozen byte budget")
            target.write(chunk)
            digest.update(chunk)
            if count - reported >= 8 * 1024 * 1024:
                print(json.dumps({"download": path.name, "bytes": count,
                                  "expected_bytes": expected_size}), flush=True)
                reported = count
        target.flush()
        os.fsync(target.fileno())
    if expected_size is not None and count != expected_size:
        raise ValueError("incomplete immutable asset")
    if digest.hexdigest() != expected_sha256:
        raise ValueError("immutable asset SHA-256 mismatch")
    os.replace(partial, path)
    print(json.dumps({"verified_asset": path.name, "bytes": count,
                      "sha256": expected_sha256}), flush=True)


class ParquetCifarRows:
    """Bounded decoding of original rows in one pinned lossless CIFAR mirror.

    Row identities are explicitly mirror row positions. They are never claimed
    to be independently proven equivalent to the original archive's order.
    Labels and RGB pixel hashes make each selected example reproducible.
    """

    def __init__(self, path: Path, split: str):
        import pyarrow.parquet as pq
        if split not in MIRROR_FILES:
            raise ValueError("unknown CIFAR split")
        self.train = split == "train"
        self.classes = list(CIFAR_CLASSES)
        self.parquet = pq.ParquetFile(path, memory_map=True)
        expected_rows, expected_per_class = (50000, 5000) if self.train else (10000, 1000)
        if self.parquet.metadata.num_rows != expected_rows:
            raise ValueError("unexpected CIFAR mirror row count")
        metadata = self.parquet.schema_arrow.metadata or {}
        features = json.loads(metadata.get(b"huggingface", b"{}"))
        names = features.get("info", {}).get("features", {}).get("label", {}).get("names")
        if names is not None and tuple(names) != CIFAR_CLASSES:
            raise ValueError("unexpected CIFAR label taxonomy")
        self.targets = self.parquet.read(columns=["label"], use_threads=False)["label"].to_pylist()
        if len(self.targets) != expected_rows or any(self.targets.count(c) != expected_per_class for c in range(10)):
            raise ValueError("unexpected class census")
        self.data = {}

    def prepare(self, indices):
        """Read only row groups containing frozen selections; retain RGB only."""
        from PIL import Image
        requested = set(indices)
        if any(isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(self.targets) for i in requested):
            raise ValueError("invalid frozen mirror row index")
        start = 0
        for group in range(self.parquet.num_row_groups):
            stop = start + self.parquet.metadata.row_group(group).num_rows
            chosen = sorted(i for i in requested if start <= i < stop)
            if chosen:
                column = self.parquet.read_row_group(group, columns=["img"], use_threads=False)["img"]
                for i in chosen:
                    raw = column[i - start].as_py()["bytes"]
                    with Image.open(io.BytesIO(raw)) as image:
                        if image.size != (32, 32):
                            raise ValueError("unexpected CIFAR pixel geometry")
                        pixels = np.asarray(image.convert("RGB"), dtype=np.uint8).copy()
                    self.data[i] = pixels
            start = stop
        if set(self.data) != requested:
            raise ValueError("incomplete frozen mirror row selection")

    def __getitem__(self, index):
        from PIL import Image
        return Image.fromarray(self.data[index]), self.targets[index]


def cifar_datasets(cache: Path, backend: str):
    if backend == "torchvision":
        from torchvision.datasets import CIFAR10
        training = CIFAR10(str(cache / "data"), train=True, download=True)
        testing = CIFAR10(str(cache / "data"), train=False, download=True)
        return training, testing, {"backend": "torchvision", "row_index_namespace": "official Python archive split"}
    if backend != "hf_parquet":
        raise ValueError("unknown CIFAR backend")
    import pyarrow
    datasets, files = {}, {}
    for split, (relative, size, expected) in MIRROR_FILES.items():
        url = f"https://huggingface.co/datasets/{MIRROR_REPOSITORY}/resolve/{MIRROR_REVISION}/{relative}?download=true"
        path = cache / "hf_data" / MIRROR_REVISION / Path(relative).name
        download_verified(url, path, expected, expected_size=size, maximum_bytes=128 * 1024 * 1024)
        datasets[split] = ParquetCifarRows(path, split)
        files[split] = {"repository_path": relative, "url": url, "bytes": size, "sha256": expected,
                        "rows": len(datasets[split].targets)}
    return datasets["train"], datasets["test"], {
        "backend": "hf_parquet", "repository": MIRROR_REPOSITORY,
        "revision": MIRROR_REVISION, "files": files, "pyarrow_version": pyarrow.__version__,
        "row_index_namespace": "original row positions in each pinned mirror parquet",
        "official_archive_row_equivalence_independently_verified": False,
        "pixels_sha256_layout": "C-contiguous uint8 RGB HWC (32,32,3)",
    }


def select_indices(labels, per_class: int, offset: int = 0):
    if per_class <= 0 or offset < 0:
        raise ValueError("positive sample count and nonnegative offset required")
    result = []
    for c in range(10):
        ids = [i for i, label in enumerate(labels) if label == c]
        chosen = ids[offset:offset + per_class]
        if len(chosen) != per_class:
            raise ValueError("insufficient examples")
        result.extend(chosen)
    return result


def acquire(clip_source: Path, cache: Path, output: Path, *, train_per_class=16,
            calibration_per_class=8, test_per_class=16, batch=4,
            dataset_backend="torchvision"):
    if output.exists() or output.with_suffix(".json").exists():
        raise FileExistsError("refusing to overwrite frozen features or receipt")
    if not 1 <= batch <= 16:
        raise ValueError("bounded CPU encoding batch required")
    source_sha = subprocess.check_output(
        ["git", "-C", str(clip_source), "rev-parse", "HEAD"], text=True).strip()
    if subprocess.check_output(["git", "-C", str(clip_source), "status", "--porcelain"], text=True).strip():
        raise ValueError("CLIP source must be clean")
    sys.path.insert(0, str(clip_source.resolve()))
    clip = importlib.import_module("clip")
    torch.set_num_threads(1)
    cache.mkdir(parents=True, exist_ok=True)
    download_start = time.perf_counter()
    training, testing, dataset_provenance = cifar_datasets(cache, dataset_backend)
    selections = {
        "train": (training, select_indices(training.targets, train_per_class)),
        "calibration": (training, select_indices(training.targets, calibration_per_class, train_per_class)),
        "test": (testing, select_indices(testing.targets, test_per_class)),
    }
    if dataset_backend == "hf_parquet":
        training.prepare(selections["train"][1] + selections["calibration"][1])
        testing.prepare(selections["test"][1])
    weight_path = cache / "weights" / "ViT-B-32.pt"
    download_verified(MODEL_URL, weight_path, MODEL_SHA256)
    if sha256(weight_path) != MODEL_SHA256:
        raise ValueError("wrong frozen CLIP weights")
    # A verified local path avoids CLIP's additional full-file hash allocation.
    # The same official implementation builds the same frozen ViT-B/32 model.
    model, preprocess = clip.load(str(weight_path), device="cpu", jit=False)
    download_seconds = time.perf_counter() - download_start
    model.eval().requires_grad_(False)
    if any(p.requires_grad for p in model.parameters()):
        raise AssertionError("encoder must be frozen")
    prompts = ["a photo of a " + name for name in training.classes]
    encoder_wall_start, encoder_cpu_start = time.perf_counter(), time.process_time()
    with torch.inference_mode():
        text = model.encode_text(clip.tokenize(prompts)).float()
        text /= text.norm(dim=-1, keepdim=True)
    arrays = {"text_embeddings": text.numpy()}
    receipt = {"schema": "hcsn.frozen-clip-label-prompt-features.v1",
               "clip_repository": "https://github.com/openai/CLIP", "clip_source_sha": source_sha,
               "clip_weight_sha256": MODEL_SHA256, "model": "ViT-B/32", "encoder_frozen": True,
               "dataset": "CIFAR-10", "dataset_url": "https://cave.cs.toronto.edu/kriz/cifar.html",
               "dataset_provenance": dataset_provenance,
               "prompts": prompts, "fusion_known_classes": list(range(8)),
               "fusion_heldout_classes": [8, 9], "pretraining_contamination_unknown": True,
               "natural_captions": False, "selections": {}, "batch_size": batch,
               "torch_version": torch.__version__, "numpy_version": np.__version__,
               "threads": 1, "device": "cpu", "download_and_load_seconds": download_seconds}
    for split, (dataset, ids) in selections.items():
        vectors, examples = [], []
        split_start = time.perf_counter()
        for start in range(0, len(ids), batch):
            chosen = ids[start:start + batch]
            images = torch.stack([preprocess(dataset[i][0]) for i in chosen])
            with torch.inference_mode():
                features = model.encode_image(images).float()
                features /= features.norm(dim=-1, keepdim=True)
            vectors.append(features.numpy())
            for i in chosen:
                examples.append({"official_split": "train" if dataset.train else "test",
                                 "index": i, "class": int(dataset.targets[i]),
                                 "index_namespace": dataset_provenance["row_index_namespace"],
                                 "pixels_sha256": hashlib.sha256(dataset.data[i].tobytes()).hexdigest()})
            print(json.dumps({"encoding": split, "done": min(start + batch, len(ids)), "total": len(ids)}), flush=True)
        arrays[split + "_embeddings"] = np.concatenate(vectors)
        arrays[split + "_labels"] = np.array([dataset.targets[i] for i in ids], dtype=np.int64)
        arrays[split + "_indices"] = np.array(ids, dtype=np.int64)
        receipt["selections"][split] = examples
        receipt[split + "_encoding_wall_seconds"] = time.perf_counter() - split_start
    receipt["encoder_wall_seconds"] = time.perf_counter() - encoder_wall_start
    receipt["encoder_process_cpu_seconds"] = time.process_time() - encoder_cpu_start
    receipt["encoder_process_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    receipt["frozen_parameter_count"] = sum(p.numel() for p in model.parameters())
    receipt["logit_scale"] = float(model.logit_scale.exp().detach())
    receipt["energy_joules"] = None
    receipt["communication_runtime_bytes"] = 0
    receipt["communication_scope"] = "single-process CPU encoding only; no distributed inference"
    receipt["source_sha256"] = sha256(Path(__file__))
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output, **arrays)
    receipt["features_sha256"] = sha256(output)
    output.with_suffix(".json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clip-source", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--batch", type=int, default=4)
    parser.add_argument("--dataset-backend", choices=("torchvision", "hf_parquet"), default="torchvision")
    args = parser.parse_args()
    result = acquire(args.clip_source, args.cache, args.output, batch=args.batch,
                     dataset_backend=args.dataset_backend)
    print(json.dumps({k: v for k, v in result.items() if k != "selections"}, indent=2))
