"""Acquire pinned natural hard-negative captions and new CIFAR image features.

The custom SugarCrepe subset is split by original COCO image, not caption row.
All raw assets remain in a reproducible cache. Only embeddings and digests are
published; no claim that CLIP's original pretraining omitted these images.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
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
from PIL import Image
import torch

try:
    from .p3_frozen_clip_features import (MODEL_SHA256, MODEL_URL, CIFAR_CLASSES,
        cifar_datasets, download_verified, select_indices, sha256)
except ImportError:
    from p3_frozen_clip_features import (MODEL_SHA256, MODEL_URL, CIFAR_CLASSES,
        cifar_datasets, download_verified, select_indices, sha256)

CLIP_COMMIT = "d05afc436d78f1c48dc0dbf8e5980a9d471f35f6"
DATA_COMMIT = "0047054b243992f0fad63d6f64f7544862daf846"
KINDS = ("add_att", "add_obj", "replace_att", "replace_obj", "replace_rel", "swap_att", "swap_obj")
SPLITS = ("train", "calibration", "test")


def digest_text(s):
    return hashlib.sha256(s.encode()).hexdigest()


def image_split(filename):
    bucket = int(digest_text("hcsn-round2-split:" + filename), 16) % 10
    return "train" if bucket < 5 else "calibration" if bucket < 7 else "test"


def selection(source):
    result, files = [], {}
    for kind in KINDS:
        path = source / "data" / (kind + ".json")
        records = json.loads(path.read_text())
        files[kind] = {"sha256": sha256(path), "rows": len(records)}
        ordered = sorted(records, key=lambda key: digest_text("hcsn-round2-order:" + kind + ":" + key))
        for split, n in (("train", 16), ("calibration", 8), ("test", 16)):
            chosen = [key for key in ordered if image_split(records[key]["filename"]) == split][:n]
            if len(chosen) != n:
                raise ValueError("insufficient predetermined rows")
            for key in chosen:
                entry = records[key]
                if Path(entry["filename"]).name != entry["filename"] or not entry["filename"].endswith(".jpg"):
                    raise ValueError("unsafe public dataset path")
                result.append({"kind": kind, "key": key, "split": split, **entry})
    sets = [{r["filename"] for r in result if r["split"] == s} for s in SPLITS]
    if any(sets[i] & sets[j] for i in range(3) for j in range(i)):
        raise ValueError("source image leakage")
    return result, files


def fetch_image(cache, filename):
    """Only the fixed selected COCO filenames; failures are never substituted."""
    path = cache / "coco" / filename
    url = "http://images.cocodataset.org/val2017/" + filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        request = urllib.request.Request(url, headers={"User-Agent": "HCSN-research/1"})
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("image byte budget exceeded")
        with Image.open(io.BytesIO(raw)) as im:
            im.verify()
        partial = path.with_suffix(".part")
        partial.write_bytes(raw)
        os.replace(partial, path)
    with Image.open(path) as im:
        pixels = np.asarray(im.convert("RGB"), dtype=np.uint8)
        geometry = list(im.size)
    return {"filename": filename, "source_url": url, "file_sha256": sha256(path),
            "rgb_sha256": hashlib.sha256(pixels.tobytes()).hexdigest(),
            "geometry": geometry, "bytes": path.stat().st_size}


def clean_head(path, expected):
    head = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(path), "status", "--porcelain"], text=True).strip()
    if head != expected or dirty:
        raise ValueError("source checkout mismatch/dirty: " + str(path))


def acquire(clip_source, data_source, cache, output, protocol):
    if output.exists() or output.with_suffix(".json").exists():
        raise FileExistsError("refusing to replace feature evidence")
    clean_head(clip_source, CLIP_COMMIT)
    clean_head(data_source, DATA_COMMIT)
    torch.set_num_threads(1)
    rows, data_files = selection(data_source)
    names = sorted({r["filename"] for r in rows})
    receipt = {"schema": "hcsn.round2-frozen-real-features.v1", "source_sha256": sha256(Path(__file__)),
               "protocol_sha256": sha256(protocol), "clip_source_sha": CLIP_COMMIT,
               "clip_weight_sha256": MODEL_SHA256, "dataset_commit": DATA_COMMIT,
               "dataset_repository": "https://github.com/RAIVNLab/sugar-crepe",
               "dataset_files": data_files, "encoder_frozen": True, "natural_captions": True,
               "pretraining_contamination_unknown": True, "torch_version": str(torch.__version__),
               "device": "cpu", "threads": 1, "sugar_rows": rows}
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=8) as pool:
        images = list(pool.map(lambda name: fetch_image(cache, name), names))
    receipt["coco_images"] = images
    print(json.dumps({"downloaded_coco_images": len(images), "seconds": time.perf_counter() - start}), flush=True)
    training, testing, provenance = cifar_datasets(cache, "hf_parquet")
    calibration_ids = [i for i in select_indices(training.targets, 16, 24) if training.targets[i] < 8]
    test_ids = select_indices(testing.targets, 32, 16)
    training.prepare(calibration_ids)
    testing.prepare(test_ids)
    weight = cache / "weights" / "ViT-B-32.pt"
    download_verified(MODEL_URL, weight, MODEL_SHA256)
    sys.path.insert(0, str(clip_source.resolve()))
    clip = importlib.import_module("clip")
    model, preprocess = clip.load(str(weight), device="cpu", jit=False)
    model.eval().requires_grad_(False)
    receipt["encoder_parameters"] = sum(p.numel() for p in model.parameters())
    receipt["asset_load_seconds"] = time.perf_counter() - start
    receipt["cifar_provenance"] = provenance
    arrays = {}
    timing = {}

    def encode_images(key, count, get_image):
        vectors = []
        w, c = time.perf_counter(), time.process_time()
        for a in range(0, count, 4):
            batch = torch.stack([preprocess(get_image(i)) for i in range(a, min(a + 4, count))])
            with torch.inference_mode():
                v = model.encode_image(batch).float()
                v = v / v.norm(dim=-1, keepdim=True)
            vectors.append(v.numpy())
        arrays[key] = np.concatenate(vectors)
        timing[key] = {"rows": count, "wall_seconds": time.perf_counter() - w,
                       "cpu_seconds": time.process_time() - c}
        print(json.dumps({"encoded": key, **timing[key]}), flush=True)

    def coco_image(i):
        with Image.open(cache / "coco" / names[i]) as im:
            return im.convert("RGB")

    encode_images("coco_image", len(names), coco_image)
    arrays["sugar_image_index"] = np.array([names.index(r["filename"]) for r in rows], dtype=np.int64)
    arrays["sugar_split"] = np.array([SPLITS.index(r["split"]) for r in rows], dtype=np.int64)
    arrays["sugar_kind"] = np.array([KINDS.index(r["kind"]) for r in rows], dtype=np.int64)
    for key, field in (("sugar_positive", "caption"), ("sugar_negative", "negative_caption")):
        chunks = []
        w, c = time.perf_counter(), time.process_time()
        for a in range(0, len(rows), 8):
            tokens = clip.tokenize([r[field] for r in rows[a:a+8]], truncate=False)
            with torch.inference_mode():
                v = model.encode_text(tokens).float()
                v = v / v.norm(dim=-1, keepdim=True)
            chunks.append(v.numpy())
        arrays[key] = np.concatenate(chunks)
        timing[key] = {"rows": len(rows), "wall_seconds": time.perf_counter()-w,
                       "cpu_seconds": time.process_time()-c}
        print(json.dumps({"encoded": key, **timing[key]}), flush=True)
    with torch.inference_mode():
        v = model.encode_text(clip.tokenize(["a photo of a " + name for name in CIFAR_CLASSES])).float()
        arrays["cifar_text"] = (v / v.norm(dim=-1, keepdim=True)).numpy()
    receipt["cifar_selections"] = {}
    for split, dataset, ids in (("calibration", training, calibration_ids), ("test", testing, test_ids)):
        encode_images("cifar_"+split, len(ids), lambda i, dataset=dataset, ids=ids: dataset[ids[i]][0])
        arrays["cifar_"+split+"_labels"] = np.array([dataset.targets[i] for i in ids], dtype=np.int64)
        arrays["cifar_"+split+"_indices"] = np.array(ids, dtype=np.int64)
        receipt["cifar_selections"][split] = [{"index": i, "class": dataset.targets[i],
            "official_split": "train" if split == "calibration" else "test",
            "rgb_sha256": hashlib.sha256(dataset.data[i].tobytes()).hexdigest()} for i in ids]
    for key, value in arrays.items():
        if not np.isfinite(value).all():
            raise ValueError("nonfinite feature output")
    receipt["logit_scale"] = float(model.logit_scale.exp().detach())
    receipt["encoder_timings"] = timing
    receipt["process_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    receipt["normalization_max_error"] = max(float(np.max(np.abs(np.linalg.norm(v,axis=-1)-1)))
        for k,v in arrays.items() if v.ndim == 2 and v.shape[-1] == 512)
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output, **arrays)
    receipt["features_sha256"] = sha256(output)
    output.with_suffix(".json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"features_sha256": receipt["features_sha256"], "rows": len(rows),
                      "unique_coco_images": len(names), "peak_rss_bytes": receipt["process_peak_rss_bytes"]}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--clip-source", type=Path, required=True)
    p.add_argument("--data-source", type=Path, required=True)
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--protocol", type=Path, required=True)
    a = p.parse_args()
    acquire(a.clip_source, a.data_source, a.cache, a.output, a.protocol)
