"""Frozen real image/text encoder, small causal temporal-fusion pilot.

Only the fusion gates and contradiction head are trained. Synthetic sequences
are made from genuine CIFAR images and CLIP class prompts. No full HX, natural
caption/video, unknown-to-pretraining, fixed-quality efficiency, or scaling claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import resource
import time

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

MODES = ("call_put", "put_linear", "ordinary", "overwrite")
SCENARIOS = ("aligned", "missing_image", "missing_text", "misaligned_text", "irregular_time", "long_blank")


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_features(path):
    path = Path(path)
    metadata = json.loads(path.with_suffix(".json").read_text())
    if file_sha(path) != metadata["features_sha256"] or metadata.get("encoder_frozen") is not True:
        raise ValueError("feature digest/frozen-encoder mismatch")
    with np.load(path, allow_pickle=False) as source:
        bundle = {k: source[k].copy() for k in source.files}
    train = {(e["official_split"], e["index"]) for e in metadata["selections"]["train"]}
    calibration = {(e["official_split"], e["index"]) for e in metadata["selections"]["calibration"]}
    test = {(e["official_split"], e["index"]) for e in metadata["selections"]["test"]}
    if train & calibration or train & test or calibration & test:
        raise ValueError("source-image split leakage")
    for split in ("train", "calibration", "test"):
        selected = metadata["selections"][split]
        if (bundle[split + "_indices"].tolist() != [e["index"] for e in selected]
                or bundle[split + "_labels"].tolist() != [e["class"] for e in selected]
                or bundle[split + "_embeddings"].shape != (len(selected), 512)
                or not np.isfinite(bundle[split + "_embeddings"]).all()):
            raise ValueError("feature rows do not match source receipt")
    if bundle["text_embeddings"].shape != (10, 512) or not np.isfinite(bundle["text_embeddings"]).all():
        raise ValueError("invalid frozen text feature pool")
    prototypes = torch.tensor(bundle["text_embeddings"][:8], dtype=torch.float32)
    text = torch.tensor(bundle["text_embeddings"], dtype=torch.float32)
    bundle["text_prob"] = (float(metadata["logit_scale"]) * text @ prototypes.T).softmax(-1)
    for split in ("train", "calibration", "test"):
        embeddings = torch.tensor(bundle[split + "_embeddings"], dtype=torch.float32)
        bundle[split + "_prob"] = (float(metadata["logit_scale"]) * embeddings @ prototypes.T).softmax(-1)
    return bundle, metadata


def streams(bundle, *, split, seed, batch=32, length=12, scenario="aligned", unknown=False):
    if scenario not in SCENARIOS or split not in ("train", "calibration", "test"):
        raise ValueError("unknown split/scenario")
    if batch <= 0 or length < 4 or (unknown and split != "test"):
        raise ValueError("invalid stream domain; heldout classes only in test")
    rng = np.random.default_rng(seed)
    classes = np.array([8, 9]) if unknown else np.arange(8)
    labels = np.asarray(bundle[split + "_labels"])
    by_class = {int(c): np.flatnonzero(labels == c) for c in classes}
    if any(len(ids) == 0 for ids in by_class.values()):
        raise ValueError("missing class in frozen feature pool")
    image_classes = np.empty((batch, length), dtype=np.int64)
    text_classes = np.empty_like(image_classes)
    indices = np.empty_like(image_classes)
    for b in range(batch):
        c = int(rng.choice(classes))
        for t in range(length):
            if rng.random() < .4:
                c = int(rng.choice(classes))
            image_classes[b, t] = c
            alternatives = classes[classes != c]
            text_classes[b, t] = c if rng.random() < .75 else int(rng.choice(alternatives))
            indices[b, t] = int(rng.choice(by_class[c]))
    observed = rng.random((batch, length, 2)) < .85
    observed[:, 0] = True
    if scenario == "missing_image":
        observed[:, length // 2:, 0] = False
    elif scenario == "missing_text":
        observed[:, length // 2:, 1] = False
    elif scenario == "misaligned_text":
        text_classes[:, 1:] = text_classes[:, :-1].copy()
        observed[:, 1:, 1] = observed[:, :-1, 1].copy()
        observed[:, 0, 1] = False
    elif scenario == "long_blank":
        observed[:, length // 2:] = False
    dt = np.ones((batch, length), dtype=np.float32)
    if scenario == "irregular_time":
        dt = np.exp(rng.uniform(np.log(.05), np.log(16), dt.shape)).astype(np.float32)
    elif scenario == "long_blank":
        dt[:, length // 2:] = 32.
    last_image = np.full((batch, length), -1, dtype=np.int64)
    last_text = np.full_like(last_image, -1)
    for t in range(length):
        old_i = last_image[:, t - 1] if t else np.full(batch, -1)
        old_t = last_text[:, t - 1] if t else np.full(batch, -1)
        last_image[:, t] = np.where(observed[:, t, 0], image_classes[:, t], old_i)
        last_text[:, t] = np.where(observed[:, t, 1], text_classes[:, t], old_t)
    return {
        "image": bundle[split + "_prob"][torch.from_numpy(indices)],
        "text": bundle["text_prob"][torch.from_numpy(text_classes.copy())],
        "observed": torch.from_numpy(observed), "dt": torch.from_numpy(dt),
        "image_label": torch.from_numpy(last_image), "text_label": torch.from_numpy(last_text),
        "source_indices": torch.from_numpy(indices),
    }


class TemporalFusion(nn.Module):
    def __init__(self, mode, width=16):
        super().__init__()
        if mode not in MODES or width <= 0:
            raise ValueError("unknown mode/width")
        self.mode = mode
        # Shared head is initialized before optional gates for exact pairing.
        self.contradiction = nn.Sequential(nn.Linear(32, width), nn.Tanh(), nn.Linear(width, 1))
        if mode != "overwrite":
            self.score = nn.Linear(4, 1)
            self.gate_readout = nn.Linear(2, 1)

    def initial_state(self, reference):
        b = reference.shape[0]
        zero = reference.new_zeros((b, 8))
        seen = torch.zeros((b, 1), dtype=torch.bool, device=reference.device)
        age = reference.new_zeros((b,))
        return zero, zero.clone(), seen, seen.clone(), age, age.clone()

    def gate(self, current, memory, dt):
        if self.mode == "overwrite":
            return torch.ones_like(dt[:, None])
        stats = torch.stack((current.max(-1).values, (current - memory).square().mean(-1),
                             memory.max(-1).values, torch.log1p(dt)), -1)
        z = self.score(stats).squeeze(-1)
        if self.mode == "ordinary":
            features = torch.stack((torch.sigmoid(z), torch.tanh(z)), -1)
        else:
            v = .01 + F.softplus(z)
            r, delta, sigma = .05, .03, .2
            q = r - delta - .5 * sigma ** 2
            beta = (q + math.sqrt(q * q + 2 * r * sigma ** 2)) / sigma ** 2
            boundary = beta / (1 + beta)
            option = (1 - boundary) * torch.exp(-beta * (torch.log(v / boundary)).clamp(min=0))
            call = torch.where(v > boundary, v - 1 + option, torch.zeros_like(v))
            put = torch.where(v > boundary, option, 1 - v)
            features = (torch.stack((call, put), -1) if self.mode == "call_put"
                        else torch.stack((put, v - 1), -1))
        return torch.sigmoid(self.gate_readout(features))

    def forward(self, image, text, observed, dt, state=None):
        if image.ndim != 3 or image.shape[-1] != 8 or text.shape != image.shape or min(image.shape[:2]) <= 0:
            raise ValueError("image/text must be B x T x 8 known-prototype probabilities")
        if observed.shape != image.shape[:2] + (2,) or observed.dtype != torch.bool or dt.shape != image.shape[:2]:
            raise ValueError("bad observation mask or physical time shape")
        if not all(bool(torch.isfinite(x).all()) for x in (image, text, dt)) or bool((dt <= 0).any()):
            raise ValueError("finite features and strictly positive physical time required")
        hi, ht, si, st, age_i, age_t = self.initial_state(image) if state is None else state
        logits, matches = [], []
        for t in range(image.shape[1]):
            oi, ot = observed[:, t, 0:1], observed[:, t, 1:2]
            age_i, age_t = age_i + dt[:, t], age_t + dt[:, t]
            # Missing payloads never affect state or gate statistics.
            vi = torch.where(oi, image[:, t], torch.zeros_like(hi))
            vt = torch.where(ot, text[:, t], torch.zeros_like(ht))
            gi, gt = self.gate(vi, hi, age_i), self.gate(vt, ht, age_t)
            ni = torch.where(si, hi + gi * (vi - hi), vi)
            nt = torch.where(st, ht + gt * (vt - ht), vt)
            hi, ht = torch.where(oi, ni, hi), torch.where(ot, nt, ht)
            si, st = si | oi, st | ot
            age_i = torch.where(oi.squeeze(-1), torch.zeros_like(age_i), age_i)
            age_t = torch.where(ot.squeeze(-1), torch.zeros_like(age_t), age_t)
            logits.append(10 * hi)  # identical fixed class decoder in every variant
            joint = torch.cat((hi, ht, (hi - ht).abs(), hi * ht), -1)
            matches.append(self.contradiction(joint).squeeze(-1))
        return torch.stack(logits, 1), torch.stack(matches, 1), (hi, ht, si, st, age_i, age_t)


def model_output(model, batch):
    return model(batch["image"], batch["text"], batch["observed"], batch["dt"])


def training_loss(model, batch):
    classes, matches, _ = model_output(model, batch)
    target = batch["image_label"]
    valid_i = target >= 0
    if bool((target[valid_i] >= 8).any()):
        raise ValueError("heldout unknown classes cannot train the fusion model")
    valid_pair = valid_i & (batch["text_label"] >= 0)
    same = (target == batch["text_label"]).float()
    return (F.cross_entropy(classes[valid_i], target[valid_i])
            + F.binary_cross_entropy_with_logits(matches[valid_pair], same[valid_pair]))


def evaluate(model, batch, threshold=None):
    with torch.inference_mode():
        logits, match, state = model_output(model, batch)
        prob = logits[:, -1].softmax(-1)
        confidence, prediction = prob.max(-1)
        truth = batch["image_label"][:, -1]
        other = batch["text_label"][:, -1]
        valid = (truth >= 0) & (other >= 0)
        target_match = truth == other
        predicted_match = match[:, -1] >= 0
        support = {str(value): int((valid & (target_match == value)).sum()) for value in (False, True)}
        recalls = {str(value): float((predicted_match[valid & (target_match == value)] == value).float().mean())
                   if support[str(value)] else None for value in (False, True)}
        known = (truth >= 0) & (truth < 8)
        unknown = truth >= 8
        known_pair = known & (other >= 0) & (other < 8)
        text_prediction = state[1].argmax(-1)
        out = {"streams": len(truth), "pair_query_count": int(valid.sum()),
               "known_query_count": int(known.sum()), "unknown_query_count": int(unknown.sum()),
               "known_recall": float((prediction[known] == truth[known]).float().mean()) if bool(known.any()) else None,
               "paired_known_recall": float(((prediction[known_pair] == truth[known_pair]) &
                                              (text_prediction[known_pair] == other[known_pair])).float().mean())
                                       if bool(known_pair.any()) else None,
               "match_support": support, "match_per_class_recall": recalls,
               "match_balanced_accuracy": float(np.mean(list(recalls.values()))) if all(support.values()) else None,
               "match_accuracy": float((predicted_match[valid] == target_match[valid]).float().mean()) if bool(valid.any()) else None,
               "match_confusion": {"tn": int((valid & ~target_match & ~predicted_match).sum()),
                                   "fp": int((valid & ~target_match & predicted_match).sum()),
                                   "fn": int((valid & target_match & ~predicted_match).sum()),
                                   "tp": int((valid & target_match & predicted_match).sum())}}
        if threshold is not None:
            out["id_acceptance"] = float((confidence[known] >= threshold).float().mean()) if bool(known.any()) else None
            out["unknown_false_acceptance"] = float((confidence[unknown] >= threshold).float().mean()) if bool(unknown.any()) else None
        return out, confidence.cpu().numpy()


def latency(model, batch, repeats=30):
    samples, cpu = [], []
    with torch.inference_mode():
        for _ in range(3):
            model_output(model, batch)
        for _ in range(repeats):
            w, c = time.perf_counter_ns(), time.process_time_ns()
            model_output(model, batch)
            samples.append(time.perf_counter_ns() - w)
            cpu.append(time.process_time_ns() - c)
    return {"warmup": 3, "repeats": repeats, "batch_size": batch["image"].shape[0],
            "length": batch["image"].shape[1], "wall_ns": samples, "process_cpu_ns": cpu,
            "p50_wall_ns": float(np.quantile(samples, .5)), "p99_wall_ns": float(np.quantile(samples, .99)),
            "scope": "complete fusion forward incl. validation + both heads; precomputed encoder inputs",
            "energy_joules": None, "single_process_runtime_communication_bytes": 0}


def study(path, *, seeds=(11, 23, 37), steps=120, batch=24, eval_n=128, width=16):
    torch.set_num_threads(1)
    bundle, metadata = load_features(path)
    rows = []
    for seed in seeds:
        for mode in MODES:
            torch.manual_seed(seed)
            model = TemporalFusion(mode, width)
            optimizer = torch.optim.Adam(model.parameters(), lr=.01)
            wall, cpu = time.perf_counter(), time.process_time()
            for step in range(steps):
                data = streams(bundle, split="train", seed=seed * 10000 + step,
                               batch=batch, length=12)
                optimizer.zero_grad(set_to_none=True)
                loss = training_loss(model, data)
                loss.backward()
                if not all(p.grad is not None and bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
                    raise ArithmeticError("missing/nonfinite gradient")
                optimizer.step()
            row = {"mode": mode, "seed": seed, "width": width, "optimizer_updates": steps,
                   "training_streams": steps * batch, "training_length": 12,
                   "trainable_parameters": sum(p.numel() for p in model.parameters()),
                   "last_training_loss": float(loss.detach()),
                   "training_wall_seconds": time.perf_counter() - wall,
                   "training_cpu_seconds": time.process_time() - cpu}
            model.eval()
            calibration = streams(bundle, split="calibration", seed=730001, batch=256, length=16)
            _, scores = evaluate(model, calibration)
            # ID-only 5th percentile; no OOD examples or labels tune this threshold.
            threshold = float(np.quantile(scores, .05, method="lower"))
            row["id_only_rejection_threshold"] = threshold
            row["evaluations"] = {}
            for scenario in SCENARIOS:
                data = streams(bundle, split="test", seed=880001, batch=eval_n, length=24, scenario=scenario)
                row["evaluations"][scenario] = evaluate(model, data, threshold)[0]
            unknown = streams(bundle, split="test", seed=990001, batch=eval_n, length=24, unknown=True)
            row["evaluations"]["heldout_class_unknown"] = evaluate(model, unknown, threshold)[0]
            timed = streams(bundle, split="test", seed=550001, batch=32, length=24)
            row["fusion_latency"] = latency(model, timed)
            rows.append(row)
            print(json.dumps({"mode": mode, "seed": seed, "aligned": row["evaluations"]["aligned"],
                              "unknown": row["evaluations"]["heldout_class_unknown"]}), flush=True)
    summary = {}
    for mode in MODES:
        group = [r for r in rows if r["mode"] == mode]
        summary[mode] = {}
        for scenario in SCENARIOS + ("heldout_class_unknown",):
            keys = group[0]["evaluations"][scenario]
            summary[mode][scenario] = {k: float(np.mean([r["evaluations"][scenario][k] for r in group]))
                                      for k in keys if isinstance(keys[k], (float, int))}
    return {"schema": "hcsn.frozen-clip-temporal-pilot.v1", "feature_sha256": metadata["features_sha256"],
            "clip_source_sha": metadata["clip_source_sha"], "clip_weight_sha256": metadata["clip_weight_sha256"],
            "source_sha256": file_sha(__file__), "seeds": list(seeds), "rows": rows, "summary": summary,
            "encoder_measurement": {k: v for k, v in metadata.items() if k.startswith("encoder_")},
            "fusion_process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            "caveats": ["class-name prompts, not natural captions; synthetic temporal assembly of real images",
                         "known recall uses visual memory; paired recall requires both last-observed labels; no missing-image semantic reconstruction",
                         "blank retention is the shared masked-identity architecture, not a Call/Put-specific effect",
                         "same streams/steps/head size for learned gates; FLOPs/local slopes not matched",
                         "overwrite baseline has eight fewer active parameters",
                         "heldout-from-fusion classes may occur in CLIP pretraining",
                         "no encoder training, generator, audio/video, device energy or distributed communication study",
                         "fusion p99 is a small-sample local estimate, not an end-to-end latency qualification"],
            "production_activation": False, "p3_closed": False, "p4_closed": False, "p5_closed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--steps", type=int, default=120)
    parser.add_argument("--eval-n", type=int, default=128)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite evidence")
    result = study(args.features, steps=args.steps, eval_n=args.eval_n)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps(result["summary"], indent=2))
