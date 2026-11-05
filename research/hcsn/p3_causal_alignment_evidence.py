"""Execute the frozen exploratory round3 protocol; retain every paired result."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import time

import numpy as np
import torch

try:
    from .p3_round2_study import load_bundle
    from .p3_causal_alignment import (CausalMatcher, PANELS, SLOTS, make_stream, train_model,
        forward_batch, mapped_put_linear, calibrate, decisions, pair_scores)
except ImportError:
    from p3_round2_study import load_bundle
    from p3_causal_alignment import (CausalMatcher, PANELS, SLOTS, make_stream, train_model,
        forward_batch, mapped_put_linear, calibrate, decisions, pair_scores)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest_stream(batch):
    h = hashlib.sha256()
    for key in sorted(batch):
        value = batch[key].numpy() if isinstance(batch[key], torch.Tensor) else batch[key]
        h.update(key.encode() + str(value.dtype).encode() + str(value.shape).encode() + value.tobytes())
    return h.hexdigest()


def paired_cluster_interval(rows, panel):
    groups = {}
    metric = "accept" if panel in ("missing_source_frame", "evicted_source") else "correct"
    for seed in (101, 113, 127):
        bymode = {r["mode"]: r for r in rows if r["seed"] == seed}
        a = bymode["call_put"]["panels"][panel]
        b = bymode["ordinary_tangent"]["panels"][panel]
        if a["source_ids"] != b["source_ids"]:
            raise AssertionError("paired source mismatch")
        for source, aa, bb in zip(a["source_ids"], a[metric], b[metric]):
            groups.setdefault(source, []).append(float(aa)-float(bb))
    counts = np.array([len(groups[k]) for k in sorted(groups)], dtype=float)
    sums = np.array([sum(groups[k]) for k in sorted(groups)], dtype=float)
    rng = np.random.default_rng(99171)
    samples = rng.integers(0, len(groups), size=(2000, len(groups)))
    draws = sums[samples].sum(-1) / counts[samples].sum(-1)
    return {"metric": "absent_false_match_rate" if metric == "accept" else "present_correct_alignment",
            "call_put_minus_ordinary": float(sums.sum()/counts.sum()),
            "descriptive_image_cluster_bootstrap95": np.quantile(draws, [.025, .975]).tolist(),
            "source_image_clusters": len(groups), "draws": 2000,
            "external_population_or_independent_seed_inference": False}


def timing(models, batch, repeats=40):
    rng = np.random.default_rng(44031)
    result = {m: {"wall_ns": [], "cpu_ns": []} for m in models}
    with torch.inference_mode():
        for model in models.values():
            for _ in range(3): forward_batch(model, batch)
        for _ in range(repeats):
            for mode in rng.permutation(list(models)):
                w, c = time.perf_counter_ns(), time.process_time_ns()
                forward_batch(models[mode], batch)
                result[mode]["cpu_ns"].append(time.process_time_ns()-c)
                result[mode]["wall_ns"].append(time.perf_counter_ns()-w)
    for stats in result.values():
        stats["median_wall_ms"] = float(np.median(stats["wall_ns"])/1e6)
        stats["p99_wall_ms"] = float(np.quantile(stats["wall_ns"], .99)/1e6)
        stats["median_cpu_ms"] = float(np.median(stats["cpu_ns"])/1e6)
    return {"samples": result, "repeats": repeats, "batch": batch["image"].shape[0],
            "length": batch["image"].shape[1], "randomized_interleaving": True,
            "scope": "entire causal FIFO, paired scorer, and validation on preencoded CPU tensors",
            "encoder_network_setup_included": False, "quality_matched_speedup_claim": False,
            "energy_joules": None, "distributed_bytes": None}


def execute(features, protocol, protocol_commit):
    torch.set_num_threads(1)
    start, cpu = time.perf_counter(), time.process_time()
    p = json.loads(Path(protocol).read_text())
    if sha(features) != p["features_sha256"]:
        raise ValueError("protocol feature hash mismatch")
    if p["training_seeds"] != [101, 113, 127] or p["memory_slots"] != SLOTS or p["training_budget"]["updates"] != 240:
        raise ValueError("runner only implements its frozen protocol")
    a, receipt = load_bundle(features)
    anchors = np.flatnonzero(a["sugar_split"] == 2)
    panels = {name: make_stream(a, split=2, seed=770031, batch=len(anchors), length=12,
                               scenario=name, anchors=anchors) for name in PANELS}
    calibration = make_stream(a, split=1, seed=880031, batch=64, length=12)
    rows, maps, all_timing, interventions = [], [], [], []
    for seed in p["training_seeds"]:
        models = {}
        for mode in ("call_put", "ordinary_tangent"):
            w, c = time.perf_counter(), time.process_time()
            model, losses = train_model(a, seed, mode)
            models[mode] = model
            rows.append({"seed": seed, "mode": mode, "updates": 240,
                         "trainable_parameters": sum(x.numel() for x in model.parameters()),
                         "training_wall_seconds": time.perf_counter()-w,
                         "training_cpu_seconds": time.process_time()-c,
                         "loss_trace": losses,
                         "state_dict": {k: v.tolist() for k, v in model.state_dict().items()}})
        models["put_linear_mapped"] = mapped_put_linear(models["call_put"]).eval()
        models["cosine"] = CausalMatcher("cosine")
        models["time_only_newest"] = CausalMatcher("time_only_newest")
        for mode in ("put_linear_mapped", "cosine", "time_only_newest"):
            rows.append({"seed": seed, "mode": mode, "updates": 0,
                         "trained_source": "call_put" if mode == "put_linear_mapped" else None,
                         "trainable_parameters": sum(x.numel() for x in models[mode].parameters())})
        for mode, model in models.items():
            row = next(r for r in rows if r["seed"] == seed and r["mode"] == mode)
            row["calibration"] = calibrate(model, calibration)
            row["panels"] = {name: decisions(model, b, row["calibration"]["threshold"]) for name, b in panels.items()}
            with torch.inference_mode():
                positive, negative = pair_scores(model, a, anchors)
            correct = (positive > negative).float() + .5 * (positive == negative).float()
            row["source_pair_ranking"] = {"accuracy": float(correct.mean()), "rows": len(anchors),
                "positive_scores": positive.tolist(), "negative_scores": negative.tolist(),
                "correct": correct.tolist(), "source_image_given": True,
                "not_a_retrieval_or_unknown_semantics_score": True}
            print(json.dumps({"seed": seed, "mode": mode,
                "aligned": row["panels"]["aligned"]["present_correct_alignment"],
                "delayed": row["panels"]["delayed_text"]["present_correct_alignment"],
                "missing_false_match": row["panels"]["missing_source_frame"]["absent_false_match_rate"],
                "pair_ranking": row["source_pair_ranking"]["accuracy"]}), flush=True)
        with torch.inference_mode():
            errors = []
            for panel in panels.values():
                x, _ = forward_batch(models["call_put"], panel)
                y, _ = forward_batch(models["put_linear_mapped"], panel)
                errors.append(float((x-y).abs().max()))
            maps.append({"seed": seed, "max_all_logit_error": max(errors)})
            counterfactual = copy.deepcopy(panels["delayed_text"])
            counterfactual["text"][:, -1] = counterfactual["text"][:, -1].flip(0)
            for mode, model in models.items():
                original, _ = forward_batch(model, panels["delayed_text"])
                changed, _ = forward_batch(model, counterfactual)
                interventions.append({"seed": seed, "mode": mode,
                    "max_final_query_logit_change": float((original[:, -1]-changed[:, -1]).abs().max()),
                    "top_slot_changed": int((original[:, -1, :SLOTS].argmax(-1) != changed[:, -1, :SLOTS].argmax(-1)).sum()),
                    "rows": len(anchors), "accuracy_not_computed_against_unmodified_targets": True})
        timed = make_stream(a, split=2, seed=555031, batch=8, length=12)
        all_timing.append({"seed": seed, **timing(models, timed)})
    comparisons = {name: paired_cluster_interval(rows, name) for name in PANELS}
    criterion = []
    for seed in p["training_seeds"]:
        modes = {r["mode"]: r for r in rows if r["seed"] == seed}
        for panel in PANELS:
            lhs, rhs = modes["call_put"]["panels"][panel], modes["ordinary_tangent"]["panels"][panel]
            absent = panel in ("missing_source_frame", "evicted_source")
            metric = "absent_false_match_rate" if absent else "present_correct_alignment"
            delta = lhs[metric]-rhs[metric]
            criterion.append({"seed": seed, "panel": panel, "delta": delta,
                              "criterion_met": delta <= .02 if absent else delta >= .02})
    return {"schema": "hcsn.round3.causal-alignment-evidence.v1", "created_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": p["base_commit"], "protocol_commit_before_execution": protocol_commit,
        "protocol_sha256": sha(protocol), "features_sha256": sha(features),
        "source_sha256": {name: sha(Path(__file__).with_name(name)) for name in
            ("p3_causal_alignment.py", "p3_causal_alignment_evidence.py", "test_p3_causal_alignment.py", "p3_round2_study.py")},
        "python": platform.python_version(), "torch": torch.__version__, "numpy": np.__version__,
        "torch_threads": torch.get_num_threads(), "device": "cpu", "cuda_available": torch.cuda.is_available(),
        "thread_environment": {k: os.environ.get(k) for k in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")},
        "encoder_frozen_parameters": receipt["encoder_parameters"], "original_image_split_disjoint": True,
        "test_caption_rows": len(anchors), "test_original_images": len(np.unique(a["sugar_image_index"][anchors])),
        "test_is_previously_used_subset": True, "source_identifiers_never_model_inputs": True,
        "calibration_stream_sha256": digest_stream(calibration),
        "test_stream_sha256": {k: digest_stream(v) for k, v in panels.items()},
        "training_fits": 6, "all_completed_fits": rows, "mapped_function_audit": maps,
        "query_interventions": interventions, "paired_image_cluster_comparisons": comparisons,
        "positive_claim_criterion_rows": criterion, "positive_claim_criterion_met": all(x["criterion_met"] for x in criterion),
        "timings": all_timing, "whole_campaign_wall_seconds": time.perf_counter()-start,
        "whole_campaign_cpu_seconds": time.process_time()-cpu,
        "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "scientific_p3_closed": False, "scientific_p4_closed": False, "production_activation": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", default="research/hcsn/fixtures/frozen_round2_20261105.npz")
    parser.add_argument("--protocol", default="research/hcsn/gates/2026-11-05-round3-p3-causal-alignment-protocol.json")
    parser.add_argument("--protocol-commit", default="cd71547cb5129985950576311bac37fa73c38aa2")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    path = Path(args.output)
    if path.exists():
        raise FileExistsError("use a fresh evidence path")
    result = execute(args.features, args.protocol, args.protocol_commit)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as out:
        json.dump(result, out, indent=2, allow_nan=False)
        out.write("\n")
    print(json.dumps({"output": str(path), "positive_claim_criterion_met": result["positive_claim_criterion_met"],
                      "whole_campaign_wall_seconds": result["whole_campaign_wall_seconds"]}), flush=True)


if __name__ == "__main__":
    main()
