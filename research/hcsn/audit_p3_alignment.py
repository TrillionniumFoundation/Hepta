"""Read-only independent accounting audit of the round3 P3 experiment.

The oracle uses ordinary Python queues, separate from source_targets().
This audit does not retrain, select a model, tune a threshold, or change data.
Its computational cross-review is not an external scientific attestation.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys

import numpy as np
import torch


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def independent_queue(batch, arrays):
    """Replay only observed image events, attaching IDs solely for this audit."""
    image_rows, text_rows = batch["image_rows"], batch["text_rows"]
    observations = batch["observed"].numpy()
    elapsed = batch["dt"].numpy()
    B, T = image_rows.shape
    labels = np.zeros((B, T, 5), bool)
    histories = np.full((B, T, 4), -1, np.int64)
    ages = np.zeros((B, 4), np.float32)
    for b in range(B):
        queue = []
        for t in range(T):
            queue = [(source, np.float32(age + elapsed[b, t])) for source, age in queue]
            if observations[b, t, 0]:
                source = int(arrays["sugar_image_index"][image_rows[b, t]])
                queue.insert(0, (source, np.float32(0)))
                queue = queue[:4]
            for slot, (source, age) in enumerate(queue):
                histories[b, t, slot] = source
            if observations[b, t, 1]:
                source = int(arrays["sugar_image_index"][text_rows[b, t]])
                targets = [i for i, (candidate, _) in enumerate(queue) if candidate == source]
                for i in targets:
                    labels[b, t, i] = True
                labels[b, t, 4] = not targets
        for slot, (_, age) in enumerate(queue):
            ages[b, slot] = age
    return labels, histories, ages


def same_float(actual, expected, tolerance=1e-7):
    if actual is None or expected is None:
        assert actual is expected
    else:
        assert math.isclose(float(actual), float(expected), rel_tol=tolerance, abs_tol=tolerance), (actual, expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path.cwd(), type=Path,
                        help="Repository root; defaults to current directory")
    parser.add_argument("--evidence", "--raw", dest="evidence", type=Path,
                        help="Plain JSON or .json.gz; default is the round3 v2 receipt under the repository root")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("refuse to overwrite independent review evidence")
    root = args.root.resolve()
    evidence = args.evidence
    if evidence is None:
        base = root / "research/hcsn/gates/2026-11-05-round3-p3-causal-alignment-raw-v2.json"
        compressed = base.with_suffix(base.suffix + ".gz")
        evidence = compressed if compressed.exists() else base
    elif not evidence.is_absolute():
        evidence = root / evidence
    sys.path.insert(0, str(root))
    from research.hcsn.p3_round2_study import load_bundle
    from research.hcsn.p3_causal_alignment import (
        CausalMatcher, PANELS, make_stream, forward_batch, mapped_put_linear, decisions,
    )
    torch.set_num_threads(1)
    source_names = ["p3_causal_alignment.py", "p3_causal_alignment_evidence.py", "p3_round2_study.py"]
    source_hashes = {n: digest(root / "research/hcsn" / n) for n in source_names}
    evidence_bytes = evidence.read_bytes()
    compressed = evidence.suffix == ".gz"
    raw_bytes = gzip.decompress(evidence_bytes) if compressed else evidence_bytes
    raw = json.loads(raw_bytes)
    features = root / "research/hcsn/fixtures/frozen_round2_20261105.npz"
    arrays, receipt = load_bundle(features)
    anchors = np.flatnonzero(arrays["sugar_split"] == 2)
    panels = {name: make_stream(arrays, split=2, seed=770031, batch=len(anchors), length=12,
                               scenario=name, anchors=anchors) for name in PANELS}
    calibration = make_stream(arrays, split=1, seed=880031, batch=64, length=12)
    train_probe = make_stream(arrays, split=0, seed=332471, batch=16, length=17)
    queues, queue_counts = {}, {}
    for name, batch in {"train_probe": train_probe, "calibration": calibration, **panels}.items():
        labels, histories, age = independent_queue(batch, arrays)
        np.testing.assert_array_equal(labels, batch["target"].numpy())
        np.testing.assert_array_equal(histories, batch["slot_ids"])
        queues[name] = labels, histories, age
        queue_counts[name] = {"streams": len(labels), "steps": labels.shape[1],
                             "observed_queries": int(batch["observed"][..., 1].sum()),
                             "multi_positive_queries": int((labels[..., :4].sum(-1) > 1).sum())}

    # Source separation is checked using original images, not caption row IDs.
    source_sets = [set(arrays["sugar_image_index"][arrays["sugar_split"] == s].tolist()) for s in range(3)]
    assert not any(source_sets[a] & source_sets[b] for a in range(3) for b in range(a))
    init_parity = []
    for seed in (101, 113, 127):
        torch.manual_seed(seed); left = CausalMatcher("call_put")
        torch.manual_seed(seed); right = CausalMatcher("ordinary_tangent")
        assert sum(p.numel() for p in left.parameters()) == sum(p.numel() for p in right.parameters()) == 322
        assert all(torch.equal(left.state_dict()[k], right.state_dict()[k]) for k in left.state_dict())
        init_parity.append({"seed": seed, "parameters_each": 322, "all_initial_parameters_equal": True})

    calibrated, replay, permutation, metadata = [], [], [], []
    with torch.inference_mode():
        for seed in (101, 113, 127):
            records = {r["mode"]: r for r in raw["all_completed_fits"] if r["seed"] == seed}
            models = {}
            for mode in ("call_put", "ordinary_tangent"):
                model = CausalMatcher(mode).eval()
                model.load_state_dict({k: torch.tensor(v) for k, v in records[mode]["state_dict"].items()})
                models[mode] = model
            models["put_linear_mapped"] = mapped_put_linear(models["call_put"]).eval()
            for mode in ("cosine", "time_only_newest"):
                models[mode] = CausalMatcher(mode).eval()
            for mode, model in models.items():
                record = records[mode]
                c_logits, _ = forward_batch(model, calibration)
                c_labels = queues["calibration"][0]
                selected = calibration["observed"][..., 1].numpy() & c_labels[..., :4].any(-1)
                c_scores = c_logits.numpy()
                margins = (c_scores[..., :4].max(-1) - c_scores[..., 4])[selected]
                ordered = sorted(float(x) for x in margins)
                threshold = ordered[math.floor(.05 * (len(ordered)-1))]
                same_float(threshold, record["calibration"]["threshold"], 0)
                np.testing.assert_array_equal(margins, record["calibration"]["margins"])
                assert len(margins) == record["calibration"]["present_queries"]
                calibrated.append({"seed": seed, "mode": mode, "queries": len(margins),
                                   "threshold_exactly_reproduced": True})
                for name, batch in panels.items():
                    logits, state = forward_batch(model, batch)
                    labels, history, oracle_age = queues[name]
                    slots, occupied, age = state
                    final_ids = history[:, -1]
                    np.testing.assert_array_equal(occupied.numpy(), final_ids >= 0)
                    for b in range(len(final_ids)):
                        for j in range(4):
                            if final_ids[b, j] >= 0:
                                np.testing.assert_array_equal(slots[b, j].numpy(), arrays["coco_image"][final_ids[b, j]])
                    np.testing.assert_array_equal(age.numpy()[final_ids >= 0], oracle_age[final_ids >= 0])
                    score = logits[:, -1].numpy()
                    masked = np.where(occupied.numpy(), score[:, :4], -np.inf)
                    chosen = masked.argmax(-1)
                    margin = masked.max(-1) - score[:, 4]
                    active = batch["observed"][:, -1, 1].numpy()
                    present = labels[:, -1, :4].any(-1)
                    accept = active & occupied.numpy().any(-1) & (margin >= threshold)
                    correct = labels[np.arange(len(labels)), -1, chosen] & accept
                    stored = record["panels"][name]
                    np.testing.assert_array_equal(present, stored["present"])
                    np.testing.assert_array_equal(accept, stored["accept"])
                    np.testing.assert_array_equal(correct, stored["correct"])
                    np.testing.assert_array_equal(chosen, stored["chosen_slot"])
                    np.testing.assert_array_equal(margin, stored["margin"])
                    pa, ab = int(present.sum()), int((active & ~present).sum())
                    acp = int((accept & present).sum())
                    cp = int((correct & present).sum())
                    af = int((accept & ~present & active).sum())
                    assert [pa, ab, acp, cp, af] == [stored[k] for k in (
                        "source_present_count", "source_absent_count", "present_accept_count",
                        "present_correct_count", "absent_false_match_count")]
                    same_float(stored["present_correct_alignment"], cp/pa if pa else None)
                    same_float(stored["present_acceptance"], acp/pa if pa else None)
                    same_float(stored["absent_false_match_rate"], af/ab if ab else None)
                    same_float(stored["accepted_present_accuracy"], cp/acp if acp else None)
                    replay.append({"seed": seed, "mode": mode, "panel": name,
                                   "query_count": int(active.sum()), "oracle_state_labels_metrics_exact": True})

                # Independent scorer equivariance with query-only step from an
                # already occupied history; labels are not needed for execution.
                batch = panels["delayed_text"]
                _, state = forward_batch(model, batch)
                permutation_index = torch.tensor([2, 0, 3, 1])
                permuted = tuple(x[:, permutation_index] for x in state)
                query_image = batch["image"][:, -1:]
                query_text = batch["text"][:, -1:]
                obs = torch.zeros(len(query_image), 1, 2, dtype=torch.bool); obs[..., 1] = True
                elapsed = torch.ones(len(query_image), 1)
                original, _ = model(query_image, query_text, obs, elapsed, state)
                moved, _ = model(query_image, query_text, obs, elapsed, permuted)
                expected = torch.cat((original[..., :4][..., permutation_index], original[..., 4:]), -1)
                torch.testing.assert_close(moved, expected, rtol=0, atol=0)
                permutation.append({"seed": seed, "mode": mode, "query_only_permutation_exact": True})

                # Inference decisions must not depend on label-side metadata.
                altered = copy.deepcopy(batch)
                altered["slot_ids"][:] = -777
                altered["query_source"][:] = -888
                altered["target"][:] = False
                original_decisions = decisions(model, batch, threshold)
                altered_decisions = decisions(model, altered, threshold)
                for key in ("accept", "chosen_slot", "margin"):
                    assert original_decisions[key] == altered_decisions[key], (seed, mode, key, "metadata dependence")
                metadata.append({"seed": seed, "mode": mode, "inference_metadata_independent": True})

                # Source-pair diagnostics can be recalculated from saved scores;
                # these are not interpreted as labels on unrelated distractors.
                pair = record["source_pair_ranking"]
                ps, ns = np.asarray(pair["positive_scores"]), np.asarray(pair["negative_scores"])
                pr = (ps > ns).astype(float) + .5*(ps == ns)
                np.testing.assert_array_equal(pr, pair["correct"])
                same_float(pair["accuracy"], pr.mean())

    assert all(digest(root / "research/hcsn" / n) == s for n, s in source_hashes.items()), "source changed during audit"
    result = {"schema": "hcsn.round3.p3.independent-accounting-review.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_sha256": source_hashes,
        "raw_evidence_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "evidence_file_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "evidence_compression": "gzip" if compressed else "none",
        "feature_sha256": digest(features), "audit_source_sha256": digest(__file__),
        "independent_queue_panels": queue_counts, "paired_initialization": init_parity,
        "calibration_replay": calibrated, "complete_metric_replay": replay,
        "query_only_slot_permutation": permutation, "metadata_independence": metadata,
        "no_new_training_or_threshold_selection": True,
        "all_assertions_passed": True, "external_scientific_attestation": False,
        "notes": ["Previously used image subset; exploratory, not untouched independent validation.",
                  "Source provenance matching differs from semantic contradiction or novel-class rejection.",
                  "Irregular-time panel inserts target in final step, so its age is zero; only distractor ages vary.",
                  "Caption rows and seeds sharing an original image are correlated.",
                  "Frozen raw cosine has near-ceiling retrieval; failure of a 2pp uniform-gain criterion is not proof of all possible HCSN hypotheses."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(result, indent=2, allow_nan=False)+"\n")
    print(json.dumps({"output": str(args.output), "all_assertions_passed": True,
                      "model_panel_replays": len(replay), "calibration_replays": len(calibrated),
                      "slot_permutation_checks": len(permutation), "metadata_checks": len(metadata)}))


if __name__ == "__main__":
    main()
