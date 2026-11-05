"""Remove unused analytic work from the ordinary comparator; preserve quality.

No fit or test-driven parameter change. Compare the exact previously published
implementation against the optimized implementation at every frozen checkpoint.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import time

import numpy as np
import torch

from .p3_causal_alignment import CausalMatcher, PANELS, make_stream, forward_batch, mapped_put_linear
from .p3_causal_alignment_evidence import timing
from .p3_round2_study import load_bundle


PUBLISHED = "d431b0b1e86e5bc62d3c38b54f7b2980c6ed515a"


def execute(output):
    output = Path(output)
    if output.exists():
        raise FileExistsError("use a fresh audit path")
    torch.set_num_threads(1)
    root = Path(__file__).resolve().parents[2]
    prior_source = subprocess.check_output(["git", "show", PUBLISHED+":research/hcsn/p3_causal_alignment.py"], cwd=root)
    namespace = {"__name__": "p3_published_cost_reference"}
    exec(compile(prior_source, "<published-d431b0-p3-source>", "exec"), namespace)
    old_class = namespace["CausalMatcher"]
    raw_bytes = gzip.decompress((root/"research/hcsn/gates/2026-11-05-round3-p3-causal-alignment-raw-v2.json.gz").read_bytes())
    raw = json.loads(raw_bytes)
    a, _ = load_bundle(root/"research/hcsn/fixtures/frozen_round2_20261105.npz")
    anchors = np.flatnonzero(a["sugar_split"] == 2)
    panels = {name: make_stream(a, split=2, seed=770031, batch=len(anchors), length=12,
                               scenario=name, anchors=anchors) for name in PANELS}
    numerical, gradients, measurements = [], [], []
    for seed in (101, 113, 127):
        models = {}
        for mode in ("call_put", "ordinary_tangent"):
            row = next(x for x in raw["all_completed_fits"] if x["seed"] == seed and x["mode"] == mode)
            state = {k: torch.tensor(v, dtype=torch.float32) for k, v in row["state_dict"].items()}
            old, new = old_class(mode), CausalMatcher(mode)
            old.load_state_dict(state); new.load_state_dict(state)
            old.eval(); new.eval(); models[mode] = new
            with torch.inference_mode():
                for panel, batch in panels.items():
                    x, sx = forward_batch(old, batch)
                    y, sy = forward_batch(new, batch)
                    exact = torch.equal(x, y) and all(torch.equal(xx, yy) for xx, yy in zip(sx, sy))
                    if not exact:
                        raise AssertionError("removing unused work changed an output")
                    numerical.append({"seed": seed, "mode": mode, "panel": panel, "outputs_and_states_bitwise_equal": exact})
            data = make_stream(a, split=0, seed=994031, batch=3, length=8)
            args = [data[k].clone() for k in ("image", "text", "observed", "dt")]
            args[0].requires_grad_(); args[1].requires_grad_()
            lhs, _ = old(*args); rhs, _ = new(*args)
            go = torch.autograd.grad(lhs.sum(), tuple(old.parameters())+(args[0], args[1]), retain_graph=True)
            gn = torch.autograd.grad(rhs.sum(), tuple(new.parameters())+(args[0], args[1]))
            exact = all(torch.equal(x, y) for x, y in zip(go, gn))
            if not exact:
                raise AssertionError("removing unused work changed a parameter/input gradient")
            gradients.append({"seed": seed, "mode": mode, "all_parameter_and_both_input_gradients_bitwise_equal": exact})
            if mode == "ordinary_tangent":
                models["ordinary_previous_unused_analytic_work"] = old
        models["put_linear_mapped"] = mapped_put_linear(models["call_put"])
        models["cosine"] = CausalMatcher("cosine")
        models["time_only_newest"] = CausalMatcher("time_only_newest")
        batch = make_stream(a, split=2, seed=555031, batch=8, length=12)
        measurements.append({"seed": seed, **timing(models, batch, repeats=80)})
    summary = {}
    for mode in measurements[0]["samples"]:
        values = [v for run in measurements for v in run["samples"][mode]["wall_ns"]]
        summary[mode] = {"samples": len(values), "median_ms": float(np.median(values)/1e6),
                         "p99_ms": float(np.quantile(values, .99)/1e6)}
    result = {"schema": "hcsn.p3.ordinary-unused-work-correction.v1",
        "prior_published_commit": PUBLISHED, "prior_model_source_sha256": hashlib.sha256(prior_source).hexdigest(),
        "current_model_source_sha256": hashlib.sha256(Path(__file__).with_name("p3_causal_alignment.py").read_bytes()).hexdigest(),
        "audit_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "raw_evidence_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "reason": "ordinary previously evaluated the analytic put only to replace it with its sigmoid control; remove that unused work",
        "new_training_fits": 0, "new_threshold_selection": False, "quality_results_unchanged": True,
        "output_checks": numerical, "gradient_checks": gradients, "timings": measurements, "pooled": summary,
        "scope": "randomized one-thread CPU FIFO/scorer/validation; no encoder, network or hardware energy",
        "production_latency_claim": False, "full_system_quality_matched_speedup_claim": False}
    with output.open("x") as f:
        json.dump(result, f, indent=2, allow_nan=False); f.write("\n")
    print(json.dumps({"output": str(output), "outputs_checked": len(numerical), "gradient_checks": len(gradients), "pooled": summary}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--output", required=True)
    execute(parser.parse_args().output)
