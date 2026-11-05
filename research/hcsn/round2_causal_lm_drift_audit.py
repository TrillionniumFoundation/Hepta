"""Limited diagnostic replay of one completed, frozen LM condition.

The original 21-model evidence is never replaced. This replays only dual and
canonical Put+linear for seed 37, two replaced blocks, and checks every loss
against the already saved trajectory before attributing parameter drift.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import time

import torch

from .round2_causal_lm import (PROTOCOL, CausalByteLM, digest,
                              load_corpus, loss_for, training_windows,
                              variant_from_dual)


def key_bias_slice(name, tensor):
    if name.endswith(".qkv.bias"):
        width = tensor.numel() // 3
        return slice(width, 2 * width)
    return None


def without_key_bias(name, tensor):
    section = key_bias_slice(name, tensor)
    if section is None:
        return tensor
    return torch.cat((tensor[:section.start], tensor[section.stop:]))


def run(root, raw_path):
    start_w, start_c = time.perf_counter(), time.process_time()
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    raw = json.loads(raw_path.read_text())
    protocol = json.loads((root / PROTOCOL).read_text())
    if raw["smoke"] or raw["source_sha256"] != digest(root / "research/hcsn/round2_causal_lm.py"):
        raise ValueError("Requires the original executed source and full evidence")
    if raw["protocol_sha256"] != digest(root / PROTOCOL):
        raise ValueError("Protocol changed after the original run")
    documents, heldout, _ = load_corpus(root, protocol)
    a, t = protocol["architecture"], protocol["training"]
    seed, replaced = 37, 2
    samples, receipt = training_windows(documents, seed=seed, updates=t["updates"],
                                       batch=t["batch"], context=a["context"])
    old_receipt = next(x for x in raw["training_windows_by_seed"] if x["seed"] == seed)
    if receipt != old_receipt:
        raise ValueError("Replayed sample stream differs")
    torch.manual_seed(seed)
    dual = CausalByteLM("dual", replaced, width=a["width"], hidden=a["feedforward_width"],
                       context=a["context"], heads=a["attention_heads"])
    canonical = variant_from_dual(dual, "put_linear_canonical")
    models = {"dual": dual, "put_linear_canonical": canonical}
    optimizers = {mode: torch.optim.Adam(model.parameters(), lr=t["lr"],
        betas=tuple(t["betas"]), eps=t["eps"], weight_decay=0.) for mode, model in models.items()}
    stats = {name: {"maximum_parameter_gap": 0., "maximum_gradient_gap": 0.,
                    "maximum_dual_gradient_abs": 0., "maximum_canonical_gradient_abs": 0.}
             for name, _ in dual.named_parameters()}
    key_stats = {name: {"maximum_parameter_gap": 0., "maximum_dual_gradient_abs": 0.,
                        "maximum_canonical_gradient_abs": 0., "maximum_gradient_gap": 0.}
                 for name, p in dual.named_parameters() if key_bias_slice(name, p) is not None}
    curves = {mode: [] for mode in models}
    max_nonkey_gap, snapshots = 0., []
    for step, pairs in enumerate(samples):
        gradients = {}
        for mode, model in models.items():
            optimizers[mode].zero_grad(set_to_none=True)
            _, loss = loss_for(model, pairs)
            loss.backward()
            gradients[mode] = {name: p.grad.detach().clone() for name, p in model.named_parameters()}
            curves[mode].append(float(loss.detach()))
            optimizers[mode].step()
        for (name, dp), (cn, cp) in zip(dual.named_parameters(), canonical.named_parameters()):
            assert name == cn
            dg, cg = gradients["dual"][name], gradients["put_linear_canonical"][name]
            gap = (dp.detach() - cp.detach()).abs()
            for key, value in (("maximum_parameter_gap", gap.max()),
                               ("maximum_gradient_gap", (dg-cg).abs().max()),
                               ("maximum_dual_gradient_abs", dg.abs().max()),
                               ("maximum_canonical_gradient_abs", cg.abs().max())):
                stats[name][key] = max(stats[name][key], float(value))
            max_nonkey_gap = max(max_nonkey_gap, float(without_key_bias(name, gap).max()))
            section = key_bias_slice(name, dp)
            if section is not None:
                for key, value in (("maximum_parameter_gap", gap[section].max()),
                                   ("maximum_gradient_gap", (dg[section]-cg[section]).abs().max()),
                                   ("maximum_dual_gradient_abs", dg[section].abs().max()),
                                   ("maximum_canonical_gradient_abs", cg[section].abs().max())):
                    key_stats[name][key] = max(key_stats[name][key], float(value))
            if step == len(samples)-1:
                index = int(gap.flatten().argmax())
                stats[name].update({"final_parameter_gap": float(gap.max()),
                    "final_maximum_flat_index": index,
                    "final_dual_value_at_maximum": float(dp.detach().flatten()[index]),
                    "final_canonical_value_at_maximum": float(cp.detach().flatten()[index]),
                    "final_gradient_gap": float((dg-cg).abs().max())})
        if step in (0, 3, 99, len(samples)-1):
            snapshots.append({"step": step+1,
                "max_parameter_gap_so_far": max(v["maximum_parameter_gap"] for v in stats.values()),
                "max_nonkey_bias_parameter_gap_so_far": max_nonkey_gap})
    matches = {}
    for mode in models:
        prior = next(r for r in raw["rows"] if r["seed"] == seed and r["replaced_blocks"] == replaced and r["mode"] == mode)
        matches[mode] = curves[mode] == prior["training_loss_nats_by_update"]
    if not all(matches.values()):
        raise ArithmeticError("Diagnostic replay does not reproduce the original training curves")
    # In exact attention, adding a common bias to every key shifts each query's
    # logit row by a constant. Softmax cancels it. Measure this invariance rather
    # than infer it solely from a parameter name.
    corrected = copy.deepcopy(canonical).eval()
    with torch.no_grad():
        for db, cb in zip(dual.blocks, corrected.blocks):
            width = db.width
            cb.qkv.bias[width:2*width].copy_(db.qkv.bias[width:2*width])
    functional = {}
    dual.eval(); canonical.eval()
    with torch.inference_mode():
        for name, pairs in heldout:
            original_gap = replacement_effect = corrected_gap = 0.
            for start in range(0, len(pairs), 8):
                tokens = pairs[start:start+8, :-1]
                dl, cl, fixed = dual(tokens), canonical(tokens), corrected(tokens)
                original_gap = max(original_gap, float((dl-cl).abs().max()))
                replacement_effect = max(replacement_effect, float((fixed-cl).abs().max()))
                corrected_gap = max(corrected_gap, float((dl-fixed).abs().max()))
            functional[name] = {"dual_vs_canonical_max_logit_gap": original_gap,
                "replacing_only_canonical_key_bias_with_dual_max_logit_effect": replacement_effect,
                "dual_vs_key_bias_corrected_canonical_max_logit_gap": corrected_gap}
    for name, value in key_stats.items():
        for mode, model in models.items():
            p = dict(model.named_parameters())[name]
            section = key_bias_slice(name, p)
            state = optimizers[mode].state[p]
            value[mode+"_final_exp_avg_abs_max"] = float(state["exp_avg"][section].abs().max())
            value[mode+"_final_sqrt_exp_avg_sq_max"] = float(state["exp_avg_sq"][section].sqrt().max())
    return {"schema": "hcsn.round2-one-condition-parameter-drift-audit.v1",
        "source_sha256": digest(__file__), "original_evidence_sha256": digest(raw_path),
        "executed_source_sha256": raw["source_sha256"], "protocol_sha256": raw["protocol_sha256"],
        "seed": seed, "replaced_blocks": replaced, "updates_per_model": len(samples),
        "replayed_models": list(models), "same_sample_receipt": True,
        "bitwise_equal_recorded_loss_curves": matches,
        "max_nonkey_bias_parameter_gap": max_nonkey_gap,
        "per_parameter": stats, "key_bias_subslices": key_stats,
        "snapshots": snapshots, "heldout_logit_diagnostics": functional,
        "interpretation_scope": [
            "This is a post-result targeted numerical diagnostic, not a new efficacy experiment.",
            "Attention key bias is a softmax row-shift null direction in real arithmetic.",
            "FP32 backward can produce small residual key-bias gradients; Adam can accumulate them.",
            "Numerical functional agreement does not assert identical parameter trajectories.",
            "One seed/two-block condition diagnoses its dominant drift; do not infer every parameter in every run has identical behavior."],
        "diagnostic_cost": {"wall_seconds": time.perf_counter()-start_w,
                            "process_cpu_seconds": time.process_time()-start_c}}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Refusing to replace evidence")
    root = Path(__file__).resolve().parents[2]
    result = run(root, args.raw)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False)+"\n")
    print(json.dumps({k: result[k] for k in ("bitwise_equal_recorded_loss_curves", "max_nonkey_bias_parameter_gap", "key_bias_subslices", "diagnostic_cost")}, indent=2))
