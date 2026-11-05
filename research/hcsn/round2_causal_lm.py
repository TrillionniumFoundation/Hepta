"""End-to-end causal byte LM: internal activation and optimizer-coordinate audit.

Embeddings, causal attention, both FFNs, layer norms and the decoder are trained
together. One or both internal FFNs use the simplified free-boundary features.
This is not a frozen-feature head probe, a pretrained large model, a solved
QVI, or an autonomous continuous-spiking network. The corpus is small, related
repository documentation; document holdout does not create a public benchmark.

For every u>0, C-P=u-1. With immediate affine feature mixing, the coordinate
change (W_C,W_P)->(W_C+W_P,W_C) preserves the whole network function and its
first derivatives in real arithmetic. A canonical Put+linear forward pulls
gradients through this map before Adam; native-coordinate Adam does not.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import platform
import resource
import subprocess
import time

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F


PROTOCOL = "research/hcsn/gates/2026-11-05-round2-causal-lm-protocol.json"
MODES = ("dual", "put_linear_native", "put_linear_canonical", "ordinary_sigmoid_tangent")
R, DELTA, SIGMA = .05, .03, .2
MU = R - DELTA - .5 * SIGMA**2
BETA = (MU + math.sqrt(MU**2 + 2 * R * SIGMA**2)) / SIGMA**2
BOUNDARY = BETA / (BETA + 1)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def call_put(u):
    """Simplified stopping pair; this is not original coupled HX equity."""
    option = (1 - BOUNDARY) * torch.exp(-BETA * torch.log(u / BOUNDARY).clamp(min=0))
    call = torch.where(u > BOUNDARY, u - 1 + option, torch.zeros_like(u))
    put = torch.where(u > BOUNDARY, option, 1 - u)
    return call, put


def ordinary_put(u):
    """Ordinary sigmoid matches P and signed dP/du at u=b, not globally."""
    return 2 * (1 - BOUNDARY) * torch.sigmoid(-2 * (u - BOUNDARY) / (1 - BOUNDARY))


class InternalFFN(nn.Module):
    def __init__(self, width, hidden, mode):
        super().__init__()
        if mode not in MODES:
            raise ValueError("Unknown activation coordinate system")
        self.mode, self.hidden = mode, hidden
        self.input = nn.Linear(width, hidden)
        self.output = nn.Linear(2 * hidden, width)

    def forward(self, x):
        u = .01 + F.softplus(self.input(x))
        if self.mode == "ordinary_sigmoid_tangent":
            features = torch.cat((ordinary_put(u), u - 1), dim=-1)
        else:
            c, p = call_put(u)
            features = torch.cat((c, p) if self.mode == "dual" else (p, u - 1), dim=-1)
        weight = self.output.weight
        if self.mode in ("put_linear_canonical", "ordinary_sigmoid_tangent"):
            wc, wp = weight.split(self.hidden, dim=1)
            weight = torch.cat((wc + wp, wc), dim=1)
        return F.linear(features, weight, self.output.bias)


class CausalBlock(nn.Module):
    def __init__(self, width, heads, hidden, mode):
        super().__init__()
        self.width, self.heads = width, heads
        self.norm_attention = nn.LayerNorm(width)
        self.qkv = nn.Linear(width, 3 * width)
        self.attention_output = nn.Linear(width, width)
        self.norm_ffn = nn.LayerNorm(width)
        self.ffn = InternalFFN(width, hidden, mode)

    def forward(self, x):
        batch, length, width = x.shape
        qkv = self.qkv(self.norm_attention(x)).view(batch, length, 3, self.heads, width // self.heads)
        q, k, v = (qkv[:, :, i].transpose(1, 2) for i in range(3))
        attended = F.scaled_dot_product_attention(q, k, v, dropout_p=0., is_causal=True)
        attended = attended.transpose(1, 2).contiguous().view(batch, length, width)
        x = x + self.attention_output(attended)
        return x + self.ffn(self.norm_ffn(x))


class CausalByteLM(nn.Module):
    def __init__(self, mode="dual", replaced=1, *, width=32, hidden=24,
                 context=64, heads=4):
        super().__init__()
        if mode not in MODES or replaced not in (0, 1, 2) or width % heads:
            raise ValueError("Invalid fixed two-block configuration")
        self.mode, self.replaced = mode, replaced
        self.config = dict(width=width, hidden=hidden, context=context, heads=heads)
        self.token = nn.Embedding(256, width)
        self.position = nn.Embedding(context, width)
        self.blocks = nn.ModuleList([
            CausalBlock(width, heads, hidden,
                        mode if i >= 2 - replaced else "ordinary_sigmoid_tangent")
            for i in range(2)
        ])
        self.norm = nn.LayerNorm(width)
        self.decoder = nn.Linear(width, 256)
        self.apply(self._init)

    @staticmethod
    def _init(module):
        if isinstance(module, (nn.Linear, nn.Embedding)):
            nn.init.normal_(module.weight, mean=0., std=.02)
            if isinstance(module, nn.Linear):
                nn.init.zeros_(module.bias)

    def forward(self, tokens):
        if (tokens.ndim != 2 or tokens.dtype != torch.long or min(tokens.shape) < 1
                or tokens.shape[1] > self.config["context"]):
            raise ValueError("Expected bounded B x T literal byte tokens")
        x = self.token(tokens) + self.position(torch.arange(tokens.shape[1], device=tokens.device))
        for block in self.blocks:
            x = block(x)
        return self.decoder(self.norm(x))


def variant_from_dual(source, mode):
    if source.mode != "dual" or mode not in MODES:
        raise ValueError("Variant requires the canonical dual source")
    replaced = 0 if mode == "ordinary_sigmoid_tangent" else source.replaced
    with torch.random.fork_rng(devices=[]):
        model = CausalByteLM(mode, replaced, **source.config).to(dtype=source.token.weight.dtype)
    model.load_state_dict(source.state_dict())
    if mode == "put_linear_native":
        with torch.no_grad():
            for i in range(2 - source.replaced, 2):
                src, dst = source.blocks[i].ffn, model.blocks[i].ffn
                wc, wp = src.output.weight.split(src.hidden, dim=1)
                dst.output.weight.copy_(torch.cat((wc + wp, wc), dim=1))
    return model.train(source.training)


def native_gradient_in_canonical(name, gradient, model):
    """Pull back native PL gradients through phi=(Wc+Wp,Wc), independently."""
    if model.mode == "put_linear_native" and name.endswith("ffn.output.weight"):
        index = int(name.split(".")[1])
        if index >= 2 - model.replaced:
            gp, gl = gradient.split(model.config["hidden"], dim=1)
            return torch.cat((gp + gl, gp), dim=1)
    return gradient


def load_corpus(root, protocol):
    corpus, records = {}, {}
    for role in ("train", "heldout"):
        corpus[role], records[role] = [], []
        for entry in protocol["corpus"][role]:
            data = (root / entry["path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != entry["sha256"] or len(data) != entry["bytes"]:
                raise ValueError("Frozen corpus changed: " + entry["path"])
            corpus[role].append(data)
            records[role].append(entry)
    if {e["path"] for e in records["train"]} & {e["path"] for e in records["heldout"]}:
        raise ValueError("Whole-document split overlap")
    context = protocol["architecture"]["context"]
    # Whole examples are excluded if their complete input/target span occurs
    # anywhere in training. Short shared vocabulary is not called independent.
    training_spans = {data[i:i + context + 1] for data in corpus["train"]
                      for i in range(len(data) - context)}
    heldout, stats = [], []
    for entry, data in zip(records["heldout"], corpus["heldout"]):
        starts = list(range(0, len(data) - context, context))
        eligible = [i for i in starts if data[i:i + context + 1] not in training_spans]
        maximum = protocol["evaluation"]["max_windows_per_document"]
        if len(eligible) > maximum:
            take = np.linspace(0, len(eligible) - 1, maximum).round().astype(int)
            eligible = [eligible[i] for i in take]
        if not eligible:
            raise ValueError("No disjoint heldout windows")
        pairs = np.stack([np.frombuffer(data[i:i + context + 1], dtype=np.uint8).copy()
                          for i in eligible])
        heldout.append((entry["path"], torch.from_numpy(pairs.astype(np.int64))))
        stats.append({"path": entry["path"], "document_bytes": len(data),
                      "candidate_windows": len(starts),
                      "exact_train_overlap_windows_excluded": sum(
                          data[i:i + context + 1] in training_spans for i in starts),
                      "selected_starts": eligible, "target_bytes": len(eligible) * context,
                      "selected_uint8_sha256": hashlib.sha256(pairs.tobytes()).hexdigest()})
    return corpus["train"], heldout, stats


def training_windows(documents, *, seed, updates, batch, context):
    counts = np.array([len(d) - context for d in documents], dtype=np.int64)
    if bool((counts <= 0).any()):
        raise ValueError("Training document shorter than context")
    ends = np.cumsum(counts)
    draws = np.random.default_rng(seed + 94001103).integers(0, ends[-1], size=updates * batch)
    documents_index = np.searchsorted(ends, draws, side="right")
    offsets = draws - np.r_[0, ends[:-1]][documents_index]
    rows = np.stack([np.frombuffer(documents[d][i:i + context + 1], dtype=np.uint8).copy()
                     for d, i in zip(documents_index, offsets)]).reshape(updates, batch, context + 1)
    receipt = {"seed": seed, "sample_uint8_sha256": hashlib.sha256(rows.tobytes()).hexdigest(),
               "sampling": "uniform over all within-document start positions; never concatenate documents",
               "document_index_and_offset": np.stack((documents_index, offsets), -1).tolist()}
    return torch.from_numpy(rows.astype(np.int64)), receipt


def loss_for(model, pairs):
    logits = model(pairs[:, :-1])
    loss = F.cross_entropy(logits.reshape(-1, 256), pairs[:, 1:].reshape(-1))
    return logits, loss


def evaluate(model, heldout):
    model.eval()
    result = {}
    with torch.inference_mode():
        for name, pairs in heldout:
            window_nll, correct, count = [], 0, 0
            for start in range(0, len(pairs), 8):
                chunk = pairs[start:start + 8]
                logits = model(chunk[:, :-1])
                per_token = F.cross_entropy(logits.reshape(-1, 256), chunk[:, 1:].reshape(-1), reduction="none")
                per_window = per_token.reshape(len(chunk), -1).double().mean(-1)
                window_nll.extend(per_window.tolist())
                correct += int((logits.argmax(-1) == chunk[:, 1:]).sum())
                count += int(per_token.numel())
            prefix = pairs[0:1, :16].clone()
            generated = prefix.clone()
            for _ in range(32):
                logits = model(generated[:, -model.config["context"]:])
                generated = torch.cat((generated, logits[:, -1].argmax(-1)[:, None]), -1)
            future = bytes(generated[0, 16:].tolist())
            target = pairs[0, 16:48]
            result[name] = {"target_bytes": count, "mean_nll_nats": float(np.mean(window_nll)),
                "bits_per_byte": float(np.mean(window_nll) / math.log(2)),
                "teacher_forced_byte_accuracy": correct / count,
                "per_window_nll_nats": window_nll,
                "greedy_prompt_hex": bytes(prefix[0].tolist()).hex(),
                "greedy_continuation_hex": future.hex(),
                "greedy_continuation_utf8_replacement": future.decode("utf-8", errors="replace"),
                "greedy_continuation_byte_accuracy": float((generated[0, 16:] == target).float().mean()),
                "greedy_scope": "32 actual autoregressive next-byte steps, one heldout prompt per document"}
    return result


def parameter_groups_changed(model, initial):
    groups = {"token_and_position": 0., "attention": 0., "internal_ffn": 0., "decoder": 0., "normalization": 0.}
    for name, value in model.named_parameters():
        group = ("token_and_position" if name.startswith(("token.", "position."))
                 else "internal_ffn" if ".ffn." in name
                 else "attention" if ".qkv." in name or ".attention_output." in name
                 else "decoder" if name.startswith("decoder.") else "normalization")
        groups[group] = max(groups[group], float((value.detach() - initial[name]).abs().max()))
    return groups


def train_group(seed, replaced, samples, heldout, protocol, *, include_ordinary):
    config = protocol["architecture"]
    torch.manual_seed(seed)
    base = CausalByteLM("dual", replaced, width=config["width"], hidden=config["feedforward_width"],
                       context=config["context"], heads=config["attention_heads"])
    modes = MODES if include_ordinary else MODES[:3]
    models = {mode: base if mode == "dual" else variant_from_dual(base, mode) for mode in modes}
    initial = {mode: {name: p.detach().clone() for name, p in model.named_parameters()}
               for mode, model in models.items()}
    t = protocol["training"]
    optimizers = {mode: torch.optim.Adam(model.parameters(), lr=t["lr"], betas=tuple(t["betas"]),
                                        eps=t["eps"], weight_decay=0.) for mode, model in models.items()}
    timings = {mode: {"wall_seconds": 0., "process_cpu_seconds": 0.} for mode in modes}
    curves = {mode: [] for mode in modes}
    comparison = {"max_logit_abs_difference": 0., "max_loss_abs_difference": 0.,
                  "max_full_gradient_abs_difference": 0., "max_full_parameter_abs_difference": 0.,
                  "native_initial_pullback_gradient_abs_difference": None,
                  "native_initial_logit_abs_difference": None}
    for step, pairs in enumerate(samples):
        gradients, predictions, losses = {}, {}, {}
        for mode, model in models.items():
            model.train()
            start_w, start_c = time.perf_counter(), time.process_time()
            optimizers[mode].zero_grad(set_to_none=True)
            logits, loss = loss_for(model, pairs)
            loss.backward()
            if not bool(torch.isfinite(loss)) or not all(p.grad is not None and bool(torch.isfinite(p.grad).all())
                                                       for p in model.parameters()):
                raise ArithmeticError("Missing/nonfinite end-to-end gradient")
            # Copy only the two matched gradient sets (and native first step).
            if mode in ("dual", "put_linear_canonical") or (mode == "put_linear_native" and step == 0):
                gradients[mode] = {name: p.grad.detach().clone() for name, p in model.named_parameters()}
                predictions[mode] = logits.detach().clone()
            losses[mode] = float(loss.detach())
            optimizers[mode].step()
            timings[mode]["wall_seconds"] += time.perf_counter() - start_w
            timings[mode]["process_cpu_seconds"] += time.process_time() - start_c
            curves[mode].append(losses[mode])
        comparison["max_logit_abs_difference"] = max(comparison["max_logit_abs_difference"],
            float((predictions["dual"] - predictions["put_linear_canonical"]).abs().max()))
        comparison["max_loss_abs_difference"] = max(comparison["max_loss_abs_difference"],
            abs(losses["dual"] - losses["put_linear_canonical"]))
        for name, grad in gradients["dual"].items():
            comparison["max_full_gradient_abs_difference"] = max(comparison["max_full_gradient_abs_difference"],
                float((grad - gradients["put_linear_canonical"][name]).abs().max()))
        for a, b in zip(models["dual"].parameters(), models["put_linear_canonical"].parameters()):
            comparison["max_full_parameter_abs_difference"] = max(comparison["max_full_parameter_abs_difference"],
                float((a.detach() - b.detach()).abs().max()))
        if step == 0:
            comparison["native_initial_logit_abs_difference"] = float(
                (predictions["dual"] - predictions["put_linear_native"]).abs().max())
            comparison["native_initial_pullback_gradient_abs_difference"] = max(
                float((grad - native_gradient_in_canonical(name, gradients["put_linear_native"][name],
                       models["put_linear_native"])).abs().max()) for name, grad in gradients["dual"].items())
    result = []
    for mode, model in models.items():
        changes = parameter_groups_changed(model, initial[mode])
        if any(v <= 0 for v in changes.values()):
            raise ArithmeticError("An entire encoder/attention/FFN/decoder path was not trained")
        start_w, start_c = time.perf_counter(), time.process_time()
        heldout_results = evaluate(model, heldout)
        evaluation_cost = {"wall_seconds": time.perf_counter() - start_w,
                           "process_cpu_seconds": time.process_time() - start_c}
        result.append({"seed": seed, "mode": mode, "replaced_blocks": model.replaced,
            "trainable_parameters": sum(p.numel() for p in model.parameters()),
            "updates": len(samples), "target_tokens": int(samples.shape[0] * samples.shape[1] * (samples.shape[2] - 1)),
            "training_loss_nats_by_update": curves[mode], "training_cost": timings[mode],
            "parameter_group_max_changes": changes, "heldout": heldout_results,
            "evaluation_and_autoregressive_generation_cost": evaluation_cost})
    return result, comparison


def run(root, *, smoke=False):
    campaign_w, campaign_c = time.perf_counter(), time.process_time()
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    protocol_path = root / PROTOCOL
    protocol = json.loads(protocol_path.read_text())
    if smoke:
        protocol = copy.deepcopy(protocol)
        protocol["training"]["updates"] = 4
        protocol["training"]["seeds"] = [11]
        protocol["evaluation"]["max_windows_per_document"] = 4
    prep_w, prep_c = time.perf_counter(), time.process_time()
    documents, heldout, corpus_stats = load_corpus(root, protocol)
    preparation = {"wall_seconds": time.perf_counter() - prep_w,
                   "process_cpu_seconds": time.process_time() - prep_c}
    rows, comparisons, samples_receipts = [], [], []
    t, a = protocol["training"], protocol["architecture"]
    for seed in t["seeds"]:
        samples, receipt = training_windows(documents, seed=seed, updates=t["updates"],
                                            batch=t["batch"], context=a["context"])
        samples_receipts.append(receipt)
        for replaced in (1, 2):
            results, differences = train_group(seed, replaced, samples, heldout, protocol,
                                                include_ordinary=(replaced == 1))
            rows.extend(results)
            comparisons.append({"seed": seed, "replaced_blocks": replaced, **differences})
            print(json.dumps({"seed": seed, "replaced_blocks": replaced,
                              "canonical_max_parameter_gap": differences["max_full_parameter_abs_difference"],
                              "heldout_bpb": {r["mode"]: {n: v["bits_per_byte"] for n, v in r["heldout"].items()}
                                              for r in results}}), flush=True)
    paired = []
    for seed in t["seeds"]:
        baseline = next(r for r in rows if r["seed"] == seed and r["mode"] == "ordinary_sigmoid_tangent")
        for replaced in (1, 2):
            group = {r["mode"]: r for r in rows if r["seed"] == seed and r["replaced_blocks"] == replaced}
            for name in baseline["heldout"]:
                reference = baseline["heldout"][name]["bits_per_byte"]
                dual = group["dual"]["heldout"][name]["bits_per_byte"]
                paired.append({"seed": seed, "replaced_blocks": replaced, "document": name,
                    "dual_minus_ordinary_bpb": dual - reference,
                    "canonical_minus_dual_bpb": group["put_linear_canonical"]["heldout"][name]["bits_per_byte"] - dual,
                    "native_minus_dual_bpb": group["put_linear_native"]["heldout"][name]["bits_per_byte"] - dual})
    canonical_close = all(abs(r["canonical_minus_dual_bpb"]) <= protocol["evaluation"]["canonical_bpb_roundoff_threshold"]
                          for r in paired)
    consistently_better = all(r["dual_minus_ordinary_bpb"] < 0 for r in paired)
    source = Path(__file__).resolve()
    return {"schema": "hcsn.p1-p5-round2-end-to-end-causal-lm.v1", "smoke": smoke,
        "base_head_before_publication": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_sha256": digest(source), "protocol_sha256": digest(protocol_path), "executed_protocol": protocol,
        "runtime": {"python": platform.python_version(), "torch": torch.__version__, "numpy": np.__version__,
                    "cpu_threads": torch.get_num_threads(), "peak_process_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024},
        "campaign_cost": {"wall_seconds": time.perf_counter() - campaign_w,
                          "process_cpu_seconds": time.process_time() - campaign_c,
                          "scope": "corpus preparation, training, gradient audits, all evaluation and greedy generation; excludes module import and final JSON serialization"},
        "corpus_preparation_cost": preparation, "corpus_window_audit": corpus_stats,
        "training_windows_by_seed": samples_receipts, "rows": rows,
        "full_path_gradient_and_update_comparisons": comparisons, "paired_heldout_differences": paired,
        "canonical_heldout_bpb_within_predeclared_roundoff": canonical_close,
        "dual_better_on_every_seed_document_and_replacement_fraction": consistently_better,
        "negative_closures": {
            "extra_independent_call_information_given_put_and_linear": "CLOSED_NEGATIVE_BY_ALGEBRA_FOR_AFFINE_CONSUMERS",
            "greater_dual_function_capacity_in_these_networks": "CLOSED_NEGATIVE_BY_INVERTIBLE_PARAMETER_MAP",
            "old_bayes_read_dual_superiority": "CLOSED_NEGATIVE_FOR_FIXED_LEGACY_PROTOCOL",
            "canonical_optimizer_equivalence_numeric_check": "SUPPORTED_WITHIN_DECLARED_TOLERANCE" if canonical_close else "NUMERICAL_COUNTEREXAMPLE_REQUIRES_REVIEW",
            "tiny_lm_uniform_positive_gain_criterion": "EXPLORATORY_CRITERION_MET" if consistently_better else "CLOSED_NOT_SUPPORTED_FOR_THIS_FIXED_PROTOCOL"},
        "limitations": [
            "The closed negative hypotheses are scoped questions, not production or entire-phase gate closure.",
            "Only a 32k-parameter two-block byte generator trained from scratch on 55k bytes of related project prose.",
            "One and two FFNs are replaced; attention remains causal attention. No autonomous spiking or optimal-QVI training.",
            "Only full 65-byte overlap is removed; shared short phrases, vocabulary, and subject matter remain.",
            "Heldout documents and windows are reused across training seeds and modes; do not count them as independent corpora.",
            "Equal parameters, target tokens and updates do not imply equal transcendental-operation or backward FLOPs.",
            "Per-mode CPU/wall training includes validation and gradient receipt copies; paired audit overhead is separately described, no latency win is claimed.",
            "Shared host clocks/RSS are descriptive; no energy, production p99, large-model training, or quality-cost frontier is certified.",
        ], "p1_scientific_gate": "OPEN", "p5_scale_gate": "OPEN", "production_activation": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing overwrite of prior evidence")
    root = Path(__file__).resolve().parents[2]
    result = run(root, smoke=args.smoke)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({"canonical_roundoff_pass": result["canonical_heldout_bpb_within_predeclared_roundoff"],
                      "dual_uniform_gain": result["dual_better_on_every_seed_document_and_replacement_fraction"],
                      "production_activation": False}))
