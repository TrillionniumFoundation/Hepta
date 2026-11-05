"""Put plus a linear payoff path: an exact capacity control for the P1 toy kernel.

The simplified stopping features in ``train_study`` obey C - P = u - 1,
where u = v / k. This holds on BOTH sides of the stopping boundary. Therefore
[C, P] and [P, u - 1] are invertible linear coordinates for the same features.
The path is affine in normalized value u, not in every raw public input.

This identity does not identify original He--Xiong equity with a traded call,
solve the original coupled HX system, or prove a neural performance advantage.
The weight mapping below is exact in real arithmetic; floating point errors
are measured separately. Adam in two different parameter coordinates is not
invariant under this mapping, even when the initial functions agree.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

import numpy as np
import torch
from torch.nn import functional as F

try:
    from . import boundary_content_bridge, p1_exact_policy_eval
    from . import p1_hermite_control, p1_tangent_control, train_study
    from .train_study import MatchedHead, MODES, make_data, train_one, two_features
    from .p1_exact_policy_eval import exact_policy_regret, paired_seed_state_ci
    from .p1_hermite_control import HermiteMatchedHead, train_hermite
    from .p1_tangent_control import ANCHOR, TangentMatchedHead, train_tangent
except ImportError:
    import boundary_content_bridge, p1_exact_policy_eval
    import p1_hermite_control, p1_tangent_control, train_study
    from train_study import MatchedHead, MODES, make_data, train_one, two_features
    from p1_exact_policy_eval import exact_policy_regret, paired_seed_state_ci
    from p1_hermite_control import HermiteMatchedHead, train_hermite
    from p1_tangent_control import ANCHOR, TangentMatchedHead, train_tangent


SEEDS = (11, 23, 37)
HOLDOUT_SEEDS = {"id": 77441001, "ood": 77441002}
JACOBIAN_SEED = 77441003


def put_linear_features(x: torch.Tensor) -> torch.Tensor:
    """Return [P, u-1], reusing exactly the previous simplified Put feature.

    We deliberately reuse the upstream construction, including its unused
    intermediate computations. This is a capacity/parameterization control,
    not a claim of a faster kernel.
    """
    if x.ndim != 2 or x.shape[1] != 4:
        raise ValueError("Expected [batch, 4] public inputs")
    p, _, cost, _ = x.unbind(-1)
    v = 2 * torch.minimum(p, 1 - p).clamp(min=1e-5)
    k = 1 + .5 * cost
    put = two_features(x, "dual_call_put")[:, 1]
    return torch.stack((put, v / k - 1), dim=-1)


class PutLinearHead(MatchedHead):
    def __init__(self, width: int = 20):
        super().__init__("dual_call_put", width=width)

    def transformed(self, x: torch.Tensor) -> torch.Tensor:
        return put_linear_features(x)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        features = torch.cat((x[:, :3], x[:, 3:4] / 5, self.transformed(x)), dim=-1)
        return self.out(torch.tanh(self.proj(features))).squeeze(-1)


def mapped_from_dual(model: MatchedHead) -> PutLinearHead:
    """Map a plain dual head's FUNCTION, preserving all learned degrees of freedom.

    w_C*C + w_P*P = (w_C+w_P)*P + w_C*(u-1).
    No bias adjustment is needed because the linear coordinate is u-1.
    Restrict the source class to exclude subclasses with different features.
    """
    if type(model) is not MatchedHead or model.mode != "dual_call_put":
        raise ValueError("Expected the exact simplified dual MatchedHead")
    if model.proj.weight.device.type != "cpu":
        raise ValueError("CPU reference mapping only")
    # Constructing a diagnostic control must not perturb later experiment RNGs.
    with torch.random.fork_rng(devices=[]):
        out = PutLinearHead(model.proj.out_features).to(dtype=model.proj.weight.dtype)
    out.load_state_dict(model.state_dict())
    weight = model.proj.weight.detach()
    with torch.no_grad():
        out.proj.weight[:, 4].copy_(weight[:, 4] + weight[:, 5])
        out.proj.weight[:, 5].copy_(weight[:, 4])
    return out.train(model.training)


def mapped_to_dual(model: PutLinearHead) -> MatchedHead:
    """Inverse real-arithmetic map; it establishes equality of function classes."""
    if type(model) is not PutLinearHead or model.proj.weight.device.type != "cpu":
        raise ValueError("Expected the CPU PutLinearHead reference")
    with torch.random.fork_rng(devices=[]):
        out = MatchedHead("dual_call_put", width=model.proj.out_features).to(
            dtype=model.proj.weight.dtype)
    out.load_state_dict(model.state_dict())
    weight = model.proj.weight.detach()
    with torch.no_grad():
        out.proj.weight[:, 4].copy_(weight[:, 5])
        out.proj.weight[:, 5].copy_(weight[:, 4] - weight[:, 5])
    return out.train(model.training)


def train_put_linear(seed: int, *, function_matched_init: bool,
                     steps: int = 90, train_rows: int = 512):
    """Use the old data and Adam budget; expose initialization and optimizer caveats."""
    torch.manual_seed(seed)
    if function_matched_init:
        model = mapped_from_dual(MatchedHead("dual_call_put"))
    else:
        model = PutLinearHead()
    optimizer = torch.optim.Adam(model.parameters(), lr=.008)
    x, y = make_data(seed + 123000, train_rows)
    start = time.process_time_ns()
    for _ in range(steps):
        optimizer.zero_grad(set_to_none=True)
        loss = F.mse_loss(model(x), 5 * y)
        loss.backward()
        if not all(p.grad is not None and bool(torch.isfinite(p.grad).all())
                   for p in model.parameters()):
            raise ArithmeticError("Missing or nonfinite Put+linear gradient")
        optimizer.step()
    return model.eval(), {
        "seed": seed,
        "mode": "put_linear_function_init" if function_matched_init else "put_linear_same_seed",
        "train_samples": train_rows,
        "optimizer_updates": steps,
        "train_process_cpu_ns": time.process_time_ns() - start,
        "last_train_mse_scaled": float(loss.detach()),
        "trainable_parameters": sum(p.numel() for p in model.parameters()),
        "initial_function_matched_to_dual": function_matched_init,
        "adam_update_equivalence_claimed": False,
    }


def feature_identity_check(x: torch.Tensor) -> dict:
    """Keep the signed derivatives of each feature, rather than their magnitudes."""
    z = x.detach().clone().requires_grad_(True)
    dual = two_features(z, "dual_call_put")
    pl = put_linear_features(z)
    reconstructed = torch.stack((pl[:, 0] + pl[:, 1], pl[:, 0]), dim=-1)
    gaps = []
    for channel in range(2):
        left = torch.autograd.grad(dual[:, channel].sum(), z, retain_graph=True)[0]
        right = torch.autograd.grad(reconstructed[:, channel].sum(), z, retain_graph=True)[0]
        gaps.append((left - right).detach())
    all_gaps = torch.stack(gaps)
    return {
        "rows": len(z), "dtype": str(z.dtype),
        "max_abs_feature_difference": float((dual - reconstructed).abs().max().detach()),
        "max_abs_signed_jacobian_difference": float(all_gaps.abs().max()),
        "max_abs_signed_jacobian_difference_by_input": all_gaps.abs().amax(dim=(0, 1)).tolist(),
        "identity_scope": "simplified train_study features: C-P=u-1, u=v/k",
        "original_hx_identity_claimed": False,
    }


def mapped_function_check(dual: MatchedHead, x: torch.Tensor) -> dict:
    z = x.detach().clone().requires_grad_(True)
    mapped = mapped_from_dual(dual)
    left, right = dual(z), mapped(z)
    jl = torch.autograd.grad(left.sum(), z, retain_graph=True)[0]
    jr = torch.autograd.grad(right.sum(), z)[0]
    return {
        "rows": len(z), "dtype": str(z.dtype),
        "max_abs_logit_difference": float((left - right).abs().max().detach()),
        "different_decisions": int(((left > 0) != (right > 0)).sum()),
        "max_abs_signed_input_jacobian_difference": float((jl - jr).abs().max()),
    }


def capacity(model: torch.nn.Module) -> dict:
    return {
        "trainable_parameters": sum(p.numel() for p in model.parameters() if p.requires_grad),
        "parameter_bytes": sum(p.numel() * p.element_size() for p in model.parameters()),
        "fixed_buffer_elements": sum(b.numel() for b in model.buffers()),
        "fixed_buffer_bytes": sum(b.numel() * b.element_size() for b in model.buffers()),
    }


def tangent_check(x: torch.Tensor) -> dict:
    head = TangentMatchedHead()
    def compare(z):
        z = z.detach().clone().requires_grad_(True)
        a, b = head.transformed(z), two_features(z, "dual_call_put")
        gap = []
        for j in range(2):
            ja = torch.autograd.grad(a[:, j].sum(), z, retain_graph=True)[0]
            jb = torch.autograd.grad(b[:, j].sum(), z, retain_graph=True)[0]
            gap.append(float((ja - jb).abs().max()))
        return {"max_abs_value_difference": float((a - b).abs().max().detach()),
                "max_abs_signed_jacobian_difference": max(gap)}
    return {"anchor": list(ANCHOR),
            "at_anchor": compare(torch.tensor([ANCHOR], dtype=torch.float32)),
            "off_anchor": compare(x), "global_slope_match_claimed": False}


def run(*, smoke: bool = False) -> dict:
    """Exploratory three-seed audit; frozen legacy splits permit direct replay."""
    torch.set_num_threads(1)
    rows, steps, holdout = (40, 3, 24) if smoke else (512, 90, 420)
    splits = {tag: make_data(seed, holdout, ood=(tag == "ood"))[0]
              for tag, seed in HOLDOUT_SEEDS.items()}
    slope_x = make_data(JACOBIAN_SEED, 512, ood=True)[0]
    names = (*MODES, "c1_hermite_null", "ordinary_tangent", "put_linear_same_seed",
             "put_linear_function_init", "put_linear_mapped_after_training")
    raw = {tag: {name: [] for name in names} for tag in splits}
    logs, mapping_checks, init_checks = [], [], []
    hashes, capacities = {}, {}
    for seed in SEEDS:
        train_x, train_y = make_data(seed + 123000, rows)
        hashes[str(seed)] = hashlib.sha256(
            train_x.numpy().tobytes() + train_y.numpy().tobytes()).hexdigest()
        models = {}
        for mode in MODES:
            models[mode], rec = train_one(mode, seed, train_rows=rows, steps=steps)
            models[mode].eval()
            logs.append(rec)
        for name, trainer in (("c1_hermite_null", train_hermite),
                              ("ordinary_tangent", train_tangent)):
            models[name], rec = trainer(seed, steps=steps, train_rows=rows)
            logs.append({"seed": seed, "mode": name, "train_samples": rows,
                         "optimizer_updates": steps, **rec})
        for flag in (False, True):
            model, rec = train_put_linear(seed, function_matched_init=flag,
                                          train_rows=rows, steps=steps)
            models[rec["mode"]] = model
            logs.append(rec)
        dual = models["dual_call_put"]
        models["put_linear_mapped_after_training"] = mapped_from_dual(dual).eval()
        torch.manual_seed(seed)
        initial_dual = MatchedHead("dual_call_put").eval()
        init_checks.append({"seed": seed, **mapped_function_check(initial_dual, slope_x)})
        mapping_checks.append({"seed": seed,
            "float32": mapped_function_check(dual, slope_x),
            "float64": mapped_function_check(copy.deepcopy(dual).double(), slope_x.double())})
        current_capacity = {name: capacity(model) for name, model in models.items()}
        if {entry["trainable_parameters"] for entry in current_capacity.values()} != {161}:
            raise ArithmeticError("Matched head capacity changed")
        capacities[str(seed)] = current_capacity
        for tag, x in splits.items():
            for name, model in models.items():
                raw[tag][name].append(exact_policy_regret(model.eval(), x)["regret"].tolist())
    distributions = {}
    for tag, by_name in raw.items():
        arrays = {name: np.asarray(scores) for name, scores in by_name.items()}
        comparisons = {}
        pairs = [(name, "ordinary_two_gate") for name in names if name != "ordinary_two_gate"]
        pairs += [("dual_call_put", "c1_hermite_null"),
                  ("put_linear_function_init", "dual_call_put"),
                  ("put_linear_same_seed", "dual_call_put"),
                  ("put_linear_mapped_after_training", "dual_call_put")]
        for candidate, reference in pairs:
            comparisons[candidate + "_minus_" + reference] = paired_seed_state_ci(
                arrays[candidate] - arrays[reference], seed=33455 + (tag == "ood"), draws=1000)
        distributions[tag] = {
            "mean_exact_policy_regret": {name: float(values.mean()) for name, values in arrays.items()},
            "per_seed_mean_exact_policy_regret": {name: values.mean(axis=1).tolist()
                                                  for name, values in arrays.items()},
            "paired_differences": comparisons,
        }
    source_modules = [Path(__file__), Path(train_study.__file__),
                      Path(boundary_content_bridge.__file__), Path(p1_exact_policy_eval.__file__),
                      Path(p1_hermite_control.__file__), Path(p1_tangent_control.__file__)]
    repo = Path(__file__).resolve().parents[2]
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True,
                          check=True, capture_output=True).stdout.strip()
    return {
        "schema": "hcsn.p1-put-linear-capacity-control.v1",
        "protocol": {
            "smoke": smoke, "seeds": list(SEEDS), "training_rows": rows,
            "optimizer_updates_per_trained_head": steps, "holdout_rows_per_distribution": holdout,
            "holdout_seeds": HOLDOUT_SEEDS, "holdout_splits_reused_from_legacy_audit": True,
            "holdout_input_sha256": {name: hashlib.sha256(x.numpy().tobytes()).hexdigest()
                                      for name, x in splits.items()},
            "training_input_and_label_sha256": hashes,
            "mapped_after_training_is_not_an_independent_training_run": True,
            "adam_equivalence_under_reparameterization_claimed": False,
            "independent_preregistration": False,
        },
        "algebra": {
            "identity": "C=P+L; L=u-1; u=v/k",
            "dual_to_put_linear_weights": "W_P_new=W_C+W_P; W_L_new=W_C; bias unchanged",
            "inverse_weights": "W_C=W_L_new; W_P=W_P_new-W_L_new",
            "equal_function_class_in_real_arithmetic": True,
            "raw_input_affine_path_claimed": False,
            "scope": "only the simplified stopping features in train_study.py",
        },
        "feature_identity": {"float32": feature_identity_check(slope_x),
                             "float64": feature_identity_check(slope_x.double())},
        "initial_function_mapping_by_seed": init_checks,
        "trained_function_mapping_by_seed": mapping_checks,
        "signed_local_tangent_control": tangent_check(slope_x),
        "model_capacity_by_seed": capacities,
        "by_distribution": distributions,
        "raw_exact_policy_regret_by_distribution_model_seed_state": raw,
        "train_logs": logs,
        "source": {"base_head": base, "executed_source_sha256": {
            str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_modules}},
        "environment": {"python": platform.python_version(), "torch": torch.__version__,
                        "numpy": np.__version__, "torch_cpu_threads": torch.get_num_threads()},
        "matched_backward_flops_proven": False, "real_encoder_used": False,
        "energy_measured": False, "externally_attested": False,
        "p1_scientific_gate": "OPEN", "production_activation": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite prior evidence")
    report = run(smoke=args.smoke)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({"by_distribution": report["by_distribution"],
                      "feature_identity": report["feature_identity"],
                      "gate": report["p1_scientific_gate"]}, indent=2))
