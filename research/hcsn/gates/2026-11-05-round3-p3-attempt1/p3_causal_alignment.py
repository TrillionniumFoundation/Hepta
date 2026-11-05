"""Bounded causal matching of real frozen image/text features.

The FIFO is an explicit shared control, not a learned spiking memory. Source
IDs enter the separate label builder only. Edited captions are never labelled
as inconsistent with unrelated candidate images.
"""
from __future__ import annotations

import copy
import math

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F


SLOTS = 4
MODES = ("call_put", "ordinary_tangent", "put_linear", "cosine", "time_only_newest")
PANELS = ("aligned", "delayed_text", "missing_source_frame", "text_gap",
          "irregular_time", "long_blank", "evicted_source")


class CausalMatcher(nn.Module):
    """Shared pair scorer sees both modalities and the actual slot age."""

    def __init__(self, mode="call_put", width=16):
        super().__init__()
        if mode not in MODES or not isinstance(width, int) or width <= 0:
            raise ValueError("bad matcher mode/width")
        self.mode, self.width = mode, width
        if mode not in ("cosine", "time_only_newest"):
            self.input = nn.Linear(17, width)
            self.output = nn.Linear(2 * width, 1)
            nn.init.normal_(self.output.weight, std=.03)
            nn.init.zeros_(self.output.bias)
            self.none_score = nn.Parameter(torch.tensor(5.))

    def score_pairs(self, image, text, age):
        """Inputs are B,K,512 and B,512; no label or slot identity API."""
        text = text[:, None, :].expand_as(image)
        iv, tv = F.normalize(image, dim=-1), F.normalize(text, dim=-1)
        cosine = (iv * tv).sum(-1)
        if self.mode == "time_only_newest":
            return -age
        if self.mode == "cosine":
            return 20 * cosine
        products = (iv * tv).reshape(*image.shape[:2], 8, 64).sum(-1)
        distances = (iv - tv).square().reshape(*image.shape[:2], 8, 64).sum(-1)
        features = torch.cat((products, distances, torch.log1p(age)[..., None]), -1)
        u = .01 + F.softplus(self.input(features))
        # r=.06, delta=.03, sigma=.2 gives beta=2, b=2/3.
        boundary, beta = 2 / 3, 2.
        linear = u - 1
        put = torch.where(u > boundary,
                          (1 - boundary) * torch.exp(-beta * torch.log(u / boundary)),
                          1 - u)
        if self.mode == "ordinary_tangent":
            put = 2 * (1 - boundary) * torch.sigmoid(-2 * (u - boundary) / (1 - boundary))
        channels = torch.cat((put, linear), -1) if self.mode == "put_linear" else torch.cat((put + linear, put), -1)
        return 20 * cosine + self.output(channels).squeeze(-1)

    def initial_state(self, image):
        batch = image.shape[0]
        return (image.new_zeros(batch, SLOTS, 512),
                torch.zeros(batch, SLOTS, dtype=torch.bool, device=image.device),
                image.new_zeros(batch, SLOTS))

    def _validate(self, image, text, observed, dt, state):
        if image.ndim != 3 or image.shape[-1] != 512 or text.shape != image.shape or min(image.shape[:2]) <= 0:
            raise ValueError("nonempty B,T,512 image/text required")
        if not image.is_floating_point() or text.dtype != image.dtype or dt.dtype != image.dtype:
            raise ValueError("matching floating dtypes required")
        if observed.shape != image.shape[:2] + (2,) or observed.dtype != torch.bool or dt.shape != image.shape[:2]:
            raise ValueError("bad observed mask or elapsed time")
        if not all(v.device == image.device for v in (text, observed, dt)):
            raise ValueError("matching devices required")
        if not all(bool(torch.isfinite(v).all()) for v in (image, text, dt)) or bool((dt <= 0).any()):
            raise ValueError("finite payloads and positive elapsed time required")
        if state is not None:
            if not isinstance(state, (tuple, list)) or len(state) != 3:
                raise ValueError("invalid FIFO state")
            slots, valid, age = state
            if (slots.shape != (image.shape[0], SLOTS, 512) or valid.shape != slots.shape[:2]
                    or age.shape != valid.shape or valid.dtype != torch.bool):
                raise ValueError("invalid FIFO state shapes")
            if any(v.device != image.device for v in state) or slots.dtype != image.dtype or age.dtype != image.dtype:
                raise ValueError("invalid FIFO state device/dtype")
            if not bool(torch.isfinite(slots).all() and torch.isfinite(age).all()) or bool((age < 0).any()):
                raise ValueError("invalid FIFO state values")

    def forward(self, image, text, observed, dt, state=None):
        self._validate(image, text, observed, dt, state)
        slots, valid, age = self.initial_state(image) if state is None else state
        logits = []
        for t in range(image.shape[1]):
            age = age + dt[:, t, None]
            oi, ot = observed[:, t, 0], observed[:, t, 1]
            # Unknown image payloads do not enter state; no IDs are used here.
            slots = torch.where(oi[:, None, None],
                                torch.cat((image[:, t, None, :], slots[:, :-1]), 1), slots)
            valid = torch.where(oi[:, None], torch.cat((torch.ones_like(oi[:, None]), valid[:, :-1]), 1), valid)
            age = torch.where(oi[:, None], torch.cat((torch.zeros_like(age[:, :1]), age[:, :-1]), 1), age)
            query = torch.where(ot[:, None], text[:, t], torch.zeros_like(text[:, t]))
            score = self.score_pairs(slots, query, age).masked_fill(~valid, -1e4)
            none = (image.new_tensor(0.) if self.mode == "time_only_newest" else
                    image.new_tensor(5.) if self.mode == "cosine" else self.none_score)
            full = torch.cat((score, none.expand(image.shape[0], 1)), -1)
            logits.append(torch.where(ot[:, None], full, torch.zeros_like(full)))
        return torch.stack(logits, 1), (slots, valid, age)


def mapped_put_linear(model):
    if model.mode != "call_put":
        raise ValueError("mapping requires canonical Call/Put")
    reference = next(model.parameters())
    result = CausalMatcher("put_linear", model.width).to(device=reference.device, dtype=reference.dtype)
    result.load_state_dict(copy.deepcopy(model.state_dict()))
    with torch.no_grad():
        call, put = model.output.weight[:, :model.width], model.output.weight[:, model.width:]
        result.output.weight[:, :model.width] = call + put
        result.output.weight[:, model.width:] = call
    return result


def source_targets(image_ids, text_ids, observed):
    """Independent integer-only FIFO labels; never used inside the model."""
    image_ids, text_ids, observed = np.asarray(image_ids), np.asarray(text_ids), np.asarray(observed)
    if image_ids.ndim != 2 or text_ids.shape != image_ids.shape or observed.shape != image_ids.shape + (2,):
        raise ValueError("invalid label input shapes")
    if observed.dtype != np.bool_:
        raise ValueError("boolean observations required")
    batch, length = image_ids.shape
    slots = np.full((batch, SLOTS), -1, dtype=np.int64)
    history = np.empty((batch, length, SLOTS), dtype=np.int64)
    target = np.zeros((batch, length, SLOTS + 1), dtype=bool)
    for t in range(length):
        yes = observed[:, t, 0]
        slots[yes] = np.concatenate((image_ids[yes, t, None], slots[yes, :-1]), 1)
        history[:, t] = slots
        positive = (slots == text_ids[:, t, None]) & (slots >= 0)
        target[:, t, :SLOTS] = positive
        target[:, t, SLOTS] = ~positive.any(-1)
        target[:, t] &= observed[:, t, 1, None]
    return target, history


def make_stream(a, *, split, seed, batch=16, length=8, scenario=None, anchors=None):
    if split not in (0, 1, 2) or batch <= 0 or length < 8 or scenario not in (None,) + PANELS:
        raise ValueError("bad stream configuration")
    pool = np.flatnonzero(a["sugar_split"] == split)
    if not len(pool):
        raise ValueError("empty split")
    rng = np.random.default_rng(seed)
    ir = rng.choice(pool, (batch, length))
    lag = rng.integers(0, 6, (batch, length))
    tr = rng.choice(pool, (batch, length))
    for b in range(batch):
        for t in range(length):
            if t >= lag[b, t]:
                tr[b, t] = ir[b, t - lag[b, t]]
    observed = rng.random((batch, length, 2)) >= np.array((.25, .20))
    dt = np.exp(rng.uniform(math.log(.1), math.log(4), (batch, length))).astype(np.float32)
    if anchors is not None:
        anchors = np.asarray(anchors, dtype=np.int64)
        if scenario is None or anchors.shape != (batch,) or not np.isin(anchors, pool).all():
            raise ValueError("anchors require a panel and the requested split")
        if length < 12:
            raise ValueError("test panels require at least 12 steps")
        # Exclude this source from random contexts, never by an ID-based model update.
        for b, anchor in enumerate(anchors):
            others = pool[a["sugar_image_index"][pool] != a["sugar_image_index"][anchor]]
            if not len(others):
                raise ValueError("panel needs another original image")
            ir[b] = rng.choice(others, length)
            tr[b] = rng.choice(others, length)
            delay = int(rng.integers(1, 4)) if scenario == "delayed_text" else 0
            source_at = length - 1 - delay
            if scenario in ("missing_source_frame", "text_gap"):
                source_at = length - 3
            elif scenario == "long_blank":
                source_at = length - 5
            elif scenario == "evicted_source":
                source_at = length - 7
            observed[b] = True
            ir[b, source_at], tr[b, -1] = anchor, anchor
            if scenario == "missing_source_frame":
                observed[b, source_at, 0] = False
            elif scenario == "text_gap":
                observed[b, source_at:-1, 1] = False
            elif scenario == "long_blank":
                observed[b, source_at + 1:, 0] = False
                observed[b, source_at + 1:-1, 1] = False
            dt[b] = 1.
            if scenario == "irregular_time":
                dt[b] = np.exp(rng.uniform(math.log(.02), math.log(32), length))
            elif scenario == "long_blank":
                dt[b, source_at + 1:] = 64.
    image_ids, text_ids = a["sugar_image_index"][ir], a["sugar_image_index"][tr]
    target, slots = source_targets(image_ids, text_ids, observed)
    return {"image": torch.from_numpy(a["coco_image"][image_ids].astype(np.float32)),
            "text": torch.from_numpy(a["sugar_positive"][tr].astype(np.float32)),
            "observed": torch.from_numpy(observed), "dt": torch.from_numpy(dt),
            "target": torch.from_numpy(target), "slot_ids": slots,
            "query_source": text_ids, "image_rows": ir, "text_rows": tr}


def forward_batch(model, batch):
    return model(batch["image"], batch["text"], batch["observed"], batch["dt"])


def marginal_loss(logits, target, query_observed):
    if logits.shape != target.shape or target.dtype != torch.bool or query_observed.shape != target.shape[:2]:
        raise ValueError("bad multi-positive target")
    if not bool(query_observed.any()) or not bool(target.any(-1)[query_observed].all()):
        raise ValueError("each observed query needs at least one admissible answer")
    selected = logits[query_observed].log_softmax(-1).masked_fill(~target[query_observed], -torch.inf)
    return -torch.logsumexp(selected, -1).mean()


def pair_scores(model, a, rows):
    image = torch.from_numpy(a["coco_image"][a["sugar_image_index"][rows]].astype(np.float32))[:, None]
    pos = torch.from_numpy(a["sugar_positive"][rows].astype(np.float32))
    neg = torch.from_numpy(a["sugar_negative"][rows].astype(np.float32))
    age = image.new_zeros(len(rows), 1)
    return model.score_pairs(image, pos, age)[:, 0], model.score_pairs(image, neg, age)[:, 0]


def calibrate(model, batch):
    with torch.inference_mode():
        logits, _ = forward_batch(model, batch)
    selected = batch["observed"][..., 1] & batch["target"][..., :SLOTS].any(-1)
    if not bool(selected.any()):
        raise ValueError("calibration needs source-present observed queries")
    margins = (logits[..., :SLOTS].max(-1).values - logits[..., SLOTS])[selected].numpy()
    threshold = float(np.quantile(margins, .05, method="lower"))
    return {"threshold": threshold, "present_queries": len(margins),
            "acceptance": float((margins >= threshold).mean()), "margins": margins.tolist(),
            "source_image_ids": batch["query_source"][selected.numpy()].tolist(),
            "threshold_ties": int((margins == threshold).sum()),
            "test_used_for_threshold": False}


def decisions(model, batch, threshold, *, final_only=True):
    with torch.inference_mode():
        logits, _ = forward_batch(model, batch)
    if final_only:
        score, target, active = logits[:, -1], batch["target"][:, -1], batch["observed"][:, -1, 1]
        source, slots = batch["query_source"][:, -1], batch["slot_ids"][:, -1]
    else:
        active = batch["observed"][..., 1].reshape(-1)
        score = logits.reshape(-1, SLOTS + 1)
        target = batch["target"].reshape(-1, SLOTS + 1)
        source, slots = batch["query_source"].reshape(-1), batch["slot_ids"].reshape(-1, SLOTS)
    chosen = score[:, :SLOTS].argmax(-1)
    margin = score[:, :SLOTS].max(-1).values - score[:, SLOTS]
    valid_slot = torch.from_numpy((slots >= 0).any(-1))
    accept = (margin >= threshold) & valid_slot & active
    present = target[:, :SLOTS].any(-1) & active
    correct = target[torch.arange(len(target)), chosen] & accept
    observed = active.numpy()
    idx = observed.nonzero()[0]
    pa = int(present.sum()); ab = int((active & ~present).sum())
    accepted_present = int((accept & present).sum())
    correct_present = int((correct & present).sum())
    return {"observed_queries": int(active.sum()), "unscored_missing_text": int((~active).sum()),
            "source_present_count": pa, "source_absent_count": ab,
            "present_correct_count": correct_present, "present_accept_count": accepted_present,
            "absent_false_match_count": int((accept & active & ~present).sum()),
            "present_correct_alignment": correct_present / pa if pa else None,
            "present_acceptance": accepted_present / pa if pa else None,
            "absent_false_match_rate": float(accept[active & ~present].float().mean()) if ab else None,
            "accepted_present_accuracy": correct_present / accepted_present if accepted_present else None,
            "source_ids": source[idx].tolist(), "slot_ids": slots[idx].tolist(),
            "present": present.numpy()[idx].tolist(), "accept": accept.numpy()[idx].tolist(),
            "correct": correct.numpy()[idx].tolist(), "chosen_slot": chosen.numpy()[idx].tolist(),
            "margin": margin.numpy()[idx].tolist()}


def train_model(a, seed, mode, *, updates=240, batch_size=16, length=8):
    torch.manual_seed(seed)
    model = CausalMatcher(mode)
    optimizer = torch.optim.Adam(model.parameters(), lr=.003)
    rows = np.flatnonzero(a["sugar_split"] == 0)
    trace = []
    for step in range(updates):
        stream = make_stream(a, split=0, seed=seed * 100000 + step, batch=batch_size, length=length)
        logits, _ = forward_batch(model, stream)
        alignment = marginal_loss(logits, stream["target"], stream["observed"][..., 1])
        sampled = np.random.default_rng(seed * 100000 + step + 50000000).choice(rows, batch_size)
        pos, neg = pair_scores(model, a, sampled)
        ranking = F.softplus(neg - pos).mean()
        loss = alignment + .25 * ranking
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        if not bool(torch.isfinite(loss)) or not all(p.grad is not None and bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
            raise ArithmeticError("nonfinite loss or missing/nonfinite gradient")
        norm = float(nn.utils.clip_grad_norm_(model.parameters(), 5.))
        optimizer.step()
        trace.append({"step": step, "loss": float(loss.detach()), "alignment": float(alignment.detach()),
                      "pair_ranking": float(ranking.detach()), "preclip_gradient_norm": norm})
    return model.eval(), trace
