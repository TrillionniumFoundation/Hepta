"""Research P2 content-supported continuous-time memory, not an HX/QVI solution.

Four learned rates govern two-state writes. The observed signed payload x_k in
[-1, 1] selects a key/value and multiplies its generator by x_k**2. Consequently
an exactly absent payload has zero hazard. Key routing and zero support are
architectural assumptions from a synthetic task grammar, NOT learned event
labels, a pretrained encoder, or evidence of a free-boundary advantage.

The ordinary exponential-memory control is the coordinate change h=2*p-1 of
this very same transition. It has identical trainable parameters and model
capacity. This deliberately detects misattribution of a holding benefit to HX.
A fixed positive background hazard is the leaky mechanistic control. All labels
are requested last-value answers; no internal state or event time is supervised.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Literal

import numpy as np
from scipy.linalg import expm
import torch
from torch import nn
from torch.nn import functional as F

Mode = Literal['protected_ctmc', 'ordinary_exponential', 'leaky_ctmc']
MODES = ('protected_ctmc', 'ordinary_exponential', 'leaky_ctmc')


def checked_batch(x: torch.Tensor, dt: torch.Tensor) -> None:
    if x.ndim != 3 or x.shape[0] < 1 or x.shape[1] < 1 or x.shape[2] < 1:
        raise ValueError('payload must be nonempty [batch,time,key]')
    if dt.shape != x.shape[:2]:
        raise ValueError('duration shape differs from batch/time')
    if x.dtype != torch.float64 or dt.dtype != torch.float64:
        raise ValueError('this reference requires binary64 tensors')
    if not bool(torch.isfinite(x).all()) or not bool((x.abs() <= 1).all()):
        raise ValueError('payload must be finite in [-1,1]')
    if not bool(torch.isfinite(dt).all()) or not bool((dt > 0).all()):
        raise ValueError('duration must be finite and positive')


class ContentHoldMemory(nn.Module):
    """Exact probability propagation; samples and readouts do not alter state."""

    def __init__(self, mode: Mode, seed: int = 11, *, blank_floor: float = .04):
        super().__init__()
        if mode not in MODES or isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError('invalid mode or seed')
        if not math.isfinite(blank_floor) or blank_floor < 0:
            raise ValueError('invalid background hazard')
        self.mode = mode
        self.blank_floor = blank_floor
        gen = torch.Generator().manual_seed(seed)
        self.raw_rates = nn.Parameter(torch.randn((2, 2), generator=gen, dtype=torch.float64)*.3-.5)

    def write_rates(self) -> torch.Tensor:
        return F.softplus(self.raw_rates) + .005

    def rates_for(self, payload: torch.Tensor) -> torch.Tensor:
        rates = self.write_rates()
        mix = ((1-payload[..., None])/2)*rates[0] + ((1+payload[..., None])/2)*rates[1]
        support = payload[..., None].square()
        floor = self.blank_floor if self.mode == 'leaky_ctmc' else 0.
        return support*mix + floor

    def forward(self, x: torch.Tensor, dt: torch.Tensor, initial=None) -> torch.Tensor:
        checked_batch(x, dt)
        if initial is None:
            p = x.new_full((x.shape[0], x.shape[2]), .5)
        else:
            if initial.shape != (x.shape[0], x.shape[2]) or initial.dtype != x.dtype:
                raise ValueError('invalid initial shape/dtype')
            if not bool(torch.isfinite(initial).all()) or not bool(((initial >= 0)&(initial <= 1)).all()):
                raise ValueError('invalid initial probabilities')
            p = initial
        output = []
        for t in range(x.shape[1]):
            a, b = self.rates_for(x[:, t]).unbind(-1)
            total = a+b
            safe_total = torch.where(total > 0, total, torch.ones_like(total))
            alpha = -torch.expm1(-total*dt[:, t, None])
            if self.mode == 'ordinary_exponential':
                h = 2*p-1
                equilibrium = (a-b)/safe_total
                h = (1-alpha)*h + alpha*equilibrium
                p = (h+1)/2
            else:
                p = p + alpha*(a/safe_total-p)
            output.append(p)
        return torch.stack(output, dim=1)

    @staticmethod
    def query(state: torch.Tensor, keys: torch.Tensor) -> torch.Tensor:
        """Read-only key selection. Query identity never enters the generator."""
        if keys.dtype != torch.long or keys.shape != state.shape[:-1]:
            raise ValueError('invalid query indices')
        if not bool(((keys >= 0)&(keys < state.shape[-1])).all()):
            raise ValueError('query outside key range')
        return state.gather(-1, keys[..., None]).squeeze(-1)


@dataclass(frozen=True)
class TaskBatch:
    payload: torch.Tensor
    duration: torch.Tensor
    query_key: torch.Tensor
    target: torch.Tensor
    query_mask: torch.Tensor


def make_task(seed: int, *, n=64, length=28, keys=4, write_min=.75,
              write_max=1.5, blank_max=2.) -> TaskBatch:
    """Keyed overwrite / multi-query synthetic task with task-only labels.

    The first K inputs fill all keys. Remaining inputs either overwrite one key
    or contain no payload; random requested keys are observed at endpoints. The
    model sees signed payload and physical duration, not a hidden write flag.
    The task grammar itself supplies exact key routing; this is not raw-token
    MQAR and does not train a routing or event-recognition mechanism.
    """
    if any(isinstance(z, bool) or not isinstance(z, int) or z < 1 for z in (seed, n, length, keys)):
        raise ValueError('invalid task size or seed')
    if length <= keys or not 0 < write_min <= write_max or not math.isfinite(write_max):
        raise ValueError('invalid writes')
    if not math.isfinite(blank_max) or blank_max < .05:
        raise ValueError('invalid blank horizon')
    rng = np.random.default_rng(seed)
    x = np.zeros((n, length, keys), dtype=np.float64)
    dt = np.zeros((n, length), dtype=np.float64)
    q = rng.integers(0, keys, size=(n, length), dtype=np.int64)
    y = np.zeros((n, length), dtype=np.float64)
    mask = np.zeros((n, length), dtype=bool)
    for row in range(n):
        truth = np.zeros(keys, dtype=np.float64)
        order = rng.permutation(keys)
        for t in range(length):
            writing = t < keys or rng.uniform() < .6
            if writing:
                key = int(order[t]) if t < keys else int(rng.integers(keys))
                value = float(rng.choice((-1., 1.)))
                x[row, t, key] = value
                truth[key] = float(value > 0)
                dt[row, t] = rng.uniform(write_min, write_max)
            else:
                dt[row, t] = math.exp(rng.uniform(math.log(.05), math.log(blank_max)))
            y[row, t] = truth[q[row, t]]
            mask[row, t] = t >= keys-1 and (rng.uniform() < .4 or t == length-1)
    return TaskBatch(torch.from_numpy(x), torch.from_numpy(dt), torch.from_numpy(q),
                     torch.from_numpy(y), torch.from_numpy(mask))


def task_loss(model: ContentHoldMemory, data: TaskBatch) -> torch.Tensor:
    p = model.query(model(data.payload, data.duration), data.query_key)[data.query_mask]
    y = data.target[data.query_mask]
    # The positive write floor keeps probabilities inside (0,1). No clipping
    # is used to hide a nonfinite or saturated model.
    return -(y*torch.log(p)+(1-y)*torch.log1p(-p)).mean()


def train(mode: Mode, seed: int, *, steps=240, n=64, length=28, lr=.065):
    if isinstance(steps, bool) or not isinstance(steps, int) or not 1 <= steps <= 10000:
        raise ValueError('invalid optimizer budget')
    if not math.isfinite(lr) or lr <= 0:
        raise ValueError('invalid learning rate')
    torch.set_num_threads(1)
    model = ContentHoldMemory(mode, seed)
    data = make_task(seed+103000, n=n, length=length)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    initial = float(task_loss(model, data).detach())
    gradient_min = math.inf
    for _ in range(steps):
        optimizer.zero_grad(set_to_none=True)
        loss = task_loss(model, data)
        if not bool(torch.isfinite(loss)):
            raise ArithmeticError('nonfinite task likelihood')
        loss.backward()
        grad = model.raw_rates.grad
        if grad is None or not bool(torch.isfinite(grad).all()):
            raise ArithmeticError('missing/nonfinite write-rate gradient')
        gradient_min = min(gradient_min, float(grad.abs().min()))
        optimizer.step()
    final = float(task_loss(model, data).detach())
    return model, {'mode': mode, 'seed': seed, 'optimizer_steps': steps, 'train_rows': n,
                   'train_length': length, 'requested_training_answers': int(data.query_mask.sum()),
                   'trainable_parameters': sum(p.numel() for p in model.parameters()),
                   'initial_nll': initial, 'final_nll': final,
                   'min_absolute_rate_gradient': gradient_min,
                   'learned_raw_rates': model.raw_rates.detach().tolist(),
                   'learned_write_rates': model.write_rates().detach().tolist()}


def evaluate(model: ContentHoldMemory, data: TaskBatch):
    with torch.no_grad():
        p = model.query(model(data.payload, data.duration), data.query_key)[data.query_mask]
        y = data.target[data.query_mask]
        correct = y*p+(1-y)*(1-p)
        return {'queries': int(data.query_mask.sum()),
                'expected_sampled_state_accuracy': float(correct.mean()),
                'nll': float(-(y*torch.log(p)+(1-y)*torch.log1p(-p)).mean()),
                'hard_probability_readout_accuracy_diagnostic': float(((p >= .5)==(y > .5)).double().mean())}


def paired_delay(model: ContentHoldMemory, duration: float, *, noise=0.):
    if not math.isfinite(duration) or duration <= 0 or not math.isfinite(noise) or not 0 <= noise <= 1:
        raise ValueError('invalid retention probe')
    x = torch.tensor([[[-1.],[1.],[noise]], [[1.],[-1.],[noise]]], dtype=torch.float64)
    dt = torch.tensor([[1., 1., duration]]*2, dtype=torch.float64)
    with torch.no_grad():
        p = model(x, dt)[:, -1, 0]
        gap = float((p[0]-p[1]).abs())
        return {'duration_s': duration, 'shared_noise_amplitude': noise,
                'p_after_last_one': float(p[0]), 'p_after_last_zero': float(p[1]),
                'balanced_endpoint_bayes_accuracy': .5+.5*gap}


def independent_matrix_reference(model: ContentHoldMemory, x: np.ndarray, dt: np.ndarray,
                                 initial=None) -> np.ndarray:
    """Independent SciPy matrix exponentials, without the transition formula."""
    if x.ndim != 2 or dt.shape != (x.shape[0],) or not np.isfinite(x).all() or (abs(x)>1).any():
        raise ValueError('invalid reference shape/payload')
    if not np.isfinite(dt).all() or (dt<=0).any():
        raise ValueError('invalid reference duration')
    # Only rates are shared. Matrix evolution is a separately implemented path.
    learned = model.write_rates().detach().numpy()
    p = np.full(x.shape[1], .5) if initial is None else np.asarray(initial, dtype=float).copy()
    outputs=[]
    for payload, duration in zip(x, dt):
        for key, value in enumerate(payload):
            a, b = value**2*((1-value)/2*learned[0]+(1+value)/2*learned[1])
            if model.mode=='leaky_ctmc':
                a += model.blank_floor
                b += model.blank_floor
            p[key] = (np.array([1-p[key],p[key]]) @ expm(np.array([[-a,a],[b,-b]])*duration))[1]
        outputs.append(p.copy())
    return np.array(outputs)
