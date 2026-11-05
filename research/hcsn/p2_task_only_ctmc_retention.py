"""HCSN P2 / iteration 38: independently test finite-memory loss under ongoing positive hazard.

This intentionally narrow two-state continuous-time Markov control is NOT an
He-Xiong first passage process, neural dynamic boundary, multi-reset proof,
or scientific P0-P6 qualification. Its input-conditioned write generators can
be learned solely from final last-write task labels, without event supervision.

For a held symbol x, rates a_x (0->1), b_x (1->0) give
    p1(t+dt) = pi_x + (p1(t)-pi_x)*exp(-(a_x+b_x)*dt)
where pi_x=a_x/(a_x+b_x). Blank rates have enforced floor >= leak_floor.
A blank delay D erases any paired endpoint difference by the *exact* factor
exp(-(a_blank+b_blank)*D); therefore balanced endpoint Bayes accuracy satisfies
    accuracy <= 1/2 + exp(-2*leak_floor*D)/2.

Uses a differentiable exact transition (Torch) for task-only training. SciPy
solve_ivp/expm numerical references are intentionally separate.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Sequence

import numpy as np
from scipy.integrate import solve_ivp
from scipy.linalg import expm

SYMBOLS = (0, 1, 2)  # 2 denotes blank, not an observed write


def checked_schedule(schedule: Sequence[tuple[float, int]]) -> None:
    if not schedule:
        raise ValueError('empty schedule')
    for duration, symbol in schedule:
        if not isinstance(symbol, int) or isinstance(symbol, bool) or symbol not in SYMBOLS:
            raise ValueError('invalid symbol')
        if not math.isfinite(duration) or duration <= 0:
            raise ValueError('invalid physical duration')


def checked_rates(rates: Sequence[Sequence[float]]) -> np.ndarray:
    r = np.asarray(rates, dtype=np.float64)
    if r.shape != (3, 2) or not np.isfinite(r).all() or (r < 0).any():
        raise ValueError('need finite nonnegative rates shaped [3,2]')
    return r


def exact_probability(schedule: Sequence[tuple[float, int]], rates: Sequence[Sequence[float]]) -> float:
    checked_schedule(schedule)
    r = checked_rates(rates)
    p = 0.0
    for duration, symbol in schedule:
        a, b = r[symbol]
        total = a + b
        if total != 0:
            p = a / total + (p-a / total)*math.exp(-float(total)*duration)
    return p


def independent_ode(schedule: Sequence[tuple[float, int]], rates: Sequence[Sequence[float]]) -> float:
    checked_schedule(schedule)
    r = checked_rates(rates)
    state = [0.0]
    for duration, symbol in schedule:
        a, b = r[symbol]
        sol = solve_ivp(lambda _t, y: [a-(a+b)*y[0]], (0, duration), state,
                        method='DOP853', rtol=2e-13, atol=2e-14)
        if not sol.success:
            raise ArithmeticError(sol.message)
        state = sol.y[:, -1]
    return float(state[0])


def independent_expm(schedule: Sequence[tuple[float, int]], rates: Sequence[Sequence[float]]) -> float:
    checked_schedule(schedule)
    r = checked_rates(rates)
    v = np.array([1., 0.])
    for duration, symbol in schedule:
        a, b = r[symbol]
        v = v @ expm(np.array([[-a, a], [b, -b]])*duration)
    return float(v[1])


def independent_event_path(schedule: Sequence[tuple[float, int]],
                           rates: Sequence[Sequence[float]], seed: int) -> tuple[int, int]:
    """Independent Gillespie/event-time simulation, returns (final state, #events).

    This generates *autonomous events*, not smoothed deterministic endpoints.
    RNG is distinct from training; boundaries do not reveal future inputs.
    """
    checked_schedule(schedule)
    r = checked_rates(rates)
    rng = random.Random(seed)
    state = 0
    n_events = 0
    for duration, symbol in schedule:
        remaining = duration
        while remaining > 0:
            hazard = float(r[symbol, state if state == 0 else 1])
            # row rates are (0 -> 1, 1 -> 0); event always switches mode.
            if hazard == 0: break
            wait = rng.expovariate(hazard)
            if wait >= remaining: break
            remaining -= wait
            state = 1-state
            n_events += 1
            if n_events >= 100000:
                raise ValueError('autonomous event budget exceeded')
    return state, n_events


def exact_blank_decay(write_a: Sequence[tuple[float, int]],
                      write_b: Sequence[tuple[float, int]],
                      blank_duration: float, rates: Sequence[Sequence[float]]) -> float:
    """Paired endpoint separation, independent of stationary blank probability."""
    r = checked_rates(rates)
    if not math.isfinite(blank_duration) or blank_duration < 0:
        raise ValueError('invalid blank duration')
    p_a = exact_probability(write_a, r)
    p_b = exact_probability(write_b, r)
    return abs(p_b-p_a)*math.exp(-float(sum(r[2]))*blank_duration)


def bayes_balanced_accuracy(write_a, write_b, blank_duration, rates) -> float:
    return .5 + exact_blank_decay(write_a, write_b, blank_duration, rates)/2


def physical_split(schedule, n: int):
    if not isinstance(n, int) or isinstance(n, bool) or n < 1 or n > 1000:
        raise ValueError('invalid refinement count')
    checked_schedule(schedule)
    return [(duration / n, symbol) for duration, symbol in schedule for _ in range(n)]


@dataclass(frozen=True)
class TrainResult:
    seed: int
    steps: int
    rates: tuple[tuple[float, float], ...]
    initial_loss: float
    final_loss: float
    grad_norm: float


def _torch_task_prob(raw, schedule, floor):
    import torch
    rates = torch.nn.functional.softplus(raw) + floor
    p = torch.zeros((), dtype=torch.float64)
    for duration, symbol in schedule:
        a, b = rates[symbol].unbind()
        z = a+b
        p = a/z + (p-a/z)*torch.exp(-z*duration)
    return p


def train_task_only(seed: int, steps: int = 420, lr: float = .065, leak_floor: float = .04) -> TrainResult:
    """Optimize six rates using *only* final labels; delay trains in [0,2]."""
    import torch
    if not isinstance(seed, int) or not 1 <= steps <= 20000 or not math.isfinite(lr) or lr <= 0:
        raise ValueError('invalid training configuration')
    if not math.isfinite(leak_floor) or not .0 <= leak_floor <= .5:
        raise ValueError('invalid blank rate floor')
    torch.manual_seed(seed)
    # Small random initial rates; neither event times nor hidden states are observed.
    raw = torch.nn.Parameter(torch.randn((3, 2), dtype=torch.float64)*.3-.5)
    optim = torch.optim.Adam([raw], lr=lr)
    schedules = [(a, b, delay) for a in (0,1) for b in (0,1) for delay in (0., .5,1.,2.)]
    initial = final = grad_norm = None
    for step in range(steps):
        optim.zero_grad()
        losses = []
        for a,b,delay in schedules:
            schedule = [(1.,a),(1.,b)] + ([(delay,2)] if delay>0 else [])
            p = _torch_task_prob(raw, schedule, leak_floor)
            losses.append(-torch.log(p if b==1 else 1-p))
        loss = torch.stack(losses).mean()
        if step == 0: initial = float(loss.item())
        if not torch.isfinite(loss): raise ArithmeticError('nonfinite task-only loss')
        loss.backward()
        grad_norm = float(torch.linalg.vector_norm(raw.grad).item())
        optim.step()
        final = float(loss.item())
    rates = (torch.nn.functional.softplus(raw.detach()) + leak_floor).numpy()
    return TrainResult(seed, steps, tuple(tuple(float(v) for v in row) for row in rates), initial, final, grad_norm)


def reproduce(seed: int = 11, steps: int = 420, floor: float = .04):
    trained = train_task_only(seed, steps, leak_floor=floor)
    r = np.asarray(trained.rates)
    # Same multiset, opposite final last-write label. Keep write duration fixed.
    A = [(1.,1),(1.,0)]  # last 0
    B = [(1.,0),(1.,1)]  # last 1
    outputs = []
    for delay in (0., 1., 4., 16., 64., 256.):
        sa = A + ([(delay, 2)] if delay else [])
        sb = B + ([(delay, 2)] if delay else [])
        pa,pb = exact_probability(sa,r),exact_probability(sb,r)
        outputs.append({'blank_s': delay, 'p_state1_last0': pa, 'p_state1_last1': pb,
                        'abs_gap': abs(pb-pa), 'bayes_accuracy': (.5+.5*abs(pb-pa)),
                        'uniform_floor_upper_bound': .5+.5*math.exp(-2*floor*delay)})
    return {'seed': seed, 'steps': steps, 'train_initial_loss': trained.initial_loss,
            'train_final_loss': trained.final_loss, 'last_grad_norm': trained.grad_norm,
            'six_learned_rates': [list(x) for x in trained.rates],
            'blank_rate_sum': float(sum(r[2])), 'heldout_blank_lengths': outputs}
