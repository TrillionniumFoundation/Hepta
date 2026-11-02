"""Research-only P2 candidate: exact physical-time EMA for held observations.

Under a zero-order-held context c on one observed interval of duration dt,
L'=(c-L)/4 and V'=(|c-L|-V)/tau, tau=-1/log(0.9).
The exact semigroup update is differentiable in c, L, V, and dt away from
absolute-value kinks. It deliberately does NOT infer unobserved first hits.

This is a P2 hypothesis only, not an original He-Xiong QVI solution, a
stochastic-event-time estimator, FLOP-matched P1 evidence, or production code.
P0-P6 remain OPEN and production activation remains false.
"""
from __future__ import annotations

import math
import torch
from torch.nn import functional as F
from research.hcsn.p2_no_event_dynamic_boundary import CausalBoundary, DIM, NKEYS, State

LEVEL_TIME = 4.0
VOL_TIME = -1.0 / math.log(0.9)


def exact_held_context_step(level: torch.Tensor, volatility: torch.Tensor,
                            context: torch.Tensor, dt: torch.Tensor):
    """Exact integration of deterministic held-context ODE, not a Brownian QVI.

    No labels, future observations, stochastic bridges or event times consumed.
    Cancellation-safe expm1 expression. Inputs retain gradients.
    """
    if not (level.shape == volatility.shape == context.shape == dt.shape):
        raise ValueError('all clock fields must have matching shape')
    if not (bool(torch.isfinite(level).all()) and bool(torch.isfinite(volatility).all())
            and bool(torch.isfinite(context).all()) and bool(torch.isfinite(dt).all())):
        raise ValueError('nonfinite clock input')
    if not bool((dt > 0).all()):
        raise ValueError('nonpositive elapsed time')
    decay_level = torch.exp(-dt / LEVEL_TIME)
    decay_vol = torch.exp(-dt / VOL_TIME)
    forcing = (decay_vol * torch.expm1(dt * (1.0 / VOL_TIME - 1.0 / LEVEL_TIME))
               / (1.0 - VOL_TIME / LEVEL_TIME))
    next_level = context + (level - context) * decay_level
    next_vol = volatility * decay_vol + torch.abs(context - level) * forcing
    return next_level, next_vol


class ClockCorrectedBoundary(CausalBoundary):
    """Exactly 4 trainable scalars; no new event labels or privileged inputs."""

    def __init__(self):
        super().__init__('dynamic')

    def step(self, xt: torch.Tensor, state: State, *, hard: bool):
        if xt.ndim != 2 or xt.shape[1] != DIM or xt.shape[0] != len(state.memory):
            raise ValueError('expected [batch,DIM] and matched state')
        if not bool(torch.isfinite(xt).all()) or not bool(((xt[:,NKEYS+4] > 0) & (xt[:,NKEYS+4] <= 4)).all()):
            raise ValueError('invalid observation or positive time increment')
        ctx = xt[:,NKEYS+3]
        delta = torch.abs(ctx - state.level)
        next_level, next_vol = exact_held_context_step(state.level, state.volatility, ctx, xt[:,NKEYS+4])
        boundary = F.softplus(self.threshold + self.sensitivity * state.volatility)
        event = (delta > boundary) & state.initialized
        if hard:
            erase = event.to(delta.dtype)
        else:
            erase = torch.sigmoid(8.0 * (delta-boundary))*state.initialized.to(delta.dtype)
        memory = state.memory * (1.0-erase[:,None])
        write = xt[:,NKEYS+1:NKEYS+2]*xt[:,:NKEYS]
        memory = memory*(1.0-write)+write*xt[:,NKEYS:NKEYS+1]
        nxt = State(memory,next_level,next_vol,torch.ones_like(state.initialized))
        read = (memory*xt[:,:NKEYS]).sum(dim=-1)
        logit = self.output_gain*read+self.output_bias
        return nxt,logit,event
