"""P2 research-only counterexample: token refractory != elapsed-time refractory.

Independent diagnostic on *fixed binary detector traces* with absolute sample
clocks.  This is deliberately not an event-time gradient, a learned neuron,
or an HX QVI solver.  It does not modify the original model or production.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import numpy as np


@dataclass(frozen=True)
class ElapsedFilterState:
    previous_raw: np.ndarray
    last_seen: np.ndarray
    last_applied: np.ndarray


def _admit(raw: np.ndarray, times: np.ndarray, seconds: float, state):
    if not isinstance(raw, np.ndarray) or raw.dtype != np.bool_ or raw.ndim != 2:
        raise ValueError('raw must be an exact boolean [batch,time] ndarray')
    if (not isinstance(times, np.ndarray) or times.dtype != np.float64 or
            times.shape != raw.shape or not (1 <= raw.shape[0] <= 512) or
            not (1 <= raw.shape[1] <= 100000) or raw.size > 1_000_000):
        raise ValueError('times must be finite FP64 [batch,time] in bounded domain')
    if not bool(np.isfinite(times).all()) or not bool((times >= 0.).all()):
        raise ValueError('times must be finite, nonnegative seconds')
    if (type(seconds) not in (float,int) or not math.isfinite(seconds) or
            not 0. <= seconds <= 1e9):
        raise ValueError('invalid duration in seconds')
    if not bool(np.all(np.diff(times,axis=1) > 0)):
        raise ValueError('sample clock must increase strictly')
    n = raw.shape[0]
    if state is None:
        state = ElapsedFilterState(np.zeros(n,dtype=np.bool_),
                                    np.full(n,-np.inf,dtype=np.float64),
                                    np.full(n,-np.inf,dtype=np.float64))
    if (not isinstance(state,ElapsedFilterState) or
            not all(isinstance(a,np.ndarray) and a.shape==(n,) for a in
                (state.previous_raw,state.last_seen,state.last_applied)) or
            state.previous_raw.dtype != np.bool_ or
            state.last_seen.dtype != np.float64 or state.last_applied.dtype != np.float64 or
            not bool(np.all(np.isfinite(state.last_seen) | np.isneginf(state.last_seen))) or
            not bool(np.all(np.isfinite(state.last_applied) | np.isneginf(state.last_applied))) or
            not bool(np.all(times[:,0] > state.last_seen))):
        raise ValueError('invalid/nonmonotone causal streaming state')
    return state


def elapsed_edge_refractory(raw: np.ndarray, times: np.ndarray,
                            *, seconds: float=2.0,
                            state: ElapsedFilterState|None=None):
    """Return accepted events and causal state using an absolute elapsed clock.

    An event is accepted at a rising detector edge only if at least `seconds`
    have elapsed after the last accepted event.  `state` carries the previous
    detector level and last hit across arbitrary nonoverlapping chunks.
    Time is in seconds (not token counts); unchanged event clocks are invariant
    to inserting any samples where raw is False. No training path exists here.
    """
    state = _admit(raw, times, seconds, state)
    previous = state.previous_raw.copy()
    applied_at = state.last_applied.copy()
    accepted = np.zeros_like(raw)
    for t in range(raw.shape[1]):
        rising = raw[:,t] & ~previous
        accepted[:,t] = rising & (
            np.isneginf(applied_at) | ((times[:,t] - applied_at) >= seconds))
        applied_at = np.where(accepted[:,t],times[:,t],applied_at)
        previous = raw[:,t].copy()
    return accepted,ElapsedFilterState(previous,times[:,-1].copy(),applied_at)


def token_edge_refractory(raw: np.ndarray, *, cooldown_tokens: int=2):
    """A fixed-trace reference for the existing token-count policy in #512.

    The actual #512 rollout feeds its own filtered memory back into raw event
    detection; this fixed-trace diagnostic does NOT assert end-to-end parity.
    """
    if (not isinstance(raw,np.ndarray) or raw.ndim != 2 or raw.dtype != np.bool_ or
            raw.shape[0] < 1 or raw.shape[1] < 1 or raw.size>1_000_000 or
            type(cooldown_tokens) is not int or not 0 <= cooldown_tokens <= 1024):
        raise ValueError('invalid token filter inputs')
    prev=np.zeros(raw.shape[0],dtype=np.bool_)
    cooldown=np.zeros(raw.shape[0],dtype=np.int64)
    out=np.zeros_like(raw)
    for t in range(raw.shape[1]):
        out[:,t]=raw[:,t] & ~prev & (cooldown == 0)
        cooldown=np.where(out[:,t],cooldown_tokens,np.maximum(0,cooldown-1))
        prev=raw[:,t].copy()
    return out


def sampling_grid(step_seconds: float):
    """Same six raw detector pulses at integer seconds, distinct null samples."""
    if step_seconds not in (0.25,0.125):
        raise ValueError('only frozen diagnostic sampling steps are allowed')
    k=int(round(5.5/step_seconds))
    times=np.arange(k+1,dtype=np.float64)*step_seconds
    raw=np.isclose(times,np.round(times),rtol=0,atol=0)
    raw &= (times <= 5.)
    return raw[None,:], times[None,:]


def accepted_times(accepted: np.ndarray, times: np.ndarray):
    if accepted.shape != times.shape:
        raise ValueError('incompatible event/time shapes')
    return [[float(v) for v in times[i][accepted[i]]] for i in range(len(accepted))]
