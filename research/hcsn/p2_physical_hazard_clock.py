"""Research-only causal continuous-time hazard clock; NOT He-Xiong first-hit law.

Conditioned on a zero-order-held nonnegative rate, integrate compensator time,
then trigger an event whenever an Exp(1) threshold is crossed. Only consumed
hazard beyond the physical refractory endpoint counts toward the next mark.
The same RNG seed is coupled across observations/refinements, drawing ONLY at
actual events, never per token. A change to the underlying rate path, rather
than its discretization, legitimately changes events.

This is a time-rescaled Poisson/renewal control, not a learned HCSN dynamic
boundary, Brownian first passage, He-Xiong QVI, or production event allocator.
P0-P6 remain OPEN; no scientific-performance acceptance is claimed.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


def causal_rate(context: float, bias: float, gain: float) -> float:
    """A trainable-in-principle positive map, evaluated only on present context.

    Weights are frozen in this experiment; not evidence of fitted parameters.
    """
    if not all(math.isfinite(x) for x in (context, bias, gain)):
        raise ValueError('nonfinite rate-map input')
    x = bias + gain * context
    if not math.isfinite(x):
        raise ValueError('overflow in rate-map logit')
    return max(0., x) + math.log1p(math.exp(-abs(x)))


@dataclass
class PhysicalHazardClock:
    seed: int
    refractory: float = 0.0
    max_events_per_interval: int = 100000
    last_end: float = 0.0
    dead_until: float = 0.0
    events: list[float] = field(default_factory=list)
    _rng: random.Random = field(init=False, repr=False)
    _remaining: float = field(init=False, repr=False)

    def __post_init__(self):
        if not math.isfinite(self.refractory) or self.refractory < 0:
            raise ValueError('invalid physical refractory')
        if not isinstance(self.max_events_per_interval, int) or self.max_events_per_interval < 1:
            raise ValueError('invalid event resource budget')
        self._rng = random.Random(self.seed)
        self._remaining = self._rng.expovariate(1.0)

    def advance(self, start: float, end: float, rate: float) -> tuple[float, ...]:
        """Consume a known held intensity on [start,end], returning exact events.

        The caller observes (and may update) rate at `start` only. Intervals must
        be contiguous; this is a causal stream, not a retrospective bridge.
        """
        if not all(math.isfinite(t) for t in (start, end, rate)):
            raise ValueError('nonfinite input')
        if start != self.last_end or end <= start or rate < 0:
            raise ValueError('noncontiguous time, nonpositive dt or negative hazard')
        # Stage all updates locally: even a resource-limit error is atomic.
        trial_rng = random.Random()
        trial_rng.setstate(self._rng.getstate())
        dead_until = self.dead_until
        remaining = self._remaining
        live = max(start, dead_until)
        produced = []
        if live < end and rate > 0:
            while live < end:
                available = rate * (end - live)
                if not math.isfinite(available):
                    raise ValueError('overflowed compensator increment')
                if available < remaining:
                    remaining -= available
                    break
                if len(produced) >= self.max_events_per_interval:
                    raise ValueError('event budget exceeded')
                hit = live + remaining / rate
                if not math.isfinite(hit) or hit > end:
                    raise ValueError('invalid inverse compensated event time')
                produced.append(hit)
                dead_until = hit + self.refractory
                if not math.isfinite(dead_until):
                    raise ValueError('refractory time overflow')
                remaining = trial_rng.expovariate(1.0)
                live = max(hit, dead_until)
        self.last_end = end
        self.dead_until = dead_until
        self._remaining = remaining
        self._rng.setstate(trial_rng.getstate())
        self.events.extend(produced)
        return tuple(produced)
