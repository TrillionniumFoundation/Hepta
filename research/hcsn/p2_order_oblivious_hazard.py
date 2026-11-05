"""Research-only falsification of temporal order for the iteration-35 model.

All destination hazards share the same input factor:
    lambda_ij(t) = R_ij * exp(beta*x(t)).
Consequently every mode/parity generator is Q(x)=exp(beta*x)*Q(0),
and a piecewise input stream has transition matrix exp(Q(0)*H), where
H=sum_k dt_k*exp(beta*x_k). Permuting segments preserves H. This
claim is about endpoint distributions/readouts, not event timestamps,
which can differ under permutations. Not a general HCSN impossibility.
"""
from __future__ import annotations
import math
import numpy as np
from scipy.linalg import expm
from research.hcsn.p2_joint_input_hazard import (
    DEFAULT_RATES, InputHazardClock, parity_generator, parity_probability
)


def exposure(segments, beta):
    if not segments:
        raise ValueError('nonempty segments required')
    total=0.0
    for duration, x in segments:
        if not math.isfinite(duration) or duration<=0 or not math.isfinite(x):
            raise ValueError('invalid exposure segment')
        if not math.isfinite(beta) or abs(beta*x)>8:
            raise ValueError('input factor out of validated domain')
        total+=duration*math.exp(beta*x)
    if not math.isfinite(total):
        raise ValueError('exposure overflow')
    return total


def endpoint_distribution(segments,beta,rates=DEFAULT_RATES):
    """Full 4-state endpoint probabilities, independent of input order."""
    h=exposure(segments,beta)
    p=np.array([1.,0.,0.,0.])@expm(parity_generator(rates,0.,0.)*h)
    if not np.isfinite(p).all() or abs(float(p.sum())-1)>1e-9:
        raise ArithmeticError('non-stochastic endpoint distribution')
    return p


def online_endpoint(segments,seed,beta,rates=DEFAULT_RATES):
    """Endpoint (event count, mode) of actual pathwise event clock."""
    clock=InputHazardClock(seed,beta,rates=rates)
    t=0.0
    for duration,x in segments:
        clock.advance(t,t+duration,x)
        t+=duration
    return len(clock.events),clock.mode


def ordered_last_write_pair(duration=0.4,query_duration=0.2):
    """Balanced, fixed-multiset last-write task; labels are last token.

    Input -1.2 means write 0, +0.9 means write 1; query input is
    identical in both sequences. Pairs are exact reverse in the writes.
    """
    if duration<=0 or query_duration<=0:
        raise ValueError('durations must be positive')
    left=[(duration,-1.2),(duration,0.9),(query_duration,0.0)]
    right=[(duration,0.9),(duration,-1.2),(query_duration,0.0)]
    return (left,1),(right,0)


def balanced_pair_endpoint_ceiling(segments_left,segments_right,beta):
    """Best accuracy for equally frequent opposed labels from endpoints.

    For binary labels with conditional endpoint probabilities p0(s),p1(s),
    Bayes accuracy = .5*sum_s max(p0(s),p1(s)). This is a structural
    upper bound even with an unrestricted endpoint classifier.
    """
    a=endpoint_distribution(segments_left,beta)
    b=endpoint_distribution(segments_right,beta)
    return float(np.maximum(a,b).sum()/2.)
