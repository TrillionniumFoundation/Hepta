"""Research-only P2: exact terminal-state capacity bound for binary MQAR.

Scope: k independent uniform write bits, a keyed query revealed after all
writes, and exactly one observable two-state terminal mode S. The decoder sees
(query index, S), but no event timestamps/history, hidden analog state, clock
that encodes values, or retained external storage. All schedules independent
of the write values. This is an upper bound on any causal stochastic CTMC
with that observation contract, even with optimal learnable/zero-leak gates.
It is NOT an upper bound on full HCSN or on an 8x16 analog memory.
"""
from __future__ import annotations
import argparse
from fractions import Fraction
from itertools import combinations_with_replacement
from math import comb, sqrt
from random import Random
import json
import sys


def analytic_random_query_accuracy(k: int) -> Fraction:
    """Exact optimum: 1/2 + E|Binom(k,1/2)-k/2| / k."""
    if not isinstance(k, int) or isinstance(k, bool) or k < 1 or k > 128:
        raise ValueError('k must be an integer in 1..128')
    absolute_sum = sum(comb(k, j) * abs(2*j-k) for j in range(k+1))
    return Fraction(1, 2) + Fraction(absolute_sum, 2*k*(1 << k))


def independent_codebook_optimum(k: int) -> Fraction:
    """Enumerate every two-decoder-output codebook, NOT using binom formula.

    Given decoded strings u,v, the best encoder chooses the closer Hamming
    prototype for each stored word. Exhausting unordered (u,v) covers every
    deterministic 1-bit encoder/decoder. Randomized strategies cannot improve
    expected 0/1 reward over deterministic extreme points.
    """
    if not 1 <= k <= 7:
        raise ValueError('exhaustive reference limited to k=1..7')
    strings = range(1 << k)
    min_loss = k * (1 << k)
    for u, v in combinations_with_replacement(strings, 2):
        loss = sum(min((x ^ u).bit_count(), (x ^ v).bit_count()) for x in strings)
        if loss < min_loss:
            min_loss = loss
    return Fraction(k*(1 << k)-min_loss, k*(1 << k))


def full_sequence_upper_bound(k: int, terminal_modes: int = 2) -> Fraction:
    """Whole-vector exact match: max one decoded vector per terminal mode."""
    if not isinstance(k, int) or isinstance(k,bool) or not 1 <= k <= 128:
        raise ValueError('invalid k')
    if not isinstance(terminal_modes, int) or isinstance(terminal_modes,bool) or terminal_modes < 1:
        raise ValueError('invalid number of modes')
    return Fraction(min(terminal_modes, 1 << k), 1 << k)


def independent_monte_carlo(k: int, n: int, seed: int) -> dict:
    """Majority encoder + one random keyed query; independent RNG samples."""
    if not 1 <= k <= 128 or n < 1:
        raise ValueError('invalid MC configuration')
    rng = Random(seed)
    successes = 0
    for _ in range(n):
        word = rng.getrandbits(k)
        mode = int(2*word.bit_count() > k)  # tie => 0
        query = rng.randrange(k)
        successes += (mode == ((word >> query) & 1))
    exact = analytic_random_query_accuracy(k)
    p = float(exact)
    z = (successes-n*p)/sqrt(n*p*(1-p))
    return {'k':k, 'seed':seed, 'trials':n, 'correct':int(successes),
            'empirical_accuracy':successes/n, 'expected_accuracy':p,
            'normal_z':z}


def evidence() -> dict:
    exact=[]
    for k in (1,2,3,4,5,6,8,16,32):
        q = analytic_random_query_accuracy(k)
        s = full_sequence_upper_bound(k)
        exact.append({'bits':k,'random_query_optimal_fraction':str(q),
                      'random_query_optimal_float':float(q),
                      'all_queries_exact_upper_fraction':str(s),
                      'all_queries_exact_upper_float':float(s)})
    enumeration=[]
    for k in (1,2,3,4,5,6):
        a=analytic_random_query_accuracy(k)
        b=independent_codebook_optimum(k)
        if a != b:
            raise ArithmeticError('independent exhaustive reference disagrees')
        enumeration.append({'bits':k,'analytic':str(a),'brute':str(b),'match':True})
    simulations=[independent_monte_carlo(k,30000,s) for k,s in
                 ((4,11),(8,23),(16,37),(32,41))]
    if any(abs(s['normal_z'])>5 for s in simulations):
        raise AssertionError('independent MC mismatch')
    return {
      'schema':'hcsn.p2.terminal-ctmc-capacity-negative.v1',
      'scope':'uniform independent binary writes; terminal 2-state observation; post-write random query; no event history or auxiliary memory',
      'proved_full_hcsn':False,'external_independent_acceptance':False,
      'analytic':exact,'exhaustive_codebooks':enumeration,
      'majority_monte_carlo':simulations,
      'gate':{'P'+str(i):'OPEN' for i in range(7)},
      'production_activation':False,
      'status':'NEGATIVE_SUBMODEL_ONLY'}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--strict',action='store_true')
    args=parser.parse_args()
    print(json.dumps(evidence(),sort_keys=True,indent=2))
    if args.strict:
        return 2  # No external trust root; NEVER return zero on this evidence.
    return 0


if __name__=='__main__':
    sys.exit(main())
