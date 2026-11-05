#!/usr/bin/env python3
"""Create-only round-2 original HX domain/precision audit on the real checkout."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import mpmath as mp
import numpy as np
import scipy
import torch

from research.hcsn.hx_original import HXParams, closed_boundary, equity_green
from research.hcsn.hx_a7_mp_regularized import equity_a7_mp
from research.hcsn.hx_precision_audit import high_precision_boundary
from research.hcsn.hx_interval_domain import (boundary_domain_enclosure,
                                             evaluate_local_mixed_precision)
from research.hcsn.hx_round2_precision import (mp_local_equity, native_literal_hx,
                                             quantized_state_diagnostic)
from research.hcsn.test_hx_precision_audit import WITNESSES


BASE = '5d91fac039437928cee1e3f68d9e9e5d22653633'
SOURCES = (
    'research/hcsn/hx_original.py',
    'research/hcsn/hx_interval_domain.py',
    'research/hcsn/hx_round2_precision.py',
    'research/hcsn/test_hx_round2_domain.py',
    'research/hcsn/2026-11-05-round2-p0-hx-audit.py',
    'research/hcsn/hx_precision_audit.py',
    'research/hcsn/hx_a7_mp_regularized.py',
    'research/hcsn/test_hx_precision_audit.py',
)


def cases():
    invalid = HXParams(r=.10, delta=.075, sigma=.20, alpha=.40, tax=.27,
        xi=4., k=.20, maturity=3., coupon_total=5., face_total=100.)
    return {
        'paper': HXParams(),
        'zero_liquidity': HXParams(xi=0.),
        'tiny_liquidity': HXParams(xi=1e-20, k=1e-15),
        'prior_fp64_boundary_A': WITNESSES[0],
        'prior_fp64_boundary_B': WITNESSES[1],
        'known_negative_local_equity': invalid,
        'same_fp32_sign_plus': replace(invalid, face_total=20., tax=.39990773048821086),
        'same_fp32_sign_minus': replace(invalid, face_total=20., tax=.3999077379072307),
        'green_overflow': HXParams(r=.3, delta=.001, sigma=.03, xi=0.),
        'low_rate_downward_low_sigma': HXParams(r=.005, delta=.2, sigma=.03, xi=0.),
        'short_maturity': HXParams(maturity=.05),
        'long_maturity': HXParams(maturity=10.),
        'zero_recovery': HXParams(alpha=0.),
        'full_recovery': HXParams(alpha=1.),
        'zero_tax': HXParams(tax=0.),
        'tax_below_one': HXParams(tax=math.nextafter(1., 0.)),
        'max_liquidity': HXParams(xi=10., k=.25),
        'high_sigma': HXParams(sigma=.75),
        'tiny_positive_cashflows': HXParams(coupon_total=1e-300, face_total=1e-300),
        'no_positive_eq12_candidate': HXParams(tax=.99, coupon_total=500., face_total=.0001),
    }


def snapshot_hashes():
    return {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES}


def original_green_failure():
    source = subprocess.check_output(['git', 'show', BASE+':research/hcsn/hx_original.py'], cwd=ROOT)
    module = types.ModuleType('_round2_exact_base_hx_original')
    sys.modules[module.__name__] = module
    exec(compile(source, BASE+':hx_original.py', 'exec'), module.__dict__)
    p = module.HXParams(r=.3, delta=.001, sigma=.03, xi=0.)
    boundary = module.closed_boundary(p)
    rows = []
    for x in (2., 8.):
        try:
            previous = {'value': module.equity_green(boundary*math.exp(x), boundary, p)}
        except Exception as exc:
            previous = {'exception': type(exc).__name__, 'reason': str(exc)}
        now = HXParams(**asdict(p))
        current = equity_green(boundary*math.exp(x), boundary, now)
        independent = equity_a7_mp(boundary*math.exp(x), now, boundary, dps=90)
        rows.append({'log_margin': x, 'before': previous, 'after': current,
                     'mp90_a7_same_supplied_boundary': independent,
                     'absolute_difference_after_vs_mp90': abs(current-independent)})
    return {'exact_base': BASE, 'base_source_sha256': hashlib.sha256(source).hexdigest(),
            'parameters': asdict(p), 'supplied_raw_fp64_boundary': float(boundary), 'rows': rows}


def run():
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    start = time.monotonic()
    names = cases()
    domains = []
    for name, p in names.items():
        try:
            truth = high_precision_boundary(p, digits=120)
            reference = {'mp120_boundary': mp.nstr(truth, 120)}
            try:
                raw = closed_boundary(p)
                reference['raw_fp64_boundary'] = float(raw)
                reference['raw_relative_error'] = float(abs(truth.context.mpf(raw)-truth)/truth)
            except Exception as exc:
                reference['raw_failure'] = f'{type(exc).__name__}: {exc}'
        except Exception as exc:
            truth = None
            reference = {'mp120_failure': f'{type(exc).__name__}: {exc}'}
        for dtype in (None, 'fp32', 'bf16'):
            row = {'case': name, 'parameters': asdict(p), 'format': dtype or 'exact_binary64', **reference}
            try:
                row['enclosure'] = boundary_domain_enclosure(p, dtype=dtype)
                if truth is not None:
                    bounds = row['enclosure']['boundary']
                    c = truth.context
                    row['mp120_original_point_contained'] = bool(c.mpf(bounds['lower']) <= truth <= c.mpf(bounds['upper']))
            except Exception as exc:
                row['failure'] = f'{type(exc).__name__}: {exc}'
            domains.append(row)

    mixed, reference_cache = [], {}
    selected = ('paper', 'zero_liquidity', 'prior_fp64_boundary_A',
                'prior_fp64_boundary_B', 'zero_recovery',
                'known_negative_local_equity', 'green_overflow')
    for name in selected:
        p = names[name]
        for x in (1e-8, 1e-5, 1e-4, 1e-3):
            truth = mp_local_equity(x, p, digits=100)
            reference_cache[name, x] = truth
            for dtype in ('fp32', 'bf16'):
                result = evaluate_local_mixed_precision(x, p, output_dtype=dtype)
                c = truth.context
                lo, hi = (result['certificate']['equity'][k] for k in ('lower', 'upper'))
                row = {'case': name, 'parameters': asdict(p), 'log_margin': x,
                       'mp100_independent_green_equity': c.nstr(truth, 100),
                       'independent_mp_equity_contained': bool(c.mpf(lo) <= truth <= c.mpf(hi)),
                       'result': result}
                if result['candidate_value'] is not None:
                    error = abs(c.mpf(result['candidate_value'])-truth)
                    row['actual_absolute_error'] = float(error)
                    row['actual_relative_error'] = float(error/abs(truth))
                    row['actual_error_below_certificate'] = bool(error <= c.mpf(result['absolute_error_bound']))
                mixed.append(row)

    native = []
    for name in ('paper', 'prior_fp64_boundary_A', 'prior_fp64_boundary_B', 'zero_liquidity'):
        p = names[name]
        for x in (1e-8, 1e-3):
            truth = reference_cache[name, x]
            c = truth.context
            for dtype in ('fp32', 'bf16'):
                result = native_literal_hx(x, p, dtype)
                row = {'case': name, 'log_margin': x, 'result': result,
                       'original_parameter_mp_equity': c.nstr(truth, 100)}
                try:
                    encoded = HXParams(**result['input_parameters'])
                    encoded_root = high_precision_boundary(encoded, digits=100)
                    encoded_equity = mp_local_equity(result['direct_log_margin'], encoded, digits=100)
                    row['quantized_parameter_mp_boundary'] = encoded_root.context.nstr(encoded_root, 100)
                    row['quantized_parameter_mp_equity'] = encoded_equity.context.nstr(encoded_equity, 100)
                    row['parameter_and_state_quantization_absolute_effect'] = float(abs(encoded_equity-truth))
                    if result.get('equity') is not None:
                        row['native_arithmetic_absolute_error_at_encoded_inputs'] = float(abs(c.mpf(result['equity'])-encoded_equity))
                        row['total_absolute_error_vs_original_inputs'] = float(abs(c.mpf(result['equity'])-truth))
                except Exception as exc:
                    row['encoded_model_reference_failure'] = f'{type(exc).__name__}: {exc}'
                native.append(row)

    states = [quantized_state_diagnostic(x, names['paper'], dtype)
              for x in (-1e-8, 0., 1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3)
              for dtype in ('fp32', 'bf16')]
    classifications = {}
    for dtype in ('exact_binary64', 'fp32', 'bf16'):
        classifications[dtype] = dict(Counter(
            row.get('enclosure', {}).get('status', 'EXPLICIT_ARITHMETIC_REFUSAL')
            for row in domains if row['format'] == dtype))
    accepted = [row for row in mixed if row['result']['value'] is not None]
    summary = {
        'frozen_parameter_cases': len(names), 'domain_enclosures_attempted': len(domains),
        'domain_status_counts': classifications,
        'mp120_point_containment_checks': sum('mp120_original_point_contained' in row for row in domains),
        'all_checked_mp120_points_contained': all(row.get('mp120_original_point_contained', True) for row in domains),
        'mixed_evaluations': len(mixed), 'accepted_mixed_evaluations': len(accepted),
        'mixed_status_counts': dict(Counter(row['result']['status'] for row in mixed)),
        'all_independent_mp_local_values_contained': all(row['independent_mp_equity_contained'] for row in mixed),
        'all_observed_errors_below_certificates': all(row.get('actual_error_below_certificate', False) for row in mixed),
        'accepted_max_relative_certificate_by_format': {
            dtype: max(row['result']['relative_error_bound'] for row in accepted if row['result']['output_dtype'] == dtype)
            for dtype in ('fp32', 'bf16')},
        'native_literal_status_counts': dict(Counter(row['result']['status'] for row in native)),
        'state_rows': len(states),
        'general_original_hx_domain_closed': False,
        'native_all_bf16_operator_certified': False,
        'phase_gate_closed': False,
    }
    return {
        'schema': 'hcsn.p0.round2.original-hx-enclosed-domain.v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'base_head': BASE,
        'checkout_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_sha256': snapshot_hashes(),
        'runtime': {'python': platform.python_version(), 'numpy': np.__version__,
                    'scipy': scipy.__version__, 'mpmath': mp.__version__, 'torch': torch.__version__,
                    'torch_threads': torch.get_num_threads(), 'torch_interop_threads': torch.get_num_interop_threads(),
                    'wall_seconds': time.monotonic()-start},
        'summary': summary,
        'green_overflow_regression': original_green_failure(),
        'domain_rows': domains, 'mixed_rows': mixed, 'native_literal_rows': native, 'state_rows': states,
        'references': ['https://www.princeton.edu/~wxiong/papers/rollover.pdf',
                       'https://mpmath.org/doc/1.3.0/contexts.html'],
        'limits': [
            'Sufficient fixed-debt stopping theorem is not necessary and does not prove equilibrium uniqueness under repriced deviations.',
            'mpmath basic interval operations are a trusted arithmetic dependency, not an independently machine-checked or IEEE-1788-validated kernel.',
            'Quantized input boxes assume the original input belonged to the explicitly declared legal binary64 prior domain.',
            'Local mixed precision retains original binary64 parameters and directly tracked log margin; accumulation is FP32, optional output storage BF16.',
            'Native literal tests do not establish a stable full-domain A7, derivatives, GPU code, throughput, recurrent control, or neural benefit.',
            'Finite diagnostic cases validate the implementation; the boxed domain claim derives from interval inclusion and the stated analytic theorem.',
            'No production or external independent-science gate is modified or self-attested.',
        ],
        'production_activation': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite an existing receipt')
    result = run()
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False)+'\n')
    print(json.dumps(result['summary'], indent=2, sort_keys=True))
