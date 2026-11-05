"""Create-only round-3 original-HX global-obstacle evidence.

The continuous proof is interval coverage plus the analytic infinite-tail
bound.  MP100 samples and Green integrals below are independent numerical
implementation checks, never substitutes for that proof.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import time

import mpmath as mp

try:
    from .hx_original import HXParams
    from .hx_precision_audit import high_precision_boundary
    from .hx_global_obstacle import global_obstacle_enclosure
except ImportError:
    from hx_original import HXParams
    from hx_precision_audit import high_precision_boundary
    from hx_global_obstacle import global_obstacle_enclosure


class IndependentMPReference:
    """Eq8 values differentiated by mpmath, without interval derivative code.

    Original binary64 parameters are converted EXACTLY to the cloned MP
    context.  Its Eq12 reference is recomputed at 20 extra decimal digits.
    """
    def __init__(self, p: HXParams, digits=100):
        self.c = c = mp.mp.clone()
        c.dps = digits
        q = {name: c.mpf(value) for name, value in asdict(p).items()}
        self.p = p
        self.digits = digits
        self.b = c.mpf(high_precision_boundary(p, digits=digits+20))
        self.r, self.delta = q['r'], q['delta']
        self.D = q['sigma']**2/2
        self.a = (self.r-self.delta-self.D)/(2*self.D)
        z = c.sqrt(self.a**2+self.r/self.D)
        self.eta, self.gamma = z-self.a, z+self.a
        self.lam = self.r+q['xi']*q['k']
        self.zh = c.sqrt(self.a**2+self.lam/self.D)
        self.maturity = q['maturity']
        self.t = q['sigma']*c.sqrt(self.maturity)
        self.coupon = q['coupon_total']/(self.maturity*self.lam)
        self.face = q['face_total']/self.maturity
        self.recovery = q['alpha']*self.b/self.maturity
        self.after_tax_coupon = (1-q['tax'])*q['coupon_total']
        self.ell = c.exp(-self.lam*self.maturity)

    def Phi(self, z):
        return self.c.erfc(-z/self.c.sqrt(2))/2

    def F(self, x):
        return (self.Phi(-x/self.t-self.a*self.t)
                +self.c.exp(-2*self.a*x)*self.Phi(-x/self.t+self.a*self.t))

    def G(self, x):
        return (self.c.exp((-self.a+self.zh)*x)*self.Phi(-x/self.t-self.zh*self.t)
                +self.c.exp((-self.a-self.zh)*x)*self.Phi(-x/self.t+self.zh*self.t))

    def cashflow(self, x):
        debt = (self.coupon+self.ell*(self.face-self.coupon)*(1-self.F(x))
                +(self.recovery-self.coupon)*self.G(x))
        return self.delta*self.b*self.c.exp(x)-self.after_tax_coupon+debt-self.face

    def equity(self, log_margin):
        """Independent Eq11 initial-value Green integral, finite MP quadrature.

        This is a numerical cross-check without a quadrature error proof.
        The interval theorem supplies the whole-state sign guarantee.
        """
        c = self.c
        x = c.mpf(log_margin)
        def integrand(y):
            u = x-y
            kernel = (c.exp(self.eta*u)-c.exp(-self.gamma*u))/(self.D*(self.eta+self.gamma))
            return -kernel*self.cashflow(y)
        splits = [c.mpf(0)]
        splits.extend(c.mpf(v) for v in (1e-5, 1e-4, .001, .01, .1, 1., 4.)
                      if c.mpf(v) < x)
        splits.append(x)
        return c.quad(integrand, splits)


def independent_cell_checks(certificate, p, *, digits=100):
    """Check every recorded cell at both endpoints and midpoint using MP."""
    reference = IndependentMPReference(p, digits=digits)
    c = reference.c
    rows = []
    for cell in certificate['cells']:
        for x in (cell['lower'], (cell['lower']+cell['upper'])/2, cell['upper']):
            xx = c.mpf(x)
            value = (c.diff(reference.cashflow, xx) if cell['kind'] == 'POSITIVE_SLOPE'
                     else reference.cashflow(xx))
            lower = c.mpf(cell['enclosure']['lower'])
            upper = c.mpf(cell['enclosure']['upper'])
            contained = bool(lower <= value <= upper)
            rows.append({'x': x, 'cell': [cell['lower'], cell['upper']],
                         'kind': cell['kind'], 'mp_value': str(value),
                         'contained': contained})
            if not contained:
                raise AssertionError(f'Independent MP value outside interval: {rows[-1]}')
    tail = certificate['tail']
    tail_rows = []
    for offset in (0., .125, 1., 4., 16., 64.):
        x = c.mpf(tail['start'])+c.mpf(offset)
        fp, gp = abs(c.diff(reference.F, x)), abs(c.diff(reference.G, x))
        qp = c.diff(reference.cashflow, x)
        passed = bool(fp <= c.mpf(tail['absolute_F_derivative_uniform_bound'])
                      and gp <= c.mpf(tail['absolute_G_derivative_uniform_bound'])
                      and qp >= c.mpf(tail['qprime_uniform_lower_bound']))
        tail_rows.append({'x': float(x), 'abs_Fprime': str(fp), 'abs_Gprime': str(gp),
                          'qprime': str(qp), 'within_tail_bounds': passed})
        if not passed:
            raise AssertionError(f'Independent MP tail-bound failure: {tail_rows[-1]}')
    return {'parameters': asdict(p), 'decimal_digits': digits,
            'cell_checks': rows, 'tail_checks': tail_rows,
            'is_global_proof': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Evidence is create-only; choose a fresh output path')
    here = Path(__file__).resolve().parent
    prior = here/'gates/2026-11-05-round2-p0-hx-numerical.json'
    panel = json.loads(prior.read_text())['domain_rows']
    started = time.perf_counter()
    rows = []
    for old in panel:
        dtype = None if old['format'] == 'exact_binary64' else old['format']
        p = HXParams(**old['parameters'])
        start = time.perf_counter()
        result = global_obstacle_enclosure(p, dtype=dtype, max_cells=512)
        before = old['enclosure']['status']
        after = result['status']
        original_pass = before == 'SUFFICIENT_FIXED_DEBT_OBSTACLE'
        new_pass = after == 'CERTIFIED_SINGLE_CROSSING_FIXED_DEBT_OBSTACLE'
        newly_certified = new_pass and not original_pass
        row = {'case': old['case'], 'format': old['format'], 'parameters': asdict(p),
               'before': before, 'after': after, 'certificate': result,
               'combined_sufficient_domain': original_pass or new_pass,
               'newly_certified': newly_certified,
               'seconds': time.perf_counter()-start}
        if newly_certified:
            # All-box bounds remain proofs by interval inclusion.  Checking
            # original and two corners just exercises the implementation.
            check_params = [('original', p)]
            if dtype:
                box = result['base_domain']['input_box']
                for side in ('lower', 'upper'):
                    check_params.append((f'all_{side}_corner',
                        HXParams(**{name: item[side] for name, item in box.items()})))
            row['independent_numerical_checks'] = [
                {'input': name, **independent_cell_checks(result, point)}
                for name, point in check_params]
            if dtype is None:
                ref = IndependentMPReference(p)
                row['independent_green_integral'] = [
                    {'log_margin': x, 'mp100_equity': str(ref.equity(x))}
                    for x in (1e-8, 1e-5, .001, .1, 1., 8.)]
                if not all(ref.c.mpf(v['mp100_equity']) > 0
                           for v in row['independent_green_integral']):
                    raise AssertionError('A certified value is nonpositive in MP integration')
        print(old['case'], old['format'], before, '->', after,
              f"cells={len(result['cells'])}", flush=True)
        rows.append(row)
    source_paths = [Path(__file__), here/'hx_global_obstacle.py', here/'hx_original.py',
                    here/'hx_interval_domain.py', here/'hx_precision_audit.py', prior]
    source_sha256 = {str(p.relative_to(here.parent.parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in source_paths}
    report = {
        'schema': 'hcsn-p0-global-obstacle-v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'base_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=here, text=True).strip(),
        'prior_panel_sha256': hashlib.sha256(prior.read_bytes()).hexdigest(),
        'runtime': {'python': platform.python_version(), 'mpmath': mp.__version__,
                    'platform': platform.platform()},
        'rows': rows,
        'summary': {
            'attempts': len(rows),
            'before_counts': dict(Counter(row['before'] for row in rows)),
            'new_method_counts': dict(Counter(row['after'] for row in rows)),
            'newly_certified': sum(row['newly_certified'] for row in rows),
            'combined_sufficient_domain_count': sum(row['combined_sufficient_domain'] for row in rows),
            'independent_cell_samples': sum(len(check['cell_checks']) for row in rows
                for check in row.get('independent_numerical_checks', [])),
            'independent_tail_samples': sum(len(check['tail_checks']) for row in rows
                for check in row.get('independent_numerical_checks', [])),
            'independent_green_integrals': sum(len(row.get('independent_green_integral', []))
                for row in rows),
        },
        'elapsed_seconds': time.perf_counter()-started,
        'source_sha256': source_sha256,
        'primary_references': [
            'https://www.princeton.edu/~wxiong/papers/rollover.pdf',
            'https://dlmf.nist.gov/7.8'],
        'scope': 'global continuation-state obstacle for fixed original HX debt prices and stated recovery extension',
        'limitations': [
            'Sufficient domain only; unresolved cases are not refuted',
            'Same mpmath interval primitive trust boundary as round 2',
            'MP samples and quadrature do not provide the global proof',
            'No repriced-policy equilibrium uniqueness or regenerative-QVI proof',
            'No native FP32/BF16 operator, GPU/energy, gradient, or neural-benefit claim',
            'Scientific P0-P5 phases remain open; no admission policy changed'],
        'production_activation': False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write('\n')
    print(json.dumps(report['summary'], sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
