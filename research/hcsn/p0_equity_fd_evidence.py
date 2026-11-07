"""Reproducible bounded numerical evidence: original HX equity FD vs Eq12/A7/Green.

This is a diagnostic. In particular, Richardson extrapolation is empirical
mesh-order evidence, NOT a guaranteed error bound or global theorem.
Output is a new, exclusive-create JSON file, never silent overwrite.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import platform
from pathlib import Path

import numpy as np
import scipy

try:
    from .hx_original import HXParams,closed_boundary,equity_green
    from .hx_a7 import equity_a7
    from .hx_equity_fd_independent import solve_equity_fd,solve_boundary_fd
    from .test_hx_equity_fd_independent import CASES
except ImportError:
    from hx_original import HXParams,closed_boundary,equity_green
    from hx_a7 import equity_a7
    from hx_equity_fd_independent import solve_equity_fd,solve_boundary_fd
    from test_hx_equity_fd_independent import CASES


def run_panels() -> dict:
    panels=[]
    for name,parameters in CASES:
        p=HXParams(**parameters)
        exact=closed_boundary(p)
        roots=[]
        for n in (800,1600,3200):
            b,sol=solve_boundary_fd(p,cells=n)
            roots.append({'cells':n,'boundary':float(b),
                          'signed_boundary_error':float(b-exact),
                          'max_equation_residual':sol.max_equation_residual,
                          'smooth_pasting_fd':sol.boundary_log_derivative})
        rich=(4*roots[2]['boundary']-roots[1]['boundary'])/3
        solution=solve_equity_fd(p,exact,cells=3200)
        checks=[]
        for x in (.025,.1,.4,1.,2.,3.):
            i=int(x/solution.h+1e-9)
            # grids x=8k/3200=0.0025k; samples all exact nodes
            numerical=solution.equity[i]
            analytic_green=equity_green(exact*math.exp(x),exact,p)
            a7=None
            if p.xi*p.k>0:
                a7=equity_a7(exact*math.exp(x),p,exact)
            checks.append({'log_margin':x,'fd':float(numerical),
                           'green':float(analytic_green),
                           'a7':None if a7 is None else float(a7),
                           'fd_green_absolute_error':float(abs(numerical-analytic_green)),
                           'fd_green_scaled_error':float(abs(numerical-analytic_green)/max(1,abs(analytic_green)))})
        panels.append({'name':name,'parameters':parameters,'eq12_boundary':exact,
                       'fd_roots':roots,'richardson_boundary':rich,
                       'richardson_relative_error':abs(rich/exact-1),
                       'checkpoints':checks})
    max_rel=max(c['fd_green_scaled_error'] for p in panels for c in p['checkpoints'])
    max_boundary=max(p['richardson_relative_error'] for p in panels)
    valid=bool(max_rel<.002 and max_boundary<5e-6)
    files=['hx_equity_fd_independent.py','test_hx_equity_fd_independent.py','p0_equity_fd_evidence.py']
    digests={f:hashlib.sha256((Path(__file__).parent/f).read_bytes()).hexdigest() for f in files}
    return {'study':'HCSN P0 original HX Eq11 independent FD equity reference',
            'claim_scope':'six bounded finite-domain cases; CPU float64; NOT global proof',
            'reference':'He & Xiong, J. Finance 67(2), eq 8, 11, 12, Appendix A7',
            'independence':'FD equity solver/root do not invoke Eq12/A7/Green; source is original bond Eq8',
            'fixed_panel_predeclared':False,
            'numerical_extrapolation_is_rigorous_error_bound':False,
            'source_sha256':digests,
            'environment':{'python':platform.python_version(), 'numpy':np.__version__, 'scipy':scipy.__version__},
            'max_green_scaled_error':max_rel,
            'max_richardson_relative_boundary_error':max_boundary,
            'bounded_sanity_check_pass':valid,
            'p0_p6_scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,
            'panels':panels}


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    report=run_panels()
    dest=Path(args.output)
    with dest.open('x',encoding='utf-8') as output:
        json.dump(report,output,indent=2,sort_keys=True)
        output.write('\n')
    print(json.dumps({'output':str(dest),'panels':len(report['panels']),
                      'max_green_scaled_error':report['max_green_scaled_error'],
                      'max_richardson_relative_boundary_error':report['max_richardson_relative_boundary_error'],
                      'bounded_sanity_check_pass':report['bounded_sanity_check_pass'],
                      'scientific_gates':'P0-P6 OPEN'}))
    return 0 if report['bounded_sanity_check_pass'] else 3


if __name__=='__main__':
    raise SystemExit(main())
