"""P0 bounded adversarial HX panel + FP32/BF16 state-representation diagnostics.

This does not establish all-domain certification. It deliberately reports
ill-conditioned near-boundary state reconstruction and a mask for failed
parameter points instead of silently skipping them or labeling green.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import numpy as np
import torch
try:
    from .hx_original import (HXParams,closed_boundary,independent_boundary,
        equity_green,equity_smooth_derivative_at_boundary)
    from .hx_a7 import equity_a7
    from .math_kernel import PhysicalParameters,beta_and_boundary
except ImportError:
    from hx_original import (HXParams,closed_boundary,independent_boundary,
        equity_green,equity_smooth_derivative_at_boundary)
    from hx_a7 import equity_a7
    from math_kernel import PhysicalParameters,beta_and_boundary


def numerical_precision_panel():
    p=PhysicalParameters();beta,b=beta_and_boundary(p)
    rows=[]
    for x in (1e-3,1e-4,1e-5,1e-6,1e-7,1e-8):
        ref=b*x*x*((1+beta)/2+(1-beta*beta)*x/6
                 +(1+beta**3)*x*x/24+(1-beta**4)*x**3/120)
        out={'log_margin':x,'reference_call':ref}
        for name,dtype in [('fp32',torch.float32),('bf16',torch.bfloat16)]:
            # State/ratio form loses small margins: reconstructed log(V/b).
            v=torch.tensor(b,dtype=dtype)*torch.exp(torch.tensor(x,dtype=dtype))
            b_t=torch.tensor(b,dtype=dtype)
            reconstructed=float(torch.log(v/b_t))
            # Direct margin form preserves the separately tracked state but
            # squaring in BF16 is only a low-accuracy local approximation.
            ml=torch.tensor(x,dtype=dtype)
            local=float(torch.tensor(b,dtype=dtype)*ml*ml*
                        (torch.tensor((1+beta)/2,dtype=dtype)
                         +ml*torch.tensor((1-beta**2)/6,dtype=dtype)))
            out[name]={'log_margin_reconstructed':reconstructed,
                       'local_call_from_margin':local,
                       'relative_call_error':abs(local-ref)/max(1e-300,abs(ref)),
                       'relative_margin_reconstruction_error':abs(reconstructed-x)/x}
        rows.append(out)
    return rows


def hx_adversarial_panel(n=84,seed=20261031):
    rng=np.random.default_rng(seed)
    rows=[]
    for i in range(n):
        # Bounded panel with extreme kappa=xi*k and wide vol/maturity.
        x=0. if i%9==0 else 10**rng.uniform(-6,-.8)
        xi=float(rng.uniform(.05,4.))
        p=HXParams(r=float(rng.uniform(.04,.16)),
            delta=float(rng.uniform(.008,.065)),
            sigma=float(rng.uniform(.08,.53)),
            alpha=float(rng.uniform(.2,.92)),tax=float(rng.uniform(.05,.4)),
            xi=xi,k=float(x/xi),
            maturity=float(rng.uniform(.2,7.)),
            coupon_total=float(rng.uniform(3.,8.)),
            face_total=float(rng.uniform(50.,100.)))
        try:
            b=closed_boundary(p)
            bi=independent_boundary(p)
            err=abs(b-bi)/max(1.,abs(b))
            ds=abs(equity_smooth_derivative_at_boundary(b,p))
            # A7 direct singular for xi*k=0; such points are not dropped.
            a7_covered=(p.xi*p.k)>0
            e_err=None
            if a7_covered:
                v=b*math.exp(.32)
                a=equity_a7(v,p,b)
                g=equity_green(v,b,p)
                e_err=abs(a-g)/max(1.,abs(g))
            rows.append({'case':i,'xi_k':p.xi*p.k,'status':'OK',
                  'relative_boundary_error':err,
                  'smooth_log_derivative_abs':ds,
                  'a7_green_relative_error':e_err,
                  'a7_direct_covered':a7_covered})
        except Exception as exc:
            rows.append({'case':i,'xi_k':p.xi*p.k,'status':'REFUSED',
                'reason':f'{type(exc).__name__}: {str(exc)[:110]}'})
    ok=[r for r in rows if r['status']=='OK']
    return {'seed':seed,'cases':n,'ok':len(ok),'refused':n-len(ok),
        'direct_a7_singular_cases':sum(z['status']=='OK' and not z['a7_direct_covered'] for z in rows),
        'max_relative_boundary_error':max((x['relative_boundary_error'] for x in ok),default=None),
        'max_abs_smooth_log_derivative':max((x['smooth_log_derivative_abs'] for x in ok),default=None),
        'max_relative_A7_Green_error':max((x['a7_green_relative_error'] for x in ok if x['a7_green_relative_error'] is not None),default=None),
        'rows':rows}


def run():
    return {'schema':'hcsn.p0-bounded-stress-precision.v1',
        'precision':numerical_precision_panel(),
        'hx_adversarial':hx_adversarial_panel(),
        'mathematical_gate_closed':False,
        'notes':'A7 xi*k=0 removable singularity is explicitly unclosed; finite sampled domains and bf16 near-margin failures remain.'}

if __name__=='__main__':
    c=argparse.ArgumentParser();c.add_argument('--output',type=Path,required=True)
    a=c.parse_args()
    if a.output.exists():c.error('Refusing overwrite')
    output=run();output['sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text(json.dumps(output,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in output['hx_adversarial'].items() if k!='rows'},indent=2))
    print('precision',output['precision'][-3:])
