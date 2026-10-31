"""Frozen exploratory panel: deterministic CPU evidence (not preregistered)."""
from __future__ import annotations
import dataclasses
import hashlib
import json
import platform
import time
from pathlib import Path

import numpy as np
import scipy
import torch

from research.hcsn.p2_checkpoint_boundary_oracle import (
    TwoStageBrownian, probability_quad, probability_torch, probability_bridge_mc,
    first_hit_prob,
)

CASES = (
    ("content_feedback_positive", TwoStageBrownian()),
    ("feedback_negative", TwoStageBrownian(gain=-.45,b2_level=-.5)),
    ("high_jump_negative_drift", TwoStageBrownian(gain=.45,b2_level=.6,drift=-.18)),
    ("high_jump_positive_drift", TwoStageBrownian(gain=0,b2_level=.9,drift=.3)),
    ("stationary_barrier", TwoStageBrownian(b1=0,b2_level=0,gain=0)),
)

def run():
    folder=Path(__file__).resolve().parents[2]
    rows=[]
    for i,(name,p) in enumerate(CASES):
        q,err=probability_quad(p)
        gl,tail=probability_torch(p,n=256)
        mc,se,k=probability_bridge_mc(p,n=160000,seed=20261031+i)
        row={"case":name,"parameters":dataclasses.asdict(p),"quad_prob":q,
             "quad_error_estimate":err,"gauss_prob":float(gl),"gauss_abs_gap":abs(float(gl)-q),
             "first_gaussian_tail_upper_bound":float(tail),"bridge_probability":mc,
             "bridge_standard_error":se,"bridge_hits":k,"mc_n":160000,
             "bridge_abs_z":abs(q-mc)/se if se else None}
        if name=="stationary_barrier":
            row["closed_form_fixed_boundary_prob"]=first_hit_prob(p.x0-p.b1,p.drift,p.diffusion,p.t1+p.t2)
        rows.append(row)
    print('case | quad | Gauss | MC | MC z')
    for row in rows:
        print(f"{row['case']}: {row['quad_prob']:.8f} {row['gauss_prob']:.8f} {row['bridge_probability']:.8f} z={row['bridge_abs_z']:.3f}")
    p=CASES[0][1]
    for _ in range(10):
        probability_quad(p);probability_torch(p)
    bench={}
    for k,fn in [('scipy_adaptive_quad',lambda:probability_quad(p)),
                 ('torch_256_node_fp64',lambda:probability_torch(p))]:
        durations=[]
        for _ in range(110):
            start=time.perf_counter_ns(); fn(); durations.append((time.perf_counter_ns()-start)/1e6)
        bench[k]={"n":len(durations),"median_ms":float(np.median(durations)),
                  "p95_ms":float(np.percentile(durations,95)),
                  "p99_ms":float(np.percentile(durations,99))}
    sources={}
    for name in ('research/hcsn/p2_checkpoint_boundary_oracle.py','research/hcsn/test_p2_checkpoint_boundary_oracle.py','research/hcsn/p2_checkpoint_boundary_evidence.py'):
        sources[name]=hashlib.sha256((folder/name).read_bytes()).hexdigest()
    evidence={"scientific_status":"OPEN","production_activation":False,"study_class":"exploratory",
              "preregistration":False,"implementation":"research-only standalone CPU FP64, no upstream production dependencies",
              "assumptions": "Brownian log state; deterministic first barrier; causal affine checkpoint barrier; second barrier frozen until horizon; gain range [-0.75,0.75]; 2 periods; no multi-reset",
              "environment":{"python":platform.python_version(),"numpy":np.__version__,"scipy":scipy.__version__,"torch":torch.__version__,"cuda_available":torch.cuda.is_available(),"platform":platform.platform()},
              "cases":rows,"scalar_cpu_latency":bench,"source_sha256":sources,
              "limitations":["No original coupled He-Xiong equity/QVI proof", "No interval-certified quadrature error", "No parameter-shifted neural model or trained memory gain", "No independent external trust-root or observer signature", "No target GPU or energy data", "No multimodal encoders", "No matched FLOP/slope causal benefit"],
              "strict_gate":"NO_GO"}
    (folder/'research/hcsn/gates/2026-10-31-iteration16-checkpoint-evidence.json').write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n')
    print(json.dumps({"worst_abs_gauss_gap":max(row['gauss_abs_gap'] for row in rows),
                      "worst_abs_mc_z":max(row['bridge_abs_z'] for row in rows),"latency":bench},indent=2))
    return evidence

if __name__=='__main__':run()
