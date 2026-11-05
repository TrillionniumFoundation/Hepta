"""Independent matrix-exponential witness for the old two-state P2 limits.

No network training is performed here. The observed output is one sampled
terminal binary state; this is not a no-go for arbitrary real-valued memories.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import numpy as np
from scipy.linalg import expm


def witness():
    epsilon=.01; duration=.02; amplitude=.01; hold=4096.
    lower=-math.log(epsilon)/duration
    upper=-math.log1p(-2*epsilon)/(amplitude**2*hold)
    records=[]
    for name,rate in [('minimum_fast_write',lower),('maximum_noise_retention',upper)]:
        positive=np.array([[-rate,rate],[0.,0.]])
        negative=np.array([[0.,0.],[rate,-rate]])
        write_transition=expm(positive*duration)
        noisy_generator=amplitude**2*((1+amplitude)*positive+(1-amplitude)*negative)/2
        noisy_transition=expm(noisy_generator*hold)
        p_last_zero=noisy_transition[0,1]
        p_last_one=noisy_transition[1,1]
        retained_accuracy=.5+.5*abs(p_last_one-p_last_zero)
        records.append({'parameter_choice':name,'rate_per_second':rate,
                        'independent_write_success':float(write_transition[0,1]),
                        'independent_retention_bayes_accuracy':float(retained_accuracy),
                        'generator_rows_sum_error':float(abs(noisy_generator.sum(1)).max()),
                        'transition_rows_sum_error':float(abs(noisy_transition.sum(1)-1).max())})
    assert abs(records[0]['independent_write_success']-.99)<1e-13
    assert records[0]['independent_retention_bayes_accuracy']<.5000000001
    assert records[1]['independent_write_success']<.001
    assert abs(records[1]['independent_retention_bayes_accuracy']-.99)<1e-13
    return {'schema':'hcsn.p2.old-flow-operating-domain-negative.v1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'requirements':{'write_error_max':epsilon,'write_duration_s':duration,
                            'retention_error_max':epsilon,'constant_noise_amplitude':amplitude,'hold_s':hold},
            'necessary_rate_interval':{'lower':lower,'upper':upper,'nonempty':False},
            'independent_scipy_expm_witnesses':records,
            'claim_scope':['two-state CTMC; one sampled terminal binary observation',
                           'old x^2 times convex mixture of two positive write generators',
                           'both write polarities must meet the same fast-write error target'],
            'conclusion':'reject simultaneous requirements for this model family',
            'not_claimed':'not a general impossibility theorem for learned token memories, extra states, deadzones or other noise models'}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);args=parser.parse_args()
    text=json.dumps(witness(),indent=2,sort_keys=True,allow_nan=False)+'\n'
    if args.output:args.output.write_text(text)
    else:print(text,end='')
