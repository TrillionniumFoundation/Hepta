"""HCSN P2 research-only: phantom gradient across a hard reset.

This is a minimal, isolated algebraic control for the forward/STE pattern in
RawResetValidityMemory.forward, NOT a replay of the trained #512 checkpoints.
It demonstrates the derivative mismatch, not the general failure of surrogate
training or of He–Xiong/QVI. No model weights or target semantics enter a gate.
"""
from __future__ import annotations
import argparse
import json
import math
import sys

import torch


def sigmoid(x: float) -> float:
    return 1.0/(1.0+math.exp(-x))


def hard_reset_forward(logit: float, old: float, fresh: float = 0.0) -> float:
    if not all(math.isfinite(z) for z in (logit, old, fresh)):
        raise ValueError('nonfinite input')
    return fresh + (0.0 if sigmoid(logit) >= 0.5 else old)


def hard_event(probability: torch.Tensor) -> torch.Tensor:
    return (probability >= .5).to(probability.dtype) + probability - probability.detach()


def torch_straight_through(logit: float, old: float, target: float, fresh: float = 0.0) -> dict:
    if not all(math.isfinite(z) for z in (logit, old, fresh, target)):
        raise ValueError('nonfinite input')
    w=torch.tensor(logit,dtype=torch.float64,requires_grad=True)
    probability=torch.sigmoid(w)
    event=hard_event(probability)
    output=fresh+(1.0-event)*old
    loss=(output-target).square()
    gradient,=torch.autograd.grad(loss,w)
    hard_output=hard_reset_forward(logit,old,fresh)
    analytic=2.0*(hard_output-target)*(-old)*sigmoid(logit)*(1.0-sigmoid(logit))
    assert math.isfinite(float(loss.detach())) and math.isfinite(float(gradient.detach()))
    assert abs(float(output.detach())-hard_output)<1e-13
    return {'hard_output':hard_output,'forward_loss':float(loss.detach()),
            'ste_gradient':float(gradient),'independent_analytic_ste_gradient':analytic,
            'reset':int(float(event.detach())>=.5),'soft_probability':float(probability.detach())}


def evaluate_case(logit:float,old:float,target:float,learning_rate:float,delta=1e-4)->dict:
    if not (logit>delta>0 and learning_rate>=0):
        raise ValueError('witness requires a positive logit separated from reset threshold')
    original=torch_straight_through(logit,old,target)
    left=hard_reset_forward(logit-delta,old)
    right=hard_reset_forward(logit+delta,old)
    finite_difference=( (right-target)**2-(left-target)**2 )/(2.0*delta)
    stepped_logit=logit-learning_rate*original['ste_gradient']
    stepped_output=hard_reset_forward(stepped_logit,old)
    stepped_loss=(stepped_output-target)**2
    return {**{'logit':logit,'old_memory':old,'target':target,'learning_rate':learning_rate,
               'finite_difference_delta':delta,'true_central_difference':finite_difference,
               'stepped_logit':stepped_logit,'stepped_reset':int(sigmoid(stepped_logit)>=.5),
               'stepped_output':stepped_output,'stepped_loss':stepped_loss,
               'loss_increase':stepped_loss-original['forward_loss']},**original}


def evidence():
    cases=[evaluate_case(0.2,m,1.0,.1) for m in (-8.0,-1.0,0.0,1.0,8.0)]
    adversarial=cases[-1]
    if not (adversarial['ste_gradient']>3.0 and adversarial['true_central_difference']==0
            and adversarial['forward_loss']==1.0 and adversarial['stepped_loss']==49.0
            and adversarial['stepped_logit']<0):
        raise AssertionError('specified hard reset gradient witness absent')
    for row in cases:
        if not math.isclose(row['ste_gradient'],row['independent_analytic_ste_gradient'],rel_tol=2e-15,abs_tol=2e-15):
            raise AssertionError('independent analytic surrogate reference mismatch')
        if row['true_central_difference']!=0.0:
            raise AssertionError('true hard forward locally changes')
    return {'schema':'hcsn.p2.ste-reset-phantom-gradient-negative.v1',
            'scope':'isolated signed hard reset + sigmoid STE + squared task loss; no trained checkpoints',
            'mechanism':'hard forward erases old information but STE propagates a counterfactual old-state-dependent gradient',
            'cases':cases,
            'identity':'d_STE L/dlogit = -2*(y-target)*old*sigmoid(logit)*(1-sigmoid(logit)); true derivative=0 away from 0',
            'main_claim':'a single gradient step can increase the real hard-forward loss despite a nonzero surrogate descent direction',
            'full_hcsn_validated':False,'external_independent_attestation':False,
            'p0_to_p6':{f'P{i}':'OPEN' for i in range(7)},'production_activation':False,
            'strict_gate_exit_code':2,'status':'NEGATIVE_ISOLATED_SURROGATE_CONTROL'}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--strict',action='store_true')
    args=parser.parse_args()
    print(json.dumps(evidence(),sort_keys=True,indent=2,allow_nan=False))
    return 2 if args.strict else 0

if __name__=='__main__':
    sys.exit(main())
