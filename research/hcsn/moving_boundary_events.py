"""Autograd-aware P2 moving free-boundary event reference (bounded deterministic case).

Within each irregular interval [t_i,t_{i+1}], log state and log boundary
follow independent affine trajectories.  The signed log margin is
m = log V - log V_B; its velocity is state_velocity - boundary_velocity.
On first contact m=0, log V jumps to log V_B + reset_margin; the boundary
itself does NOT reset.  This is an event-level continuous-to-impulse model,
not the He--Xiong original equity solution, a learned recurrent memory cell,
or a surrogate-gradient proof through changes in the number of events.

The branch geometry is detached for branching; event times and terminal
values remain differentiable on fixed-event-count regions. An exact zero
margin contact counts as an event, making event-count transition surfaces
explicit and non-differentiable.
"""
from __future__ import annotations
from dataclasses import dataclass
import torch


@dataclass
class MovingBoundaryTrajectory:
    event_times: torch.Tensor
    event_log_boundaries: torch.Tensor
    log_state_end: torch.Tensor
    log_boundary_end: torch.Tensor
    log_margin_end: torch.Tensor
    events_per_interval: tuple[int, ...]
    derivative_scope: str = 'fixed-event-count/order: no gradient through count or grazing hit'


def simulate_moving_boundary(log_state0:torch.Tensor, log_boundary0:torch.Tensor,
                             reset_log_margin:torch.Tensor,
                             state_velocity:torch.Tensor,
                             boundary_velocity:torch.Tensor,
                             durations:torch.Tensor, *,
                             max_events:int=128) -> MovingBoundaryTrajectory:
    inputs=(log_state0,log_boundary0,reset_log_margin,state_velocity,boundary_velocity,durations)
    if any(not isinstance(a,torch.Tensor) for a in inputs):
        raise TypeError('All inputs must be torch tensors')
    if (any(t.ndim!=0 for t in inputs[:3])
            or any(t.ndim!=1 for t in inputs[3:])
            or state_velocity.shape!=boundary_velocity.shape
            or state_velocity.shape!=durations.shape
            or not 1<=len(durations)<=4096 or not 1<=max_events<=10000):
        raise ValueError('Invalid moving-boundary geometry')
    if (any(t.dtype!=torch.float64 or t.device!=log_state0.device for t in inputs)
            or any(not bool(torch.isfinite(t).all()) for t in inputs)
            or not bool((durations.detach()>0).all())
            or reset_log_margin.detach().item()<=1.e-8
            or log_state0.detach().item()<=log_boundary0.detach().item()):
        raise ValueError('Finite FP64 matching tensors, positive times/margins required')
    clock=log_state0*0.
    boundary=log_boundary0
    margin=log_state0-log_boundary0
    event_times=[]
    event_boundaries=[]
    per=[]
    for vs,vb,dt in zip(state_velocity.unbind(),boundary_velocity.unbind(),durations.unbind()):
        net=vb-vs
        remain=dt
        n=0
        # May be negative or zero: the boundary retreats relative to state.
        if net.detach().item()>0:
            while bool((margin.detach() <= net.detach()*remain.detach())):
                if len(event_times)>=max_events:
                    raise ArithmeticError('Event budget exceeded (Zeno / runaway input)')
                to_hit=margin/net
                clock=clock+to_hit
                boundary=boundary+vb*to_hit
                event_times.append(clock)
                event_boundaries.append(boundary)
                remain=remain-to_hit
                margin=reset_log_margin
                n+=1
        margin=margin-net*remain
        boundary=boundary+vb*remain
        clock=clock+remain
        if margin.detach().item() < -1e-9:
            raise ArithmeticError('Event solver failed to clear negative margin')
        per.append(n)
    times=torch.stack(event_times) if event_times else clock.reshape(1)[:0]
    bounds=torch.stack(event_boundaries) if event_boundaries else boundary.reshape(1)[:0]
    return MovingBoundaryTrajectory(times,bounds,boundary+margin,boundary,margin,tuple(per))
