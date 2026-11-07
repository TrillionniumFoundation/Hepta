"""P2 piecewise-exact autonomous free-boundary event-time reference.

A minimal deterministic limit of a continuous free-boundary neuron:
  m=log(V/VB),  dm/dt=-rate_t,  spike when m=0,  m^+=reset_margin.
The depletion rate is frozen on each irregular input interval. Within an
interval crossings are found exactly and any number of *endogenous* events
is handled (no externally supplied reset markers). Event times and final
margin are differentiable in PyTorch on open regions with fixed event
count/order. The event count and grazing/tangential hits are NONSMOOTH.

This checks only timing and backward sensitivity of a deliberately simple
continuous-state limit; it does not verify neural recall, stochastic
first-passage, or full recursive He-Xiong coupled valuation.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import torch


@dataclass
class EventTrajectory:
    events: torch.Tensor
    margin_end: torch.Tensor
    elapsed: torch.Tensor
    events_per_interval: tuple[int,...]
    derivative_scope: str = 'fixed-event-count-and-order-only'


def simulate_autonomous(margin0: torch.Tensor, reset_margin: torch.Tensor,
                        rates: torch.Tensor, durations: torch.Tensor, *,
                        max_events: int = 128) -> EventTrajectory:
    """Exactly advance positive margin under piecewise-constant depletion.

    Durations and rates must have identical shape [n]; all scalars and
    arrays use double precision to avoid artificial event-time collisions.
    Gradients propagate through continuous event times, not branch counts.
    """
    if not (isinstance(margin0,torch.Tensor) and isinstance(reset_margin,torch.Tensor)
            and isinstance(rates,torch.Tensor) and isinstance(durations,torch.Tensor)):
        raise TypeError('Autograd tensors are required for all parameters')
    if margin0.ndim or reset_margin.ndim or rates.ndim!=1 or durations.ndim!=1 \
       or rates.shape!=durations.shape or len(rates)<1 or len(rates)>4096 \
       or not 1<=max_events<=10000:
        raise ValueError('Invalid event geometry')
    if (not all(t.dtype==torch.float64 for t in (margin0,reset_margin,rates,durations))
        or not all(t.device==margin0.device for t in (reset_margin,rates,durations))):
        raise ValueError('Use a single device and torch.float64 tensors')
    if (not all(bool(torch.isfinite(t).all()) for t in (margin0,reset_margin,rates,durations))
        or margin0.detach().item()<=0 or reset_margin.detach().item()<=1.e-8
        or bool((rates.detach()<=0).any()) or bool((durations.detach()<=0).any())):
        raise ValueError('Positive finite flow, initial margin, reset and time required')
    clock=margin0*0.0
    margin=margin0
    events=[]
    per=[]
    for rate,interval in zip(rates.unbind(),durations.unbind()):
        remaining=interval
        k=0
        # Strict crossing: equality at endpoint counts as an event. Changes in
        # event count are discontinuities, explicitly NOT differentiated.
        while bool((margin.detach()<=rate.detach()*remaining.detach())):
            if len(events)>=max_events:
                raise ArithmeticError('Event budget exhausted; possible Zeno behavior')
            time_to_event=margin/rate
            clock=clock+time_to_event
            remaining=remaining-time_to_event
            events.append(clock)
            margin=reset_margin
            k+=1
        margin=margin-rate*remaining
        clock=clock+remaining
        if margin.detach().item()< -1.e-10:
            raise ArithmeticError('Crossing solver generated negative margin')
        per.append(k)
    times=torch.stack(events) if events else clock.reshape(1)[:0]
    return EventTrajectory(times,margin,clock,tuple(per))


def event_time_calibration(*, target_rate: float=.53,
                           initial_rate: float=.45, steps: int=100):
    """Train one physical depletion rate from *autonomous* timing targets.

    A narrow, non-production sanity test. Kept away from event-count
    transition surfaces; gradient cannot learn a missing/new discrete event.
    """
    if not (.5<=target_rate<=.55 and .43<=initial_rate<=.47 and 20<=steps<=500):
        raise ValueError('Outside fixed-count timing-identification experiment')
    margin=torch.tensor(.8,dtype=torch.float64)
    reset=torch.tensor(1.3,dtype=torch.float64)
    duration=torch.tensor([1.1,2.3,1.7,2.9],dtype=torch.float64)
    r_target=torch.full((len(duration),),target_rate,dtype=torch.float64)
    target=simulate_autonomous(margin,reset,r_target,duration).events.detach()
    min_rate,max_rate=.43,.56
    theta=torch.tensor(math.log((initial_rate-min_rate)/(max_rate-initial_rate)),
                       dtype=torch.float64,requires_grad=True)
    opt=torch.optim.Adam([theta],lr=.12)
    initial_loss=None
    for i in range(steps):
        opt.zero_grad(set_to_none=True)
        rate=min_rate+(max_rate-min_rate)*torch.sigmoid(theta)
        t=simulate_autonomous(margin,reset,rate.expand_as(duration),duration).events
        if len(t)!=len(target):
            raise ArithmeticError('Event-count transition during fixed-count calibration')
        loss=torch.mean((t-target)**2)
        if i==0:
            initial_loss=float(loss.detach())
        loss.backward()
        if not bool(torch.isfinite(theta.grad)):
            raise ArithmeticError('Invalid event-time gradient')
        opt.step()
    with torch.no_grad():
        rate=float(min_rate+(max_rate-min_rate)*torch.sigmoid(theta))
        events=simulate_autonomous(margin,reset,torch.full_like(duration,rate),duration).events
        final_mse=float(torch.mean((events-target)**2))
    return {'schema':'hcsn.p2-autonomous-exact-event-time.v1',
            'target_rate':target_rate,'initial_rate':initial_rate,
            'estimated_rate':rate,'steps':steps,'event_count':len(target),
            'initial_event_time_mse':initial_loss,'final_event_time_mse':final_mse,
            'supports_grad_through_event_count':False,
            'scope':'deterministic piecewise-constant log-margin depletion, fixed event count'}
