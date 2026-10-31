"""Bounded fixed-count event-time autograd stress over random irregular schedules.

Explicitly excludes event-time collisions with interval boundaries (where
count/order or which interval owns an event is nondifferentiable).
"""
import unittest
import numpy as np
import torch
try:
    from .autonomous_event_time import simulate_autonomous
except ImportError:
    from autonomous_event_time import simulate_autonomous


def td(x,grad=False):
    return torch.tensor(x,dtype=torch.float64,requires_grad=grad)

class AutonomousEventStressTests(unittest.TestCase):
    def test_irregular_trajectories_signed_gradients(self):
        g=np.random.default_rng(902114)
        valid=0
        for i in range(100):
            m=float(g.uniform(.45,1.2)); reset=float(g.uniform(.55,1.2))
            rates=g.uniform(.3,.9,size=4)
            dt=g.uniform(.8,1.8,size=4)
            m0=td(m,True); mr=td(reset,True)
            rt=td(rates,True); intervals=td(dt,True)
            flow=simulate_autonomous(m0,mr,rt,intervals)
            if len(flow.events)==0:continue
            endpoints=np.cumsum(dt)
            if np.min(abs(flow.events.detach().numpy()[:,None]-endpoints[None,:]))<.04:
                continue
            loss=sum((k+1)*v for k,v in enumerate(flow.events))+.125*flow.margin_end
            grad=torch.autograd.grad(loss,(m0,mr,rt,intervals))
            def f(mb,rb,rat,durations):
                p=simulate_autonomous(td(mb),td(rb),td(rat),td(durations))
                self.assertEqual(len(p.events),len(flow.events))
                return sum((k+1)*float(v) for k,v in enumerate(p.events))+.125*float(p.margin_end)
            baseline=[m,reset,rates.tolist(),dt.tolist()]
            for group,index in ((0,0),(1,0),(2,0),(2,1),(2,2),(2,3),(3,0),(3,1),(3,2),(3,3)):
                plus=[baseline[0],baseline[1],list(baseline[2]),list(baseline[3])]
                minus=[baseline[0],baseline[1],list(baseline[2]),list(baseline[3])]
                eps=1e-6
                if group<2:
                    plus[group]+=eps;minus[group]-=eps
                    derivative=float(grad[group])
                else:
                    plus[group][index]+=eps;minus[group][index]-=eps
                    derivative=float(grad[group][index])
                numeric=(f(*plus)-f(*minus))/(2*eps)
                self.assertLess(abs(derivative-numeric),3e-6,(i,group,index))
            valid+=1
        self.assertGreaterEqual(valid,70)

if __name__=='__main__':unittest.main()
