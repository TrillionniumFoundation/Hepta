"""P2 exact autonomous first-passage timing checks, not full BPTT gates."""
import math
import unittest
import torch
try:
    from .autonomous_event_time import simulate_autonomous,event_time_calibration
except ImportError:
    from autonomous_event_time import simulate_autonomous,event_time_calibration

D=torch.float64

def t(x,requires_grad=False):
    return torch.tensor(x,dtype=D,requires_grad=requires_grad)


class AutonomousEventTimeTests(unittest.TestCase):
    def test_multiple_autonomous_resets_exact_formula(self):
        init=t(.85);reset=t(.7);rate=.48
        path=simulate_autonomous(init,reset,t([rate]),t([8.]))
        expected=[(.85+k*.7)/rate for k in range(5)]
        self.assertEqual(len(path.events),5)
        for actual,reference in zip(path.events.tolist(),expected):
            self.assertAlmostEqual(actual,reference,places=11)
        self.assertAlmostEqual(float(path.margin_end),.85+5*.7-8*rate,places=12)

    def test_invariant_to_irregular_partition_of_constant_rate(self):
        start=t(.8);reset=t(.65);r=.51
        a=simulate_autonomous(start,reset,t([r]),t([8.]))
        b=simulate_autonomous(start,reset,t([r]*5),t([.67,1.03,2.11,.81,3.38]))
        self.assertEqual(len(a.events),len(b.events))
        self.assertTrue(torch.allclose(a.events,b.events,atol=1e-11,rtol=0))
        self.assertAlmostEqual(float(a.margin_end),float(b.margin_end),places=11)

    def test_signed_event_time_gradient_vs_independent_finite_difference(self):
        m=t(.8,True);reset=t(.6,True)
        rates=t([.38,.41,.43],True);dt=t([2.,2.,3.],True)
        path=simulate_autonomous(m,reset,rates,dt)
        self.assertGreaterEqual(len(path.events),3)
        # Independent centered finite differences wrt each selected input.
        score=sum((k+1)*v for k,v in enumerate(path.events))+.1*path.margin_end
        grads=torch.autograd.grad(score,(m,reset,rates,dt))
        def f(mv,rv,rat,durations):
            q=simulate_autonomous(t(mv),t(rv),t(rat),t(durations))
            self.assertEqual(len(q.events),len(path.events))
            return sum((k+1)*float(v) for k,v in enumerate(q.events))+.1*float(q.margin_end)
        base=[float(m.detach()),float(reset.detach()),rates.detach().tolist(),dt.detach().tolist()]
        eps=1.e-6
        for kind,index in ((0,0),(1,0),(2,0),(2,1),(2,2),(3,0),(3,1),(3,2)):
            plus=[base[0],base[1],list(base[2]),list(base[3])]
            minus=[base[0],base[1],list(base[2]),list(base[3])]
            if kind<2:
                plus[kind]+=eps;minus[kind]-=eps
                true_g=float(grads[kind])
            else:
                plus[kind][index]+=eps;minus[kind][index]-=eps
                true_g=float(grads[kind][index])
            fd=(f(*plus)-f(*minus))/(2*eps)
            with self.subTest(variable=(kind,index)):
                self.assertLess(abs(fd-true_g),2e-6)

    def test_event_count_is_non_differentiable_at_contact(self):
        a=simulate_autonomous(t(1.),t(.7),t([1.]),t([1.]))
        b=simulate_autonomous(t(1.+1.e-8),t(.7),t([1.]),t([1.]))
        self.assertEqual(len(a.events),1)
        self.assertEqual(len(b.events),0)
        self.assertEqual(a.derivative_scope,'fixed-event-count-and-order-only')

    def test_trainable_autonomous_event_times(self):
        result=event_time_calibration(steps=100)
        self.assertEqual(result['event_count'],3)
        self.assertLess(result['final_event_time_mse'],result['initial_event_time_mse']*.001)
        self.assertLess(abs(result['estimated_rate']-.53),.003)
        self.assertFalse(result['supports_grad_through_event_count'])

    def test_reject_invalid_and_zeno_budget(self):
        with self.assertRaises(ValueError):
            simulate_autonomous(t(.8),t(.7),t([0.]),t([1.]))
        with self.assertRaises(ValueError):
            simulate_autonomous(t(.8),t(0.),t([1.]),t([1.]))
        with self.assertRaises(ValueError):
            simulate_autonomous(t(.8),t(.7),t([.2]),t([1.]),max_events=0)
        with self.assertRaises(ArithmeticError):
            simulate_autonomous(t(.01),t(.001),t([1.]),t([1.]),max_events=2)

if __name__=='__main__':unittest.main()
