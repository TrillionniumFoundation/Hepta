"""P2 moving-boundary exact-event and signed-gradient checks; not neural recall."""
import unittest
import numpy as np
import torch

try:
    from .moving_boundary_events import simulate_moving_boundary
except ImportError:
    from moving_boundary_events import simulate_moving_boundary


def td(v,grad=False):
    return torch.tensor(v,dtype=torch.float64,requires_grad=grad)


class MovingBoundaryEventTests(unittest.TestCase):
    def test_boundary_moves_through_stationary_state(self):
        out=simulate_moving_boundary(td(1.),td(0.),td(.6),
                                      td([0.]),td([.5]),td([5.]))
        self.assertEqual(len(out.event_times),3)
        self.assertTrue(torch.allclose(out.event_times,td([2.,3.2,4.4]),atol=1e-12,rtol=0))
        self.assertTrue(torch.allclose(out.event_log_boundaries,td([1.,1.6,2.2]),atol=1e-12,rtol=0))
        self.assertAlmostEqual(float(out.log_margin_end),.3,places=12)
        self.assertAlmostEqual(float(out.log_boundary_end),2.5,places=12)

    def test_signed_retreating_boundary_no_event(self):
        # log-state rises and boundary declines, so margin grows.
        out=simulate_moving_boundary(td(.5),td(0.),td(.8),
                                      td([.3,-.1]),td([-.2,-.2]),td([1.,2.]))
        self.assertEqual(len(out.event_times),0)
        self.assertAlmostEqual(float(out.log_margin_end),1.2,places=12)

    def test_partition_independence_when_slopes_constant(self):
        args=(td(1.),td(0.),td(.6))
        single=simulate_moving_boundary(*args,td([.05]),td([.5]),td([5.]))
        partition=simulate_moving_boundary(*args,td([.05]*4),td([.5]*4),td([.7,1.3,1.4,1.6]))
        self.assertEqual(len(single.event_times),len(partition.event_times))
        self.assertTrue(torch.allclose(single.event_times,partition.event_times,atol=1e-12,rtol=0))
        self.assertAlmostEqual(float(single.log_margin_end),float(partition.log_margin_end),places=12)

    def test_exact_signed_event_gradients_and_boundary_value(self):
        x=td(.9,True);b=td(-.1,True);reset=td(.63,True)
        vs=td([.08,-.01,.12],True);vb=td([.55,.3,.6],True)
        dt=td([1.8,2.2,2.1],True)
        original=simulate_moving_boundary(x,b,reset,vs,vb,dt)
        self.assertGreaterEqual(len(original.event_times),2)
        score=sum((j+1)*s for j,s in enumerate(original.event_times)) + \
              .4*original.log_state_end - .2*original.log_boundary_end
        grads=torch.autograd.grad(score,(x,b,reset,vs,vb,dt))
        base=(float(x.detach()),float(b.detach()),float(reset.detach()),vs.detach().tolist(),vb.detach().tolist(),dt.detach().tolist())
        def objective(params):
            q=simulate_moving_boundary(*(td(z) for z in params))
            self.assertEqual(len(q.event_times),len(original.event_times))
            return (sum((j+1)*float(z) for j,z in enumerate(q.event_times))
                    +.4*float(q.log_state_end)-.2*float(q.log_boundary_end))
        eps=1e-6
        for group,index in [(0,0),(1,0),(2,0)]+[(j,k) for j in (3,4,5) for k in range(3)]:
            plus=[base[0],base[1],base[2],list(base[3]),list(base[4]),list(base[5])]
            minus=[base[0],base[1],base[2],list(base[3]),list(base[4]),list(base[5])]
            if group<3:
                plus[group]+=eps; minus[group]-=eps
                exact=float(grads[group])
            else:
                plus[group][index]+=eps;minus[group][index]-=eps
                exact=float(grads[group][index])
            numerical=(objective(plus)-objective(minus))/(2*eps)
            with self.subTest(group=group,index=index):
                self.assertLess(abs(numerical-exact),4e-6)

    def test_random_fixed_event_count_gradient_panels(self):
        rng=np.random.default_rng(940471)
        successes=0
        for _ in range(64):
            x0=float(rng.uniform(.65,1.1));b0=0.
            reset=float(rng.uniform(.5,.9))
            state=rng.uniform(-.14,.08,size=3)
            boundary=rng.uniform(.32,.64,size=3)
            dt=rng.uniform(.9,1.9,size=3)
            a=td(x0,True); c=td(b0,True); d=td(reset,True)
            e=td(state,True); f=td(boundary,True); g=td(dt,True)
            path=simulate_moving_boundary(a,c,d,e,f,g)
            if not len(path.event_times):continue
            endpoints=np.cumsum(dt)
            if np.min(np.abs(path.event_times.detach().numpy()[:,None]-endpoints[None,:]))<.06:
                continue
            score=path.event_times.sum()+.1*path.log_state_end
            grads=torch.autograd.grad(score,(a,c,d,e,f,g))
            eps=1.e-6
            for group,index in [(0,0),(1,0),(2,0),(3,1),(4,1),(5,1)]:
                q1=[x0,b0,reset,state.tolist(),boundary.tolist(),dt.tolist()]
                q2=[x0,b0,reset,state.tolist(),boundary.tolist(),dt.tolist()]
                if group<3:
                    q1[group]+=eps;q2[group]-=eps
                    analytic=float(grads[group])
                else:
                    q1[group][index]+=eps;q2[group][index]-=eps
                    analytic=float(grads[group][index])
                def value(z):
                    t=simulate_moving_boundary(*(td(y) for y in z))
                    self.assertEqual(len(t.event_times),len(path.event_times))
                    return float(t.event_times.sum()+.1*t.log_state_end)
                error=abs((value(q1)-value(q2))/(2*eps)-analytic)
                self.assertLess(error,5e-6)
            successes+=1
        self.assertGreaterEqual(successes,45)

    def test_contact_event_count_is_discontinuous(self):
        hit=simulate_moving_boundary(td(1.),td(0.),td(.5),td([0.]),td([1.]),td([1.]))
        miss=simulate_moving_boundary(td(1.+1e-9),td(0.),td(.5),td([0.]),td([1.]),td([1.]))
        self.assertEqual(len(hit.event_times),1)
        self.assertEqual(len(miss.event_times),0)
        self.assertIn('fixed-event-count',hit.derivative_scope)

    def test_bad_inputs_and_zeno_guard(self):
        with self.assertRaises(ValueError):
            simulate_moving_boundary(td(0.),td(0.),td(.3),td([0.]),td([1.]),td([1.]))
        with self.assertRaises(ValueError):
            simulate_moving_boundary(td(.5),td(0.),td(0.),td([0.]),td([1.]),td([1.]))
        with self.assertRaises(ValueError):
            simulate_moving_boundary(td(.5),td(0.),td(.3),td([0.]),td([1.]),td([0.]))
        with self.assertRaises(ArithmeticError):
            simulate_moving_boundary(td(.01),td(0.),td(.01),td([0.]),td([1.]),td([2.]),max_events=3)


if __name__=='__main__':
    unittest.main()
