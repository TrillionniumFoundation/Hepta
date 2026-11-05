"""Independent invariants for the content-supported memory research reference."""
import unittest
import numpy as np
import torch
try:
    from .p2_content_hold import ContentHoldMemory, MODES, make_task, task_loss, train, evaluate, paired_delay, independent_matrix_reference
except ImportError:
    from p2_content_hold import ContentHoldMemory, MODES, make_task, task_loss, train, evaluate, paired_delay, independent_matrix_reference


class ContentHoldTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)

    def test_independent_matrix_exponential(self):
        rng = np.random.default_rng(8131)
        x = rng.uniform(-1, 1, (3, 9, 4))
        x[:, 2] = 0.
        dt = rng.uniform(.03, 4., (3, 9))
        for mode in MODES:
            model = ContentHoldMemory(mode, 11)
            actual = model(torch.tensor(x), torch.tensor(dt)).detach().numpy()
            for row in range(3):
                np.testing.assert_allclose(actual[row], independent_matrix_reference(model,x[row],dt[row]),atol=7e-14,rtol=0)

    def test_mapped_ordinary_control_value_and_gradients(self):
        data = make_task(1011,n=6,length=12)
        a = ContentHoldMemory('protected_ctmc',23)
        b = ContentHoldMemory('ordinary_exponential',23)
        torch.testing.assert_close(a(data.payload,data.duration), b(data.payload,data.duration),atol=3e-15,rtol=0)
        la,lb=task_loss(a,data),task_loss(b,data)
        la.backward();lb.backward()
        torch.testing.assert_close(a.raw_rates.grad,b.raw_rates.grad,atol=3e-15,rtol=0)
        self.assertEqual(sum(p.numel() for p in a.parameters()),4)

    def test_zero_blank_hold_and_leaky_counterexample(self):
        x=torch.zeros((2,1,3),dtype=torch.float64)
        dt=torch.tensor([[1e6],[1e6]],dtype=torch.float64)
        initial=torch.tensor([[.1,.3,.9],[.7,.8,.2]],dtype=torch.float64)
        for mode in ('protected_ctmc','ordinary_exponential'):
            model=ContentHoldMemory(mode,11)
            torch.testing.assert_close(model(x,dt,initial)[:,-1],initial,atol=1e-16,rtol=0)
        leaky=ContentHoldMemory('leaky_ctmc',11)
        torch.testing.assert_close(leaky(x,dt,initial)[:,-1],torch.full_like(initial,.5),atol=1e-16,rtol=0)

    def test_physical_refinement_streaming_and_no_future_leak(self):
        data=make_task(2011,n=4,length=16)
        for mode in MODES:
            model=ContentHoldMemory(mode,11)
            full=model(data.payload,data.duration)
            refined=model(data.payload.repeat_interleave(7,1),data.duration.repeat_interleave(7,1)/7)[:,6::7]
            torch.testing.assert_close(full,refined,atol=8e-15,rtol=0)
            first=model(data.payload[:,:8],data.duration[:,:8])
            second=model(data.payload[:,8:],data.duration[:,8:],first[:,-1])
            torch.testing.assert_close(full,torch.cat((first,second),dim=1),atol=3e-15,rtol=0)
            changed=data.payload.clone();changed[:,8:]*=-1
            torch.testing.assert_close(full[:,:8],model(changed,data.duration)[:,:8],atol=0,rtol=0)

    def test_query_does_not_mutate_and_preserves_other_keys(self):
        model=ContentHoldMemory('protected_ctmc',11)
        initial=torch.tensor([[.2,.4,.7]],dtype=torch.float64)
        x=torch.tensor([[[1.,0.,0.]]],dtype=torch.float64)
        state=model(x,torch.ones((1,1),dtype=torch.float64),initial)[:,-1]
        torch.testing.assert_close(state[:,1:],initial[:,1:],atol=0,rtol=0)
        before=state.clone()
        for key in (0,1,2,0): model.query(state,torch.tensor([key]))
        torch.testing.assert_close(state,before,atol=0,rtol=0)

    def test_loss_gradient_finite_difference(self):
        model=ContentHoldMemory('protected_ctmc',37)
        data=make_task(3011,n=3,length=13)
        task_loss(model,data).backward();actual=model.raw_rates.grad.clone()
        eps=1e-5
        for row in range(2):
            for col in range(2):
                with torch.no_grad(): model.raw_rates[row,col]+=eps
                plus=task_loss(model,data).item()
                with torch.no_grad(): model.raw_rates[row,col]-=2*eps
                minus=task_loss(model,data).item()
                with torch.no_grad(): model.raw_rates[row,col]+=eps
                self.assertAlmostEqual(actual[row,col].item(),(plus-minus)/(2*eps),delta=1e-9)

    def test_missing_information_bound_and_noise_limitation(self):
        model=ContentHoldMemory('protected_ctmc',11)
        # Opposite missing final writes induce identical observed inputs.
        x=torch.tensor([[[1.],[0.]],[[1.],[0.]]],dtype=torch.float64)
        dt=torch.tensor([[1.,256.],[1.,256.]],dtype=torch.float64)
        p=model(x,dt)[:,-1,0]
        expected=(p[0]+1-p[1])/2
        self.assertAlmostEqual(float(expected.detach()),.5,delta=1e-15)
        clean=paired_delay(model,1e6)
        noisy=paired_delay(model,1e6,noise=.05)
        self.assertGreater(clean['balanced_endpoint_bayes_accuracy'],.5)
        self.assertAlmostEqual(noisy['balanced_endpoint_bayes_accuracy'],.5,delta=1e-12)

    def test_task_training_smoke_and_overwrite(self):
        model,r=train('protected_ctmc',11,steps=50,n=12,length=16)
        self.assertLess(r['final_nll'],r['initial_nll']-.1)
        self.assertGreater(evaluate(model,make_task(92301,n=16,length=32))['expected_sampled_state_accuracy'],.8)
        self.assertEqual(r['trainable_parameters'],4)

    def test_independent_gillespie_endpoints(self):
        try:
            from .p2_content_hold_evidence import independent_sample
        except ImportError:
            from p2_content_hold_evidence import independent_sample
        model=ContentHoldMemory('leaky_ctmc',11)
        exact=paired_delay(model,16.)
        for last in (0,1):
            p=exact['p_after_last_one' if last else 'p_after_last_zero']
            n=1600
            samples=[independent_sample(model,last,16.,510000+10000*last+i) for i in range(n)]
            empirical=sum(s for s,_ in samples)/n
            self.assertLess(abs(empirical-p)/(p*(1-p)/n)**.5,4.5)
            self.assertGreater(sum(events for _,events in samples)/n,.5)

    def test_reject_malformed_payload_time_and_query(self):
        model=ContentHoldMemory('protected_ctmc')
        x=torch.zeros((2,3,4),dtype=torch.float64);dt=torch.ones((2,3),dtype=torch.float64)
        for bad in (x.float(),x[:,:0],x+float('nan'),x+1.1):
            with self.assertRaises(ValueError): model(bad,dt)
        for bad in (dt.float(),dt*0,dt*-1,dt+float('inf'),dt[:,:2]):
            with self.assertRaises(ValueError): model(x,bad)
        state=model(x,dt)
        with self.assertRaises(ValueError): model.query(state,torch.full((2,3),4,dtype=torch.long))
        with self.assertRaises(ValueError): model.query(state,torch.zeros((2,3)))

if __name__=='__main__': unittest.main()
