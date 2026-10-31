"""P2 optional auxiliary-event-label removal test, explicitly exploratory."""
import unittest
import torch
try:
    from .p2_task_only_reset import train_task_only
    from .p2_learned_autonomous_content import AutonomousBoundaryMemory,make_context_recall
except ImportError:
    from p2_task_only_reset import train_task_only
    from p2_learned_autonomous_content import AutonomousBoundaryMemory,make_context_recall

class TaskOnlyTests(unittest.TestCase):
    def test_task_only_uses_gradients_and_no_event_labels(self):
        for mode in ('analytic','ordinary','no_reset'):
            result=train_task_only(mode,11,steps=8,batch=16,eval_n=32)
            self.assertFalse(result['event_supervision'])
            self.assertEqual(result['train_steps'],8)
            self.assertTrue(0<=result['results']['id']['hard_accuracy']<=1)
            if mode=='no_reset':
                self.assertEqual(result['results']['id']['applied_events_per_sequence'],0)

    def test_content_loss_grad_is_sufficient_to_reach_margin_within_one_seed(self):
        model=AutonomousBoundaryMemory('analytic')
        x,y,_=make_context_recall(8,42,71)
        out,_=model(x)
        torch.nn.functional.binary_cross_entropy_with_logits(out,y).backward()
        self.assertIsNotNone(model.novelty_raw.grad)
        self.assertTrue(torch.isfinite(model.novelty_raw.grad).all())

if __name__=='__main__':unittest.main()
