"""Semantic regression checks, independent of any performance claim."""
import unittest
import numpy as np
import torch

try:
    from .p3_round2_study import EmbeddingMemory, fixed_coverage, forward, mapped_put_linear, stream
    from .p3_round2_features import image_split
    from .p4_round2_online import step
except ImportError:
    from p3_round2_study import EmbeddingMemory, fixed_coverage, forward, mapped_put_linear, stream
    from p3_round2_features import image_split
    from p4_round2_online import step


def fixture():
    rng=np.random.default_rng(123)
    image=rng.normal(size=(21,512)).astype(np.float32)
    image/=np.linalg.norm(image,axis=-1,keepdims=True)
    text=rng.normal(size=(21,512)).astype(np.float32)
    text/=np.linalg.norm(text,axis=-1,keepdims=True)
    return {"sugar_split":np.repeat(np.arange(3),7),"sugar_image_index":np.arange(21),
            "sugar_kind":np.tile(np.arange(7),3),"coco_image":image,
            "sugar_positive":text,"sugar_negative":-text}


class Round2Semantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def test_image_split_shared_across_captions(self):
        names=[f"{i:012d}.jpg" for i in range(200)]
        first={name:image_split(name) for name in names}
        self.assertEqual(set(first.values()),{"train","calibration","test"})
        self.assertEqual(first,{name:image_split(name) for name in reversed(names)})

    def test_constant_scores_cannot_fake_fixed_quality_rejection(self):
        result=fixed_coverage(np.ones(20),np.ones(7),.95)
        self.assertEqual(result["id_acceptance"],.95)
        self.assertAlmostEqual(result["unknown_false_acceptance"],.95)
        self.assertFalse(result["deployable_threshold"])
        with self.assertRaises(ValueError):fixed_coverage([],np.ones(7))

    def test_future_and_targets_do_not_affect_past_outputs(self):
        data=stream(fixture(),split="train",seed=12,batch=3,length=8)
        model=EmbeddingMemory("call_put")
        old=forward(model,data)
        data["image"][:,4:]*=-1;data["text"][:,4:]*=-1
        data["target_image"].fill_(123);data["target_text"].fill_(-123)
        data["last_image_row"].fill(999)
        new=forward(model,data)
        for x,y in zip(old,new):torch.testing.assert_close(x[:,:4],y[:,:4],rtol=0,atol=0)

    def test_absent_payload_cannot_write_memory(self):
        data=stream(fixture(),split="test",seed=4,batch=7,length=12,
                    scenario="long_blank",anchors=np.arange(14,21))
        for mode in ("call_put","ordinary","overwrite"):
            model=EmbeddingMemory(mode)
            before=forward(model,data)
            mutated={k:v.clone() if isinstance(v,torch.Tensor) else v for k,v in data.items()}
            mutated["image"][:,6:]=1e6;mutated["text"][:,6:]=-1e6
            after=forward(model,mutated)
            for a,b in zip(before,after):
                torch.testing.assert_close(a,b,rtol=0,atol=0)
                torch.testing.assert_close(a[:,5],a[:,-1],rtol=0,atol=0)

    def test_overwrite_tracks_last_observed_entity_under_all_scenarios(self):
        a=fixture();model=EmbeddingMemory("overwrite")
        for scenario in ("aligned","missing_image","missing_text","misaligned_text","irregular_time","long_blank"):
            data=stream(a,split="test",seed=14,batch=7,length=12,scenario=scenario,anchors=np.arange(14,21))
            image,text=forward(model,data)
            torch.testing.assert_close(image,data["target_image"],rtol=1e-6,atol=1e-7)
            torch.testing.assert_close(text,data["target_text"],rtol=1e-6,atol=1e-7)

    def test_mapped_controller_has_same_full_causal_trajectory(self):
        torch.manual_seed(17)
        model=EmbeddingMemory("call_put").double()
        mapped=mapped_put_linear(model).double()
        data=stream(fixture(),split="test",seed=3,batch=7,length=12,scenario="irregular_time",anchors=np.arange(14,21))
        for k in ("image","text","dt"):data[k]=data[k].double()
        for x,y in zip(forward(model,data),forward(mapped,data)):
            torch.testing.assert_close(x,y,rtol=1e-12,atol=1e-14)

    def test_invalid_domains_rejected(self):
        model=EmbeddingMemory("ordinary")
        data=stream(fixture(),split="train",seed=6,batch=2,length=8)
        data["dt"][0,2]=0
        with self.assertRaises(ValueError):forward(model,data)
        with self.assertRaises(ValueError):stream(fixture(),split="train",seed=4,batch=1,anchors=[14])

    def test_online_adapter_matches_full_observed_sequence(self):
        data=stream(fixture(),split="train",seed=15,batch=3,length=8)
        data["observed"].fill_(True);data["dt"].fill_(1)
        for mode in ("call_put","put_linear","ordinary","overwrite"):
            model=EmbeddingMemory(mode)
            full=forward(model,data);state=None
            for t in range(8):
                state=step(model,data["image"][:,t],data["text"][:,t],state)
                for expected,actual in zip(full,state):
                    torch.testing.assert_close(expected[:,t],actual,rtol=0,atol=0)


if __name__ == "__main__":
    unittest.main()
