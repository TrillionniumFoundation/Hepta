"""Image-disjoint natural-caption memory and calibrated new-image rejection.

This is a prospective fixed subset relative to round1, not an official full
SugarCrepe score. The temporal streams are synthetic. Caption labels and image
identities enter losses/metrics only. All actual model inputs are frozen image
or text vectors, observation masks, and elapsed intervals.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import resource
import time

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

try:
    from .p3_frozen_temporal_fusion import TemporalFusion
    from .p3_round2_features import KINDS, SPLITS
except ImportError:
    from p3_frozen_temporal_fusion import TemporalFusion
    from p3_round2_features import KINDS, SPLITS

SCENARIOS = ("aligned", "missing_image", "missing_text", "misaligned_text", "irregular_time", "long_blank")


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_bundle(path):
    path = Path(path)
    receipt = json.loads(path.with_suffix(".json").read_text())
    if receipt["features_sha256"] != file_sha(path) or receipt["encoder_frozen"] is not True:
        raise ValueError("frozen feature digest mismatch")
    with np.load(path, allow_pickle=False) as data:
        a = {key: data[key].copy() for key in data.files}
    rows = receipt["sugar_rows"]
    if len(rows) != len(a["sugar_split"]) or a["sugar_positive"].shape != (len(rows), 512):
        raise ValueError("bad caption feature shape")
    image_names = [r["filename"] for r in receipt["coco_images"]]
    for i, row in enumerate(rows):
        if (image_names[a["sugar_image_index"][i]] != row["filename"]
            or a["sugar_split"][i] != SPLITS.index(row["split"])
            or a["sugar_kind"][i] != KINDS.index(row["kind"])):
            raise ValueError("source row/feature mismatch")
    sets = [{r["filename"] for r in rows if r["split"] == s} for s in SPLITS]
    if any(sets[i] & sets[j] for i in range(3) for j in range(i)):
        raise ValueError("source image leakage")
    pixels = [{r["rgb_sha256"] for r in receipt["coco_images"] if r["filename"] in ids} for ids in sets]
    if any(pixels[i] & pixels[j] for i in range(3) for j in range(i)):
        raise ValueError("decoded image leakage")
    if any(not np.isfinite(v).all() for v in a.values()):
        raise ValueError("nonfinite feature bundle")
    return a, receipt


def wilson(k, n):
    if not n:
        return None
    z = 1.959963984540054
    p, den = k / n, 1 + z*z/n
    center = (p + z*z/(2*n)) / den
    half = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / den
    return [center-half, center+half]


def fixed_coverage(id_scores, ood_scores, coverage=.95):
    """Retrospective ID-ROC diagnostic; randomize only cutoff score ties.

    Does not inspect OOD labels/scores to choose its threshold, but uses the
    test ID distribution and MUST NOT be a deployable calibration threshold.
    """
    x, y = np.asarray(id_scores), np.asarray(ood_scores)
    if not 0 < coverage < 1 or not len(x) or not len(y):
        raise ValueError("nonempty scores and interior coverage required")
    k = int(math.floor(coverage * len(x)))
    if not 0 < k < len(x):
        raise ValueError("insufficient ID samples for target coverage")
    threshold = float(np.sort(x)[len(x)-k])
    gt, eq = int((x > threshold).sum()), int((x == threshold).sum())
    fraction = (k - gt) / eq
    return {"threshold": threshold, "threshold_tie_accept_probability": fraction,
            "id_acceptance": k / len(x), "id_expected_accept_count": k,
            "unknown_false_acceptance": float(((y > threshold).sum()+fraction*(y == threshold).sum())/len(y)),
            "test_id_used_for_threshold": True, "deployable_threshold": False}


def rejection_study(a, receipt, old_path):
    old_path = Path(old_path)
    old_receipt = json.loads(old_path.with_suffix(".json").read_text())
    if file_sha(old_path) != old_receipt["features_sha256"]:
        raise ValueError("prior training feature digest mismatch")
    with np.load(old_path, allow_pickle=False) as source:
        use = source["train_labels"] < 8
        train = source["train_embeddings"][use].astype(np.float64)
        labels = source["train_labels"][use]
    previous = {r["rgb_pixels_sha256"] if "rgb_pixels_sha256" in r else r.get("pixels_sha256")
                for split in old_receipt["selections"].values() for r in split}
    # Index namespaces are the same pinned parquet source and row ordering.
    old_ids = {(r["official_split"], r["index"]) for split in old_receipt["selections"].values() for r in split}
    new_ids = {(r["official_split"], r["index"]) for split in receipt["cifar_selections"].values() for r in split}
    if old_ids & new_ids:
        raise ValueError("round1/round2 CIFAR source overlap")
    new_pixels = {r["rgb_sha256"] for split in receipt["cifar_selections"].values() for r in split}
    if (previous - {None}) & new_pixels:
        raise ValueError("round1/round2 CIFAR pixel overlap")
    prototypes = a["cifar_text"][:8].astype(np.float64)
    centroid = np.stack([train[labels == c].mean(0) for c in range(8)])
    centroid /= np.linalg.norm(centroid, axis=-1, keepdims=True)
    score_arrays = {}
    for split in ("calibration", "test"):
        x = a["cifar_"+split].astype(np.float64)
        cosine = x @ prototypes.T
        logit = receipt["logit_scale"] * cosine
        prob = np.exp(logit-logit.max(-1, keepdims=True))
        prob /= prob.sum(-1, keepdims=True)
        score_arrays[split] = {"max_softmax": prob.max(-1), "max_text_cosine": cosine.max(-1),
            "nearest_training_image": (x @ train.T).max(-1), "nearest_class_centroid": (x @ centroid.T).max(-1)}
    cal_y, test_y = a["cifar_calibration_labels"], a["cifar_test_labels"]
    if not (cal_y < 8).all():
        raise ValueError("unknown input cannot calibrate rejection")
    known = test_y < 8
    results = {}
    for method, cal_scores in score_arrays["calibration"].items():
        threshold = float(np.quantile(cal_scores, .05, method="lower"))
        scores = score_arrays["test"][method]
        id_scores, ood_scores = scores[known], scores[~known]
        ki, ku = int((id_scores >= threshold).sum()), int((ood_scores >= threshold).sum())
        results[method] = {"id_only_calibration_threshold": threshold,
            "calibration_count": len(cal_scores), "calibration_acceptance": float((cal_scores >= threshold).mean()),
            "test_id_count": len(id_scores), "test_unknown_count": len(ood_scores),
            "test_id_accept_count": ki, "test_id_acceptance": ki/len(id_scores), "id_wilson95": wilson(ki,len(id_scores)),
            "test_unknown_accept_count": ku, "test_unknown_false_acceptance": ku/len(ood_scores),
            "unknown_wilson95": wilson(ku,len(ood_scores)),
            "id_vs_unknown_auroc": float(np.mean((id_scores[:,None] > ood_scores[None,:]).astype(float)
                                                + .5*(id_scores[:,None] == ood_scores[None,:]))),
            "fixed_test_id_coverage_diagnostic": fixed_coverage(id_scores,ood_scores),
            "calibration_scores": cal_scores.tolist(), "test_id_scores": id_scores.tolist(),
            "test_unknown_scores": ood_scores.tolist()}
    return {"methods": results, "training_known_images": len(train),
        "new_source_rows_disjoint_from_round1": True, "new_pixels_disjoint_from_round1": True,
        "same_taxonomy_as_round1": True, "unknown_to_fusion_not_pretraining": True,
        "scope": "distinct new static images; these rejection scores are encoder controls, not a special HCSN effect",
        "binomial_intervals_descriptive_for_this_class_balanced_subset": True}


class EmbeddingMemory(nn.Module):
    """Same eight-parameter gate as round1, now preserving full embeddings."""
    def __init__(self, mode):
        super().__init__()
        if mode not in ("call_put", "put_linear", "ordinary", "overwrite"):
            raise ValueError("unknown memory mode")
        self.mode = mode
        if mode != "overwrite":
            self.score = nn.Linear(4, 1)
            self.gate_readout = nn.Linear(2, 1)

    gate = TemporalFusion.gate

    def forward(self, image, text, observed, dt):
        if image.ndim != 3 or text.shape != image.shape or min(image.shape) <= 0:
            raise ValueError("nonempty B,T,D image/text required")
        if observed.shape != image.shape[:2]+(2,) or observed.dtype != torch.bool or dt.shape != image.shape[:2]:
            raise ValueError("bad mask/time shape")
        if not all(bool(torch.isfinite(x).all()) for x in (image,text,dt)) or bool((dt <= 0).any()):
            raise ValueError("finite vectors and strictly positive time required")
        b, length, d = image.shape
        h = [image.new_zeros(b,d), image.new_zeros(b,d)]
        seen = [torch.zeros((b,1),dtype=torch.bool,device=image.device), torch.zeros((b,1),dtype=torch.bool,device=image.device)]
        age = [image.new_zeros(b), image.new_zeros(b)]
        histories = [[],[]]
        for t in range(length):
            for m, data in enumerate((image,text)):
                obs = observed[:,t,m:m+1]
                age[m] = age[m] + dt[:,t]
                payload = torch.where(obs, data[:,t], torch.zeros_like(h[m]))
                gate = self.gate(payload,h[m],age[m])
                proposal = torch.where(seen[m], h[m]+gate*(payload-h[m]), payload)
                h[m] = torch.where(obs,proposal,h[m])
                seen[m] = seen[m] | obs
                age[m] = torch.where(obs[:,0], torch.zeros_like(age[m]), age[m])
                histories[m].append(h[m])
        return torch.stack(histories[0],1), torch.stack(histories[1],1)


def mapped_put_linear(model):
    if model.mode != "call_put":
        raise ValueError("map only Call/Put canonical coordinates")
    reference = next(model.parameters())
    result = EmbeddingMemory("put_linear").to(device=reference.device,dtype=reference.dtype)
    result.load_state_dict(copy.deepcopy(model.state_dict()))
    with torch.no_grad():
        wc, wp = model.gate_readout.weight[:,0].clone(), model.gate_readout.weight[:,1].clone()
        result.gate_readout.weight[:,0] = wc + wp
        result.gate_readout.weight[:,1] = wc
    return result


def stream(a, *, split, seed, batch=16, length=8, scenario="aligned", anchors=None):
    if split not in SPLITS or scenario not in SCENARIOS or length < 4 or batch <= 0:
        raise ValueError("bad stream domain")
    rng = np.random.default_rng(seed)
    pool = np.flatnonzero(a["sugar_split"] == SPLITS.index(split))
    if anchors is not None:
        anchors = np.asarray(anchors, dtype=np.int64)
        if len(anchors) != batch or not np.isin(anchors,pool).all():
            raise ValueError("anchors must belong to the requested split")
    ir = rng.choice(pool,size=(batch,length))
    tr = np.where(rng.random((batch,length)) < .8, ir, rng.choice(pool,size=(batch,length)))
    mask = rng.random((batch,length,2)) < .85
    mask[:,0] = True
    dt = np.ones((batch,length),dtype=np.float32)
    if anchors is not None:
        ir[:,-1], tr[:,-1] = anchors, anchors
        mask[:,-1] = True
        if scenario == "missing_image":
            ir[:,-3] = anchors; mask[:,-3,0] = True; mask[:,-2:,0] = False
        elif scenario == "missing_text":
            tr[:,-3] = anchors; mask[:,-3,1] = True; mask[:,-2:,1] = False
        elif scenario == "misaligned_text":
            tr[:,1:] = tr[:,:-1].copy(); mask[:,1:,1] = mask[:,:-1,1].copy(); mask[:,0,1] = False
        elif scenario == "long_blank":
            t = length//2-1
            ir[:,t],tr[:,t] = anchors,anchors; mask[:,t] = True; mask[:,t+1:] = False
            dt[:,t+1:] = 64
    if scenario == "irregular_time":
        dt = np.exp(rng.uniform(np.log(.02),np.log(32),size=dt.shape)).astype(np.float32)
    image = a["coco_image"][a["sugar_image_index"][ir]]
    text = a["sugar_positive"][tr]
    lasts = [np.full((batch,length),-1,dtype=np.int64) for _ in range(2)]
    for t in range(length):
        for m, ids in enumerate((ir,tr)):
            previous = lasts[m][:,t-1] if t else np.full(batch,-1)
            lasts[m][:,t] = np.where(mask[:,t,m],ids[:,t],previous)
    targets = [np.zeros_like(image), np.zeros_like(text)]
    for m, source in enumerate((a["coco_image"][a["sugar_image_index"]],a["sugar_positive"])):
        valid = lasts[m] >= 0
        targets[m][valid] = source[lasts[m][valid]]
    return {"image":torch.from_numpy(image),"text":torch.from_numpy(text),
        "observed":torch.from_numpy(mask),"dt":torch.from_numpy(dt),
        "target_image":torch.from_numpy(targets[0]),"target_text":torch.from_numpy(targets[1]),
        "last_image_row":lasts[0],"last_text_row":lasts[1],"image_rows":ir,"text_rows":tr}


def forward(model,batch):
    return model(batch["image"],batch["text"],batch["observed"],batch["dt"])


def evaluate(model,a,batch,anchors):
    with torch.inference_mode():
        hi,ht = forward(model,batch)
        hi,ht = F.normalize(hi[:,-1],dim=-1).numpy(),F.normalize(ht[:,-1],dim=-1).numpy()
    gallery = np.flatnonzero(a["sugar_split"] == 2)
    gallery_images = np.unique(a["sugar_image_index"][gallery])
    pred_i = a["sugar_image_index"][gallery[np.argmax(hi@a["sugar_positive"][gallery].T,axis=-1)]]
    pred_t = gallery_images[np.argmax(ht@a["coco_image"][gallery_images].T,axis=-1)]
    truth_i = a["sugar_image_index"][batch["last_image_row"][:,-1]]
    truth_t = a["sugar_image_index"][batch["last_text_row"][:,-1]]
    if not np.array_equal(truth_i,a["sugar_image_index"][anchors]):
        raise ValueError("hard-negative anchor does not match last observed image")
    pos = np.sum(hi*a["sugar_positive"][anchors],axis=-1)
    neg = np.sum(hi*a["sugar_negative"][anchors],axis=-1)
    correct = (pos > neg).astype(float) + .5*(pos == neg)
    return {"rows":len(anchors),"unique_source_images":len(np.unique(truth_i)),
        "hard_negative_accuracy":float(correct.mean()),
        "hard_negative_by_type":{kind:float(correct[a["sugar_kind"][anchors]==k].mean()) for k,kind in enumerate(KINDS)},
        "image_to_caption_entity_recall":float((pred_i==truth_i).mean()),
        "caption_to_image_entity_recall":float((pred_t==truth_t).mean()),
        "joint_entity_recall":float(((pred_i==truth_i)&(pred_t==truth_t)).mean()),
        "raw_hard_negative_correct":correct.tolist(),"raw_positive_score":pos.tolist(),"raw_negative_score":neg.tolist(),
        "raw_image_retrieval_correct":(pred_i==truth_i).tolist(),
        "raw_text_retrieval_correct":(pred_t==truth_t).tolist()}


def benchmark(models,batch,seed=920061,repeats=60):
    rng = np.random.default_rng(seed)
    samples = {mode:{"wall_ns":[],"cpu_ns":[]} for mode in models}
    with torch.inference_mode():
        for model in models.values():
            for _ in range(3):forward(model,batch)
        for _ in range(repeats):
            for mode in rng.permutation(list(models)):
                w,c=time.perf_counter_ns(),time.process_time_ns()
                forward(models[mode],batch)
                samples[mode]["cpu_ns"].append(time.process_time_ns()-c)
                samples[mode]["wall_ns"].append(time.perf_counter_ns()-w)
    for value in samples.values():
        value.update({"p50_wall_ms":float(np.quantile(value["wall_ns"],.5)/1e6),
            "p99_wall_ms":float(np.quantile(value["wall_ns"],.99)/1e6),
            "median_cpu_ms":float(np.median(value["cpu_ns"])/1e6)})
    return {"randomized_interleaving":True,"repeats_per_mode":repeats,"batch":batch["image"].shape[0],
        "length":batch["image"].shape[1],"samples":samples,"energy_joules":None,
        "scope":"complete CPU fusion and validation; frozen vectors already encoded"}


def study(path,old_path,protocol):
    torch.set_num_threads(1)
    a,receipt=load_bundle(path)
    if file_sha(protocol) != receipt["protocol_sha256"]:
        raise ValueError("protocol changed after feature acquisition")
    rejection = rejection_study(a,receipt,old_path)
    anchors = np.flatnonzero(a["sugar_split"]==2)
    panels = {s:stream(a,split="test",seed=820061,batch=len(anchors),length=12,scenario=s,anchors=anchors) for s in SCENARIOS}
    rows=[];timings=[];mapped_errors=[]
    for seed in (61,73,89):
        models={}
        for mode in ("call_put","ordinary","overwrite"):
            torch.manual_seed(seed)
            model=EmbeddingMemory(mode)
            w,c=time.perf_counter(),time.process_time()
            loss_value=None
            if mode != "overwrite":
                opt=torch.optim.Adam(model.parameters(),lr=.01)
                for step in range(120):
                    data=stream(a,split="train",seed=seed*10000+step,batch=16,length=8)
                    pred=forward(model,data)
                    loss=sum((1-F.cosine_similarity(p,data[k],dim=-1)).mean()
                             for p,k in zip(pred,("target_image","target_text")))
                    opt.zero_grad(set_to_none=True);loss.backward()
                    if not all(p.grad is not None and bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
                        raise ArithmeticError("nonfinite or missing gradient")
                    opt.step()
                loss_value=float(loss.detach())
            model.eval();models[mode]=model
            rows.append({"seed":seed,"mode":mode,"training_steps":0 if mode=="overwrite" else 120,
                "trainable_parameters":sum(p.numel() for p in model.parameters()),
                "training_wall_seconds":time.perf_counter()-w,"training_cpu_seconds":time.process_time()-c,
                "last_loss":loss_value,"state_dict":{k:v.tolist() for k,v in model.state_dict().items()},
                "evaluations":{s:evaluate(model,a,b,anchors) for s,b in panels.items()}})
            print(json.dumps({"seed":seed,"mode":mode,"aligned_hard_negative":rows[-1]["evaluations"]["aligned"]["hard_negative_accuracy"]}),flush=True)
        models["put_linear_mapped"]=mapped_put_linear(models["call_put"]).eval()
        mapped=models["put_linear_mapped"]
        errors=[]
        with torch.inference_mode():
            for panel in panels.values():
                ref,out=forward(models["call_put"],panel),forward(mapped,panel)
                errors.append(max(float((x-y).abs().max()) for x,y in zip(ref,out)))
        mapped_errors.append({"seed":seed,"max_state_abs_error":max(errors)})
        rows.append({"seed":seed,"mode":"put_linear_mapped","training_steps":0,
            "trained_function_source":"call_put","trainable_parameters":sum(p.numel() for p in mapped.parameters()),
            "state_dict":{k:v.tolist() for k,v in mapped.state_dict().items()},
            "evaluations":{s:evaluate(mapped,a,b,anchors) for s,b in panels.items()}})
        timed=stream(a,split="test",seed=550061,batch=8,length=12)
        timings.append({"seed":seed,**benchmark(models,timed,seed=920000+seed)})
    scalar=("hard_negative_accuracy","image_to_caption_entity_recall","caption_to_image_entity_recall","joint_entity_recall")
    summary={mode:{s:{k:float(np.mean([r["evaluations"][s][k] for r in rows if r["mode"]==mode])) for k in scalar}
        for s in SCENARIOS} for mode in ("call_put","put_linear_mapped","ordinary","overwrite")}
    return {"schema":"hcsn.round2-natural-caption-rejection.v1","source_sha256":file_sha(__file__),
        "feature_sha256":file_sha(path),"protocol_sha256":file_sha(protocol),
        "rejection":rejection,"rows":rows,"summary":summary,"mapped_state_errors":mapped_errors,
        "timings":timings,"process_peak_rss_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        "caveats":["synthetic temporal arrangement of genuine COCO images and natural/hard-negative captions",
            "custom split; not full official SugarCrepe benchmark","rows can share a source image across caption types",
            "training teaches last-observed memory; not inference of unavailable content",
            "blank hold is the shared mask operation","eight trainable parameters per learned gate; overwrite has zero",
            "frozen CLIP limits semantic distinctions; no mechanism superiority assumed",
            "rejection taxonomy repeated from round1 but all calibration/test source rows are new",
            "no real audio/video, GPU, power, external attestation or scale acceptance"],
        "production_activation":False,"p3_closed":False,"p4_closed":False}


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--features",type=Path,required=True)
    p.add_argument("--prior-features",type=Path,required=True)
    p.add_argument("--protocol",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():p.error("refusing to replace evidence")
    result=study(args.features,args.prior_features,args.protocol)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+"\n")
    print(json.dumps({"rejection":{k:{q:v[q] for q in ("test_id_acceptance","test_unknown_false_acceptance","id_vs_unknown_auroc")}
        for k,v in result["rejection"]["methods"].items()},"summary":result["summary"]},indent=2),flush=True)
