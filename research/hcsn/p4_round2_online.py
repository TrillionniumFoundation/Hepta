"""Actual CPU image/text encoder -> memory -> caption decision measurements.

Each case runs in a fresh process. Exact encoded-input caching is a standard
systems control, not an HCSN-specific gain. A fixed 64-request stream cycles
eight genuine COCO examples; it is an explicit high-repetition synthetic load.
Cold setup, warmup, raw-input IO, both encoders, control and outputs are exposed.
No latency-to-joules conversion, GPU claim, or distributed extrapolation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time

import numpy as np
from PIL import Image
import torch
from torch.nn import functional as F

try:
    from .p3_round2_features import CLIP_COMMIT, MODEL_SHA256, clean_head, sha256
    from .p3_round2_study import EmbeddingMemory, mapped_put_linear, load_bundle
except ImportError:
    from p3_round2_features import CLIP_COMMIT, MODEL_SHA256, clean_head, sha256
    from p3_round2_study import EmbeddingMemory, mapped_put_linear, load_bundle

CASES=("call_put_uncached","call_put_cached","put_linear_cached","overwrite_cached")


def step(memory, image, text, state=None):
    if state is None:
        return image, text
    dt=image.new_ones(image.shape[0])
    return tuple(h+memory.gate(x,h,dt)*(x-h) for x,h in zip((image,text),state))


def selected_requests(receipt):
    by_name={}
    for row in receipt["sugar_rows"]:
        if row["split"]=="test":
            by_name.setdefault(row["filename"],row)
    names=sorted(by_name)[:8]
    if len(names)!=8:
        raise ValueError("eight distinct heldout images required")
    return [by_name[names[i%8]] for i in range(64)]


def worker(args):
    if args.case not in CASES:
        raise ValueError("unknown online case")
    if args.output.exists():
        raise FileExistsError("refusing to replace online evidence")
    torch.set_num_threads(1)
    _,receipt=load_bundle(args.features)
    if sha256(args.study)!=args.study_sha256:
        raise ValueError("study source checkpoint changed")
    clean_head(args.clip_source,CLIP_COMMIT)
    weight=args.cache/"weights"/"ViT-B-32.pt"
    start=time.perf_counter();cpu_start=time.process_time()
    if sha256(weight)!=MODEL_SHA256:
        raise ValueError("wrong encoder weights")
    sys.path.insert(0,str(args.clip_source.resolve()))
    clip=importlib.import_module("clip")
    encoder,preprocess=clip.load(str(weight),device="cpu",jit=False)
    encoder.eval().requires_grad_(False)
    study=json.loads(args.study.read_text())
    canonical=next(r for r in study["rows"] if r["seed"]==61 and r["mode"]=="call_put")
    memory=EmbeddingMemory("call_put")
    memory.load_state_dict({k:torch.tensor(v,dtype=torch.float32) for k,v in canonical["state_dict"].items()})
    if args.case=="put_linear_cached":memory=mapped_put_linear(memory)
    elif args.case=="overwrite_cached":memory=EmbeddingMemory("overwrite")
    memory.eval()
    requests=selected_requests(receipt)
    image_receipts={r["filename"]:r for r in receipt["coco_images"]}
    for filename in {r["filename"] for r in requests}:
        if sha256(args.cache/"coco"/filename)!=image_receipts[filename]["file_sha256"]:
            raise ValueError("online image differs from frozen source receipt")
    setup_seconds=time.perf_counter()-start
    warm_start=time.perf_counter()
    with torch.inference_mode():
        with Image.open(args.cache/"coco"/requests[0]["filename"]) as im:
            encoder.encode_image(preprocess(im.convert("RGB")).unsqueeze(0))
        encoder.encode_text(clip.tokenize([requests[0]["caption"]]))
        encoder.encode_text(clip.tokenize([requests[0]["negative_caption"]]))
    warmup_seconds=time.perf_counter()-warm_start
    image_cache={};text_cache={};state=None
    cached=args.case!="call_put_uncached"
    counts={"image_encoder_calls":0,"text_encoder_calls":0,"image_cache_hits":0,"text_cache_hits":0,
            "raw_image_bytes_read":0}
    timings=[];scores=[];encoder_digests=[];trace=hashlib.sha256()
    namespace=(CLIP_COMMIT+MODEL_SHA256+"official_clip_preprocess_and_tokenize").encode()
    with torch.inference_mode():
        for request in requests:
            w,c=time.perf_counter_ns(),time.process_time_ns()
            raw=(args.cache/"coco"/request["filename"]).read_bytes()
            counts["raw_image_bytes_read"]+=len(raw)
            image_key=hashlib.sha256(namespace+b"image\0"+raw).hexdigest()
            if cached and image_key in image_cache:
                image=image_cache[image_key];counts["image_cache_hits"]+=1
            else:
                with Image.open(io.BytesIO(raw)) as im:
                    pixels=preprocess(im.convert("RGB")).unsqueeze(0)
                image=F.normalize(encoder.encode_image(pixels).float(),dim=-1)
                counts["image_encoder_calls"]+=1
                if cached:image_cache[image_key]=image
            text_vectors=[]
            for name in ("caption","negative_caption"):
                value=request[name]
                key=hashlib.sha256(namespace+b"text\0"+value.encode("utf-8")).hexdigest()
                if cached and key in text_cache:
                    vector=text_cache[key];counts["text_cache_hits"]+=1
                else:
                    vector=F.normalize(encoder.encode_text(clip.tokenize([value],truncate=False)).float(),dim=-1)
                    counts["text_encoder_calls"]+=1
                    if cached:text_cache[key]=vector
                text_vectors.append(vector)
            state=step(memory,image,text_vectors[0],state)
            normalized=F.normalize(state[0],dim=-1)
            score=torch.cat([(normalized*v).sum(-1) for v in text_vectors]).numpy()
            state_bytes=b"".join(v.numpy().tobytes() for v in state)
            # Hashing/serialization are part of the measured complete request.
            encoder_digests.append(hashlib.sha256(image.numpy().tobytes()+b"".join(v.numpy().tobytes() for v in text_vectors)).hexdigest())
            trace.update(state_bytes);trace.update(score.tobytes())
            scores.append(score.tolist())
            timings.append({"wall_ns":time.perf_counter_ns()-w,"cpu_ns":time.process_time_ns()-c})
    wall=np.array([t["wall_ns"] for t in timings],dtype=np.float64)
    cpu=np.array([t["cpu_ns"] for t in timings],dtype=np.float64)
    energy_paths=list(Path("/sys/class/powercap").glob("**/energy_uj")) if Path("/sys/class/powercap").exists() else []
    out={"schema":"hcsn.round2-complete-online-cpu-case.v1","case":args.case,
         "source_sha256":sha256(Path(__file__)),"feature_sha256":sha256(args.features),"study_sha256":args.study_sha256,
         "model_seed":61,"requests":64,"unique_source_images":8,"cached":cached,"counts":counts,
         "raw_request_timings":timings,"caption_scores":scores,"encoder_output_digests":encoder_digests,
         "full_state_and_score_trace_sha256":trace.hexdigest(),
         "final_memory":[v.numpy().tolist() for v in state],
         "hard_negative_accuracy":float(np.mean([p>n for p,n in scores])),
         "online_total_wall_seconds":float(wall.sum()/1e9),"online_total_cpu_seconds":float(cpu.sum()/1e9),
         "p50_request_ms":float(np.quantile(wall,.5)/1e6),"p95_request_ms":float(np.quantile(wall,.95)/1e6),
         "p99_request_ms":float(np.quantile(wall,.99)/1e6),"requests_per_second":float(len(wall)/(wall.sum()/1e9)),
         "setup_seconds":setup_seconds,"warmup_seconds":warmup_seconds,
         "worker_setup_through_measurement_wall_seconds":time.perf_counter()-start,
         "worker_setup_through_measurement_cpu_seconds":time.process_time()-cpu_start,
         "isolated_process_peak_rss_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
         "retained_embedding_cache_bytes":sum(v.numel()*v.element_size() for v in list(image_cache.values())+list(text_cache.values())),
         "energy_joules":None,"energy_counter_paths_found":[str(p) for p in energy_paths],
         "cuda_available":torch.cuda.is_available(),"runtime_network_calls_in_measured_code":0,
         "distributed_communication_measured":False,"device":"cpu","torch_version":str(torch.__version__),
         "platform":platform.platform(),"threads":1,
         "scope":"local raw-file read, hashes, image decoding/preprocessing, both actual CLIP encoders, memory controller, caption scores and trace serialization"}
    args.output.write_text(json.dumps(out,indent=2,sort_keys=True,allow_nan=False)+"\n")
    print(json.dumps({k:out[k] for k in ("case","hard_negative_accuracy","online_total_wall_seconds","p99_request_ms","isolated_process_peak_rss_bytes")}),flush=True)


def orchestrate(args):
    if args.output.exists():raise FileExistsError("refusing to replace aggregate evidence")
    rows=[]
    study_sha=sha256(args.study)
    for case in CASES:
        target=args.output.with_name(args.output.stem+"-"+case+".json")
        command=[sys.executable,str(Path(__file__).resolve()),"--case",case,"--features",str(args.features.resolve()),
                 "--study",str(args.study.resolve()),"--study-sha256",study_sha,"--cache",str(args.cache.resolve()),
                 "--clip-source",str(args.clip_source.resolve()),"--output",str(target.resolve())]
        start=time.perf_counter()
        subprocess.run(command,check=True)
        row=json.loads(target.read_text())
        row["whole_child_process_wall_seconds"]=time.perf_counter()-start
        rows.append(row)
    by={r["case"]:r for r in rows}
    uncached,cached,mapped=(by[x] for x in CASES[:3])
    trace_equal=uncached["full_state_and_score_trace_sha256"]==cached["full_state_and_score_trace_sha256"]
    encoder_equal=all(r["encoder_output_digests"]==uncached["encoder_output_digests"] for r in rows)
    if not trace_equal or not encoder_equal:
        raise ArithmeticError("exact-input cache changed encoded/model outputs")
    result={"schema":"hcsn.round2-complete-online-cpu.v1","cases":rows,
            "same_call_put_full_trace_with_and_without_cache":trace_equal,
            "all_encoder_outputs_equal_across_cases":encoder_equal,
            "mapped_caption_score_max_abs_error":float(np.max(np.abs(np.array(cached["caption_scores"])-np.array(mapped["caption_scores"])))),
            "mapped_final_memory_max_abs_error":float(np.max(np.abs(np.array(cached["final_memory"])-np.array(mapped["final_memory"])))),
            "call_put_cache_online_wall_speedup":uncached["online_total_wall_seconds"]/cached["online_total_wall_seconds"],
            "call_put_cache_cpu_ratio":cached["online_total_cpu_seconds"]/uncached["online_total_cpu_seconds"],
            "caveats":["eight-image cyclic synthetic load, not natural video","exact cache savings are ordinary input reuse, not free-boundary skipping",
                       "64 request samples per case; p99 is descriptive, not production qualification",
                       "filesystem cache and shared-host load uncontrolled; cases are separate processes in fixed order",
                       "encoder setup and warmup separately reported and included in whole child process time",
                       "no actual joules, accelerator, distributed traffic or production activation"],
            "production_activation":False,"p4_closed":False}
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="cases"},indent=2),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--case",choices=CASES)
    p.add_argument("--features",type=Path,required=True)
    p.add_argument("--study",type=Path,required=True)
    p.add_argument("--study-sha256")
    p.add_argument("--clip-source",type=Path,required=True)
    p.add_argument("--cache",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if a.case:worker(a)
    else:orchestrate(a)
