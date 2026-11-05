"""Read-only provenance and arithmetic audit of executed round2 P3/P4 evidence.

Exit zero means these files/receipts agree. It is NOT scientific acceptance,
external attestation, a quality threshold, or a production eligibility gate.
Run this audit before reusing the frozen bundle, including its CIFAR rows.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import math

import numpy as np


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(root, data_source):
    here=root/"research"/"hcsn"
    feature=here/"fixtures"/"frozen_round2_20261105.npz"
    prior=here/"fixtures"/"frozen_clip_cifar10_20261105.npz"
    receipt=json.loads(feature.with_suffix(".json").read_text())
    old=json.loads(prior.with_suffix(".json").read_text())
    protocol=here/"gates"/"2026-11-05-round2-p3-p4-protocol.json"
    study_path=here/"gates"/"2026-11-05-round2-p3-natural-rejection-raw.json"
    online_path=here/"gates"/"2026-11-05-round2-p4-online-raw.json"
    study=json.loads(study_path.read_text());online=json.loads(online_path.read_text())
    checks=[]
    def require(value,name):
        if not value:raise AssertionError(name)
        checks.append(name)
    require(sha(feature)==receipt["features_sha256"]==study["feature_sha256"],"new feature bytes match receipt and study")
    require(sha(prior)==old["features_sha256"],"prior training feature bytes match receipt")
    require(receipt["encoder_frozen"] is True,"frozen encoder declared")
    require(sha(protocol)==receipt["protocol_sha256"]==study["protocol_sha256"],"protocol unchanged since acquisition")
    require(sha(here/"p3_round2_features.py")==receipt["source_sha256"],"acquisition source is exact executed version")
    require(sha(here/"p3_round2_study.py")==study["source_sha256"],"study source is exact executed version")
    with np.load(feature,allow_pickle=False) as data:
        arrays={k:data[k].copy() for k in data.files}
    require(all(np.isfinite(v).all() for v in arrays.values()),"all new feature arrays finite")
    for split in ("calibration","test"):
        rows=receipt["cifar_selections"][split]
        require(arrays["cifar_"+split+"_labels"].tolist()==[r["class"] for r in rows],split+" CIFAR label array matches receipt")
        require(arrays["cifar_"+split+"_indices"].tolist()==[r["index"] for r in rows],split+" CIFAR index array matches receipt")
        require(arrays["cifar_"+split].shape==(len(rows),512),split+" CIFAR feature row count and dimension match")
    require(np.array_equal(np.bincount(arrays["cifar_calibration_labels"],minlength=10),[16]*8+[0,0]),"calibration contains 128 known images and no unknown labels")
    require(np.array_equal(np.bincount(arrays["cifar_test_labels"],minlength=10),[32]*10),"test contains 256 known and 64 unknown source images")
    old_ids={(r["official_split"],r["index"]) for split in old["selections"].values() for r in split}
    old_pixels={r["pixels_sha256"] for split in old["selections"].values() for r in split}
    new_ids={(r["official_split"],r["index"]) for split in receipt["cifar_selections"].values() for r in split}
    new_pixels={r["rgb_sha256"] for split in receipt["cifar_selections"].values() for r in split}
    require(not old_ids&new_ids and not old_pixels&new_pixels,"new CIFAR source IDs and pixels disjoint from all round1 rows")
    require(receipt["cifar_provenance"]["revision"]==old["dataset_provenance"]["revision"],"CIFAR row namespaces use same immutable mirror revision")
    filenames=[r["filename"] for r in receipt["coco_images"]]
    splitsets={};pixelsets={};source_files={}
    kinds=("add_att","add_obj","replace_att","replace_obj","replace_rel","swap_att","swap_obj")
    for kind in kinds:
        path=data_source/"data"/(kind+".json")
        require(sha(path)==receipt["dataset_files"][kind]["sha256"],kind+" annotation source digest matches")
        source_files[kind]=json.loads(path.read_text())
    for i,row in enumerate(receipt["sugar_rows"]):
        original=source_files[row["kind"]][row["key"]]
        require(all(row[k]==original[k] for k in ("filename","caption","negative_caption")),f"caption row {i} is original pinned source")
        if filenames[arrays["sugar_image_index"][i]]!=row["filename"] or arrays["sugar_kind"][i]!=kinds.index(row["kind"]):
            raise AssertionError("caption/image/type row misalignment")
        splitsets.setdefault(row["split"],set()).add(row["filename"])
    names=list(splitsets)
    for s in names:
        pixelsets[s]={r["rgb_sha256"] for r in receipt["coco_images"] if r["filename"] in splitsets[s]}
    require(all(not splitsets[s]&splitsets[t] and not pixelsets[s]&pixelsets[t] for s in names for t in names if s!=t),"all caption splits disjoint by source image and decoded pixels")
    for row in study["rows"]:
        for scenario,result in row["evaluations"].items():
            pos=np.array(result["raw_positive_score"]);neg=np.array(result["raw_negative_score"])
            actual=(pos>neg).astype(float)+.5*(pos==neg)
            require(np.array_equal(actual,result["raw_hard_negative_correct"]),f"{row['seed']} {row['mode']} {scenario} raw caption decisions consistent")
            require(abs(actual.mean()-result["hard_negative_accuracy"])<1e-14,f"{row['seed']} {row['mode']} {scenario} caption accuracy correct")
            i=np.array(result["raw_image_retrieval_correct"],dtype=bool);t=np.array(result["raw_text_retrieval_correct"],dtype=bool)
            require(abs((i&t).mean()-result["joint_entity_recall"])<1e-14,f"{row['seed']} {row['mode']} {scenario} joint retrieval denominator correct")
    for method,row in study["rejection"]["methods"].items():
        c=np.array(row["calibration_scores"]);i=np.array(row["test_id_scores"]);u=np.array(row["test_unknown_scores"])
        threshold=np.quantile(c,.05,method="lower")
        require(threshold==row["id_only_calibration_threshold"],method+" threshold uses calibration scores only")
        require(int((i>=threshold).sum())==row["test_id_accept_count"] and int((u>=threshold).sum())==row["test_unknown_accept_count"],method+" reported accepted counts agree")
        diag=row["fixed_test_id_coverage_diagnostic"]
        require(diag["id_expected_accept_count"]==243 and diag["id_acceptance"]==243/256 and diag["deployable_threshold"] is False,method+" fixed-coverage result explicitly diagnostic")
    by={r["case"]:r for r in online["cases"]}
    for case,row in by.items():
        require(row["source_sha256"]==sha(here/"p4_round2_online.py") and row["study_sha256"]==sha(study_path),case+" executed source and trained study match")
        require(row["requests"]==len(row["raw_request_timings"])==len(row["caption_scores"])==64,case+" request denominator correct")
        require(abs(sum(r["wall_ns"] for r in row["raw_request_timings"])/1e9-row["online_total_wall_seconds"])<1e-12,case+" total wall time matches raw timings")
        require(row["energy_joules"] is None and row["cuda_available"] is False,case+" unavailable energy/GPU measurements not imputed")
    a,b=by["call_put_uncached"],by["call_put_cached"]
    require(a["full_state_and_score_trace_sha256"]==b["full_state_and_score_trace_sha256"],"uncached/cached complete model traces byte-identical")
    require(all(r["encoder_output_digests"]==a["encoder_output_digests"] for r in by.values()),"all online encoded inputs identical across cases")
    require(a["counts"]["image_encoder_calls"]==64 and b["counts"]["image_encoder_calls"]==8 and a["counts"]["text_encoder_calls"]==128 and b["counts"]["text_encoder_calls"]==16,"actual online encoder calls demonstrate exact reuse")
    files=[feature,feature.with_suffix(".json"),prior,protocol,study_path,online_path,
           here/"p3_round2_features.py",here/"p3_round2_study.py",here/"p4_round2_online.py"]
    return {"schema":"hcsn.round2-readonly-multimodal-audit.v1","audit_source_sha256":sha(Path(__file__)),
            "checks_passed":len(checks),"checks":checks,
            "files":{str(p.relative_to(root)):sha(p) for p in files},
            "caption_source_image_counts":{k:len(v) for k,v in splitsets.items()},
            "hard_negative_readout_uses_image_memory_and_caption_candidates_only":True,
            "misalignment_metric_uses_each_modalities_last_observed_entity":True,
            "scientific_acceptance_asserted":False,"production_activation":False}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument("--data-source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error("refusing to replace audit")
    result=audit(a.root.resolve(),a.data_source.resolve())
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"checks_passed":result["checks_passed"],"scientific_acceptance_asserted":False}))
