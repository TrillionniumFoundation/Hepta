"""Compile new candidate budget owners with unchanged native B3 limits.
Restore a portable owner map from frozen originals; no original is modified.
"""
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace"
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=WORK/"native-edit-candidate-snapshot-r2-next"
DEST=ROOT/"development/compile-r1"
FROZEN=WORK/"native-edit-candidate-next/development/build-r1"
COMPILER=FROZEN/"source/1/B3.image.bin"
PINS={}
def pin(path):
    path=Path(path); raw=path.read_bytes()
    if path in PINS: assert PINS[path]==raw
    PINS[path]=raw
    return raw
def save(name, obj):
    (DEST/name).write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def main():
    assert not DEST.exists()
    DEST.mkdir()
    sys.path.insert(0,str(REF))
    from tools.qualify_hia_selfhost import compile_stage
    assert sha256(pin(COMPILER)).hexdigest()=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    source=json.loads(pin(ROOT/"development/source-r1.json"))
    compiled={}
    for role in ["59","60"]:
        row=source["components"][role]
        raw=pin(row["source_path"])
        assert sha256(raw).hexdigest()==row["source_sha256"]
        sub=DEST/("role-"+role);sub.mkdir()
        image,receipt=compile_stage(sub,"candidate-snapshot",COMPILER,raw)
        compiled[role]={**row,"image_path":str(image),"image_bytes":image.stat().st_size,
                       "image_sha256":sha256(pin(image)).hexdigest(),"receipt_path":str(sub/"candidate-snapshot.receipt.json"),
                       "compiler_sha256":sha256(pin(COMPILER)).hexdigest()}
        save("compile-progress.json",dict(status="IN_PROGRESS",components=compiled))
    original=json.loads(pin(FROZEN/"bundle.json"))
    index={}
    for p in sorted((FROZEN/"source").rglob("*")):
        if p.is_file():
            raw=pin(p)
            key=(p.name,len(raw),sha256(raw).hexdigest())
            index.setdefault(key,[]).append(str(p))
    owners={}
    for role,row in original["components"].items():
        out=dict(row)
        for k in ["source","image"]:
            key=(Path(row[k+"_path"]).name,row[k+"_bytes"],row[k+"_sha256"])
            choices=index.get(key,[])
            if not choices:
                choices=[q for (n,sz,dig),paths in index.items() if sz==row[k+"_bytes"] and dig==row[k+"_sha256"] for q in paths]
            assert choices, (role,k,key)
            chosen=sorted(choices)[0]
            out["original_"+k+"_path"]=row[k+"_path"]
            out[k+"_path"]=chosen
            out[k+"_frozen_copies"]=choices
        owners[role]=out
    save("portable-original-bundle.json",dict(schema="hia-portable-exact-owner-map-v1",
        original_bundle=str(FROZEN/"bundle.json"),components=owners,all_126_owner_sources_images_exact=True))
    owners.update(compiled)
    save("portable-new-components.json",dict(schema="hia-candidate-snapshot-components-v1",
        components=owners,substituted_roles=[59,60],unchanged_roles=sorted(int(k) for k in owners if k not in compiled),
        scope="ACTUAL_B3_COMPILE_ONLY_NOT_LINKED_OR_SEMANTICALLY_QUALIFIED",whole_stack_closed=False))
    inspected=[]
    for filename in ["hia_edit_query.py","hia_program.py","hia_core_patch_native.py"]:
        path=REF/"hepta"/filename
        raw=pin(path);text=raw.decode()
        tree=ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in [
                "prepare_edit","apply_edit","_bounded_detached_snapshot","_decode_response","_response_object"]:
                inspected.append("\nSOURCE "+str(path)+"\n"+ast.get_source_segment(text,node)+"\n")
    (DEST/"reference-inspection.txt").write_text("".join(inspected))
    save("frozen-source-inventory.json",[{ "path":str(p), "bytes":len(raw),"sha256":sha256(raw).hexdigest()} for p,raw in PINS.items() if str(p).startswith(str(FROZEN/"source"))])
    save("summary.json",dict(status="PASS",components=compiled,portable_owners=len(owners),
        all_126_owner_source_images_recovered=True,whole_stack_closed=False))
    print(json.dumps(dict(status="PASS",summary=str(DEST/"summary.json"),
        components={k:{f:v[f] for f in ["source_bytes","source_sha256","image_bytes","image_sha256"]} for k,v in compiled.items()},
        source_filenames=sorted(set(p.name for p in PINS if str(p).startswith(str(FROZEN/"source")))))),flush=True)
started=time.monotonic()
try:
    main()
except BaseException:
    if DEST.is_dir():
        (DEST/"failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
    raise
finally:
    if DEST.is_dir():
        equal=all(p.read_bytes()==raw for p,raw in PINS.items())
        save("pins.json",dict(elapsed_seconds=time.monotonic()-started,source_before_after_equal=equal,
            pins={str(p):dict(bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in PINS.items()}))
        assert equal
