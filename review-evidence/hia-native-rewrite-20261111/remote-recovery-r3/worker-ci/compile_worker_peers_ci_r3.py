"""Fresh bounded B3 compilations for worker peers and the new journal bridge.

This script never reuses a historical image as a fresh result and never supplies
cold qualification. The original compile_stage limits remain unchanged.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util, json, os, stat, sys, time, traceback
from pathlib import Path
WORK=Path(sys.argv[1]).resolve()
MODE=sys.argv[2]
REFERENCE=WORK/"Hepta-agent-edit-native"
COMPILER=WORK/"dependencies/f50-B3.image.bin"
sys.path.insert(0,str(REFERENCE))
from tools.qualify_hia_selfhost import compile_stage
from hepta.hia_agent_assembly import assemble_program,render_assembly
def digest(raw): return sha256(raw).hexdigest()
def info(path):
    path=Path(path).resolve(); raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
assert (COMPILER.stat().st_size,digest(COMPILER.read_bytes()))==(668608,
    "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8")
if MODE=="graph":
    ROOT=WORK/"native-agent-edit-render-next"
    OUT=ROOT/"development/compile-r3"
    scope="SOURCE_BOUND_GRAPH_WIRE_DEVELOPMENT_NOT_PUBLIC_ADMISSION_OR_COLD"
    roles=[("scan",ROOT/"examples/hia_bootstrap/graph_json_wire_scan.hiaasm"),
           ("emit",ROOT/"examples/hia_bootstrap/graph_json_wire_emit.hiaasm")]
    expected={"scan":"c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3",
              "emit":"9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2"}
    counts=None
elif MODE=="bridge":
    ROOT=WORK/"native-agent-service-call-next"
    OUT=ROOT/"development/compile-ci-r1"
    scope="NEW_CI_JOURNAL_TRANSPORT_DEVELOPMENT_NOT_NAMESPACE_OR_COMPLETE_WORKER_OR_COLD"
    sys.path.insert(0,str(ROOT/"tools"))
    from generate_hia_service_journal_bridge import document
    authoring=[ROOT/"tools/service_journal_bridge.py",ROOT/"tools/generate_hia_service_journal_bridge.py"]
    assert digest(authoring[0].read_bytes())=="7097c244df5c8225d5a8c984a47bc3df5822f3c7e97f9968a6802cbff9e059bf"
    assert digest(authoring[1].read_bytes())=="be8aeb6d62cef861e04b5690a5e2eea59815a81772e0a1b063c1532cee5b4189"
    source=ROOT/"examples/hia_bootstrap/agent_service_journal_bridge.hiaasm"
    roles=[("bridge",source),("journal",REFERENCE/"examples/hia_bootstrap/agent_journal.hiaasm")]
    expected={}
    counts=None
else: raise AssertionError(("unknown compile mode",MODE))
OUT.mkdir(parents=True,exist_ok=False)
paths=[Path(__file__).resolve(),COMPILER,REFERENCE/"tools/qualify_hia_selfhost.py",
       REFERENCE/"tools/generate_hia_selfhost.py",REFERENCE/"tools/hia_agent_edit_source_views.py",
       REFERENCE/"hepta/hia_agent_assembly.py",REFERENCE/"hepta/hia_program.py",
       REFERENCE/"hepta/hia_json_preflight_native.py",REFERENCE/"hepta/hia_agent_journal_native.py",
       REFERENCE/"hepta/hia_json_decode_native.py",REFERENCE/"hepta/hia_agent_data_json_native.py"]
paths += sorted((ROOT/"tools").glob("*.py"))
paths += [p for _,p in roles if p.exists()]
before=[info(p) for p in paths]
save(OUT/"source-before.json",before)
for i,row in enumerate(before):
    p=Path(row["path"]); dest=OUT/"source"/str(i)/p.name
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(p.read_bytes()); dest.chmod(row["mode"])
summary=dict(status="INCOMPLETE",scope=scope,environment="github-actions",
             historical_run_inherited=False,compile_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20))
started=time.monotonic_ns()
frozen={}
try:
    if MODE=="bridge":
        value=document()
        fs=value["functions"]
        counts=dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),
                    instructions=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
                    max_function_blocks=max(len(f["blocks"]) for f in fs),
                    max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]))
        assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16)))
        raw=render_assembly(value).encode()
        assemble_program(raw)
        assert not source.exists(),"Never overwrite an earlier generated revision"
        source.write_bytes(raw)
    rows={}
    for role,p in roles:
        raw=p.read_bytes(); frozen[p]=raw
        if role in expected: assert digest(raw)==expected[role]
        assemble_program(raw)
        label="graph-json-wire-"+role if MODE=="graph" else "service-journal-"+role
        image,receipt=compile_stage(OUT,label,COMPILER,raw)
        image=Path(image).resolve()
        receipt_path=OUT/(label+".receipt.json")
        actual=json.loads(receipt_path.read_bytes())
        image_raw=image.read_bytes()
        assert actual["input_sha256"]==digest(raw)
        assert actual["produced_sha256"]==digest(image_raw)
        assert actual["image_sha256"]==digest(COMPILER.read_bytes())
        schema=("hepta.hia.graph-json-wire-"+role+"-native.v1" if MODE=="graph"
                else "hepta.hia.agent-service-journal-"+role+"-development.v1")
        row=dict(schema=schema,source_path=str(p.resolve()),source_bytes=len(raw),source_sha256=digest(raw),
                 image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
                 compiler_path=str(COMPILER),compiler_sha256=digest(COMPILER.read_bytes()),
                 receipt_path=str(receipt_path.resolve()),scope=scope)
        manifest=OUT/(role+".manifest.json")
        save(manifest,row)
        rows[role]=dict(row,manifest_path=str(manifest))
    assert all(p.read_bytes()==raw for p,raw in frozen.items())
    bundle=dict(status="PASS",schema="hepta.hia.worker-ci-peers.v1",scope=scope,components=rows,
                fresh_ci_compilation=True,historical_run_inherited=False)
    save(OUT/("bundle-relocated-r2.json" if MODE=="graph" else "bundle.json"),bundle)
    summary.update(status="PASS",components=rows,counts=counts)
except BaseException as exc:
    summary.update(status="FAIL",error_class=type(exc).__name__,error=str(exc))
    traceback.print_exc(); raise
finally:
    after=[info(p) for p in paths]
    summary.update(source_unchanged=before==after,generated_source_unchanged=all(p.read_bytes()==raw for p,raw in frozen.items()),
                   elapsed_ns=time.monotonic_ns()-started)
    save(OUT/"source-after.json",after); save(OUT/"summary.json",summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
    assert before==after and summary["generated_source_unchanged"]
