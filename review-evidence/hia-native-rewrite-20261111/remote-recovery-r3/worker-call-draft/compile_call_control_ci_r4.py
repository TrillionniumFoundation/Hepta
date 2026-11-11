"""Fresh exact-source generation/B3 gate for the complete call control draft.

This gate alone does not test peer semantics or qualify a whole Worker.
Usage: script WORK_DIRECTORY GIT_REPOSITORY NEW_OUTPUT_DIRECTORY.
"""
from __future__ import annotations
import ast
from hashlib import sha1,sha256
import json,os,stat,subprocess,sys,time,traceback
from pathlib import Path
WORK=Path(sys.argv[1]).resolve()
REPO=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-service-call-control-next'
REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "service_call_flow.py",
    "bytes": 22385,
    "sha256": "145095e106d630e38258d637e62c60f9856d47f47f928ed2f8a7f6e8859702ea",
    "gitsha": "7f7366044e3feb6df78ced24ed814b9a7be3461a"
  },
  {
    "path": "generate_hia_service_call.py",
    "bytes": 4106,
    "sha256": "f1f2aba87140d585ab20752b460132cf83adae466acecca89da6e3e6492a6f7b",
    "gitsha": "592f43d64bcddc91ec5be9b13178a98518b3b164"
  },
  {
    "path": "service_call_unwind.py",
    "bytes": 3256,
    "sha256": "45a4594fa537b4be7bec1e6417d671d7170cb8bf56b787f1ca070a3971e37f5e",
    "gitsha": "9694c865285b6636cb4d52abbf67c25a12bd0c0a"
  }
]
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def info(path):
    path=Path(path).resolve();raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
OUT.mkdir(parents=True,exist_ok=False)
ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir()
(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
summary=dict(status='INCOMPLETE',scope='CALL_CONTROL_GENERATION_AND_BOUNDED_COMPILE_ONLY',
             native_control_entries=0,actual_namespace_effects=0,whole_worker_closed=False,
             compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20))
paths=[Path(__file__).resolve(),COMPILER,REFERENCE/'tools/qualify_hia_selfhost.py',
       REFERENCE/'tools/generate_hia_selfhost.py',REFERENCE/'tools/hia_agent_edit_source_views.py',
       REFERENCE/'hepta/hia_agent_assembly.py',REFERENCE/'hepta/hia_program.py']
before=[]
started=time.monotonic_ns()
source=None
source_bytes=None
try:
    assert (COMPILER.stat().st_size,digest(COMPILER.read_bytes()))==(668608,
        '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        target=ROOT/'tools'/row['path'];ast.parse(raw,filename=str(target));target.write_bytes(raw)
        assert target.read_bytes()==raw;paths.append(target)
    prior=WORK/'native-agent-service-call-next/tools/service_journal_bridge.py'
    bridge_raw=prior.read_bytes()
    assert digest(bridge_raw)=='7097c244df5c8225d5a8c984a47bc3df5822f3c7e97f9968a6802cbff9e059bf'
    target=ROOT/'tools/service_journal_bridge.py';target.write_bytes(bridge_raw)
    paths.extend([prior,target])
    before=[info(p) for p in paths]
    save(OUT/'source-before.json',before)
    for index,row in enumerate(before):
        original=Path(row['path']);frozen=OUT/'source'/str(index)/original.name
        frozen.parent.mkdir(parents=True,exist_ok=True)
        frozen.write_bytes(original.read_bytes());frozen.chmod(row['mode'])
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    from generate_hia_service_call import document
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    value=document()
    fs=value['functions']
    counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16)))
    source_bytes=render_assembly(value).encode()
    assemble_program(source_bytes)
    source=ROOT/'examples/hia_bootstrap/agent_service_call.hiaasm'
    source.write_bytes(source_bytes)
    image,receipt=compile_stage(OUT,'service-call-control',COMPILER,source_bytes)
    image=Path(image).resolve()
    receipt_path=OUT/'service-call-control.receipt.json'
    actual=json.loads(receipt_path.read_bytes())
    image_bytes=image.read_bytes()
    assert actual['input_sha256']==digest(source_bytes)
    assert actual['produced_sha256']==digest(image_bytes)
    assert actual['image_sha256']==digest(COMPILER.read_bytes())
    manifest=dict(schema='hepta.hia.agent-service-call-control-development.v1',
        scope=summary['scope'],source_path=str(source),source_bytes=len(source_bytes),
        source_sha256=digest(source_bytes),image_path=str(image),image_bytes=len(image_bytes),
        image_sha256=digest(image_bytes),compiler_path=str(COMPILER),
        compiler_sha256=digest(COMPILER.read_bytes()),receipt_path=str(receipt_path))
    save(OUT/'call-control.manifest.json',manifest)
    summary.update(status='PASS',counts=counts,manifest=manifest)
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc))
    traceback.print_exc()
finally:
    after=[info(p) for p in paths if p.exists()]
    unchanged=bool(before) and after==before
    generated_unchanged=source is None or source.read_bytes()==source_bytes
    if not unchanged or not generated_unchanged:summary['status']='FAIL'
    summary.update(source_unchanged=unchanged,generated_source_unchanged=generated_unchanged,
                   elapsed_ns=time.monotonic_ns()-started)
    save(OUT/'source-after.json',after);save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if summary['status']!='PASS':raise SystemExit(1)
