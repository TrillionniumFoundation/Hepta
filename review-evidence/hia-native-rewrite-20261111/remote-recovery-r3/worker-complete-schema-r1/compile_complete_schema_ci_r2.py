"""Generate all complete schema stages and compile every actual peer afresh.

All original authoring/bootstrap limits remain unchanged. Each independent
generation/compile failure is retained; no missing component is substituted.
"""
from __future__ import annotations
import ast,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-schema-complete-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_schema_common.py",
    "bytes": 16735,
    "sha256": "d036356dfea906dc44d604c8bd72da09006cc93d76d4d42dc4881207ad0ac582",
    "gitsha": "73422b7eca27b5cf0f7acb101454689dad832af9"
  },
  {
    "path": "tools/agent_schema_peers.py",
    "bytes": 9888,
    "sha256": "4aca1055b9a5c4fa62c4d3e9c08798f64495297356bbf31dcbd1234953fa39b6",
    "gitsha": "5300104e506656b70c12a314f9778fd9f06a7b4b"
  },
  {
    "path": "tools/agent_schema_numbers.py",
    "bytes": 6564,
    "sha256": "ca648cd1b677df9c2850629ed20e23ee8123edc1d4a546d07505e6556a1ebe47",
    "gitsha": "be0fc39c4d562b7e77ff88ff2758d307d911a9a1"
  },
  {
    "path": "tools/agent_schema_scalars.py",
    "bytes": 7180,
    "sha256": "3c4fe6ac6453680d2df16aa5c3dcc9ae5af0997cfc1e5965574760c93d935c78",
    "gitsha": "c1950ed6045258588a5c395def4dc561153e00ae"
  },
  {
    "path": "tools/agent_schema_logic.py",
    "bytes": 12669,
    "sha256": "f9d35e99678ce9fcd3ac30c0de0598f8d0623494507b5ee89ccf6db407a87574",
    "gitsha": "ef8a1277345c966128324ab8c328673b3d5441f9"
  },
  {
    "path": "tools/agent_schema_containers.py",
    "bytes": 11520,
    "sha256": "22c302ecac3af038c52b6a1ea703fcfbb5bffca9bbe6fdf994ab40f2ff88e7e1",
    "gitsha": "8500786ff97fedd285092c58f441848e395db8a1"
  },
  {
    "path": "tools/agent_schema_errors.py",
    "bytes": 7059,
    "sha256": "e4ae88cd3f1e0325f6a9fbfc76783b20555d6d8d6b070f3156c04a6a94b73c90",
    "gitsha": "4fd90e9794dfb510c983480714e3f938fa263b41"
  },
  {
    "path": "tools/generate_hia_agent_schema.py",
    "bytes": 9013,
    "sha256": "8e8e2c0a127b187ff3cba256f31e7f25d41377c282fa8c5faf1c62ab70388619",
    "gitsha": "186a2230a2b0098c7320d4a29d32498492b43d80"
  },
  {
    "path": "tools/agent_schema_patterns.py",
    "bytes": 4116,
    "sha256": "f8a41b688db6e405fd0ca77ad0406ec561bbb2e3d16fee76a5e1fcadb54244a8",
    "gitsha": "162a0c6971d8eed9569102f878aa13231d9985c0"
  },
  {
    "path": "tools/generate_hia_agent_schema_patterns.py",
    "bytes": 4435,
    "sha256": "22fb5f5e8b190f638fc2be3aa13c2e47cc8024e7dbd2fcebeb50112453ed3eee",
    "gitsha": "eb2921eb86c6e916ea08f68e8f8c4037a07f298c"
  },
  {
    "path": "tools/graph_wire_frozen_original.py",
    "bytes": 13815,
    "sha256": "32ceeceb285f9d3d3250a920c40ebd7bac8e1a44460c5321d714f6f5a0da2b3c",
    "gitsha": "0711ccf18b3838e53b47821c464c3492b802eff6"
  },
  {
    "path": "tools/graph_harness_frozen_original.py",
    "bytes": 9783,
    "sha256": "75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c",
    "gitsha": "eaf060c8c6870cad0a85a23f6b94ffa39308c45c"
  }
]
WIRE_PINS=[
 dict(role='scan',path='graph_json_wire_scan.hiaasm',bytes=147822,sha256='c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3'),
 dict(role='emit',path='graph_json_wire_emit.hiaasm',bytes=173680,sha256='9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2')]
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={};components={};failures=[];attempts=[]
summary=dict(status='INCOMPLETE',scope='COMPLETE_SCHEMA_AND_REAL_WIRE_PATTERN_PEERS_DEVELOPMENT',
    actual_compiles=0,native_entries=0,whole_worker_closed=False,production_activation=False,
    compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20))
start=time.monotonic_ns()
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def rows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode)) for p,raw in pins.items()]
def counts(value):
    fs=value['functions']
    return dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
def compile_one(role,source,value_counts=None):
    raw=read(source)
    image,receipt=compile_stage(OUT,role,COMPILER,raw);image=Path(image).resolve()
    image_bytes=read(image);receipt_path=OUT/(role+'.receipt.json')
    actual=json.loads(read(receipt_path))
    assert actual['input_sha256']==digest(raw)
    assert actual['produced_sha256']==digest(image_bytes)
    assert actual['image_sha256']==digest(read(COMPILER))
    summary['actual_compiles']+=1
    row=dict(role=role,source_path=str(source),source_bytes=len(raw),source_sha256=digest(raw),
        image_path=str(image),image_bytes=len(image_bytes),image_sha256=digest(image_bytes),
        compiler_sha256=digest(read(COMPILER)),receipt_path=str(receipt_path),counts=value_counts)
    components[role]=row
    save(OUT/(role+'.manifest.json'),row)
    return row
try:
    raw=read(COMPILER)
    assert (len(raw),digest(raw))==(668608,'0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        target=ROOT/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
        ast.parse(raw,filename=str(target));target.write_bytes(raw);read(target)
    for path in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
        'tools/qualify_hia_selfhost.py','hepta/hia_program.py','hepta/hia_agent_assembly.py',
        'hepta/hia_agent_contract.py','hepta/hia_agent_store.py','hepta/hia_program_tools.py',
        'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'):
        read(REFERENCE/path)
    read(__file__);save(OUT/'source-before.json',rows())
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    import generate_hia_agent_schema as generator
    import generate_hia_agent_schema_patterns as pattern_generator
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    inventory=pattern_generator.inventory()
    for role,(name,_) in generator.ROLES.items():
        label='schema_'+name
        try:
            expanded=generator.source_program(role)
            (OUT/(label+'.expanded-authoring.py')).write_text(expanded)
            value=generator.document(role);actual_counts=counts(value)
            assert all(a<=b for a,b in zip(actual_counts.values(),(128,1536,8192,256,16))),actual_counts
            raw=render_assembly(value).encode();assemble_program(raw)
            path=ROOT/'examples/hia_bootstrap'/(label+'.hiaasm');path.write_bytes(raw)
            row=compile_one(label,path,actual_counts)
            attempts.append(dict(role=label,status='PASS',manifest=row))
        except BaseException as exc:
            trace=traceback.format_exc();(OUT/(label+'.failure.log')).write_text(trace)
            traceback.print_exc();failure=dict(role=label,status='FAIL',error_class=type(exc).__name__,error=str(exc))
            attempts.append(failure);failures.append(failure)
    try:
        value=pattern_generator.document();raw=render_assembly(value).encode();assemble_program(raw)
        path=ROOT/'examples/hia_bootstrap/agent_schema_patterns.hiaasm';path.write_bytes(raw)
        compile_one('patterns',path,counts(value))
    except BaseException as exc:
        trace=traceback.format_exc();(OUT/'patterns.failure.log').write_text(trace);traceback.print_exc()
        failures.append(dict(role='patterns',error_class=type(exc).__name__,error=str(exc)))
    for row in WIRE_PINS:
        try:
            path=WORK/'native-agent-edit-render-next/examples/hia_bootstrap'/row['path']
            raw=read(path);assert (len(raw),digest(raw))==(row['bytes'],row['sha256'])
            compile_one(row['role'],path)
        except BaseException as exc:
            trace=traceback.format_exc();(OUT/(row['role']+'.failure.log')).write_text(trace);traceback.print_exc()
            failures.append(dict(role=row['role'],error_class=type(exc).__name__,error=str(exc)))
    if not failures:
        assert len(components)==7
        bundle=dict(schema='hia-agent-complete-schema-development-bundle-v1',status='PASS',
            components=components,inventory=inventory,compiler_sha256=digest(read(COMPILER)),
            role_order=['schema_scalar','schema_logic','schema_containers','schema_errors'],
            whole_worker_closed=False,scope=summary['scope'])
        save(OUT/'bundle.json',bundle);summary.update(status='PASS',bundle=bundle)
except BaseException as exc:
    failures.append(dict(role='generation-driver',error_class=type(exc).__name__,error=str(exc)));traceback.print_exc()
finally:
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if failures or not unchanged:summary['status']='FAIL'
    for i,(path,raw) in enumerate(pins.items()):
        target=OUT/'frozen-inputs'/str(i)/path.name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        target.chmod(stat.S_IMODE(path.stat().st_mode))
    save(OUT/'source-after.json',rows())
    summary.update(source_unchanged=unchanged,attempts=attempts,failures=failures,
                   elapsed_ns=time.monotonic_ns()-start)
    save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if summary['status']!='PASS':raise SystemExit(1)
