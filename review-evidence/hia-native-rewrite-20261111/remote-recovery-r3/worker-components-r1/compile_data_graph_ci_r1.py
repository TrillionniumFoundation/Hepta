"""Fresh original-limit B3 compilation of the complete DataGraph value owner.

The old issued decoder, binary64, and Graph-wire peers are independently
source-pinned and freshly compiled; this is development, never cold admission.
"""
from __future__ import annotations
import ast,json,os,stat,subprocess,sys,time,traceback
from pathlib import Path
from hashlib import sha1,sha256
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-data-graph-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_data_graph_common.py",
    "bytes": 13039,
    "sha256": "192366d8ad7934e78e3e31617ccde4591d69af428779d65d449d30a5a581af8b",
    "gitsha": "bd05a2344399c4b7f2028c407e49bb43ecd48335"
  },
  {
    "path": "tools/agent_data_graph_values.py",
    "bytes": 12677,
    "sha256": "4b005ea341992084ce60355c7112dcd47c7544dc3f24b2eccd4b8966b2734421",
    "gitsha": "308b0cc5a962bf9a74b4b87101fee815143c0ae8"
  },
  {
    "path": "tools/generate_hia_agent_data_graph.py",
    "bytes": 4528,
    "sha256": "7bd7aaa02358acf599931338994ed9c7e6746dc7202f9195c81d92d82427eb7b",
    "gitsha": "323595d0596e55e4317ea4c017aaae7dd7f32e9e"
  }
]
RAW_PINS=[
  {
    "path": "examples/hia_bootstrap/agent_data_json.hiaasm",
    "bytes": 92926,
    "sha256": "bfb36b20e6e2def7a484c794b71f6ff7a202ecdc5452605bc0ad63251b03308e",
    "gitsha": "3129bb348bc8edfbd4398f69f30fd1b20b70497b"
  },
  {
    "path": "examples/hia_bootstrap/agent_binary64.hiaasm",
    "bytes": 43647,
    "sha256": "6aa2b2cd944cbcd3b5d5b19f9b275db060b63bd8b1e1d73cc1a6973b52000515",
    "gitsha": "44739875e9ac2734523521b375154a6f8dabfb62"
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
OUT.mkdir(parents=True,exist_ok=False)
ROOT.mkdir(parents=True,exist_ok=False);(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={}
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def rows():
    return [dict(path=str(p),bytes=len(b),sha256=digest(b),mode=stat.S_IMODE(p.stat().st_mode)) for p,b in pins.items()]
summary=dict(status='INCOMPLETE',native_entries=0,actual_compiles=0,whole_worker_closed=False,
             scope='FRESH_DATA_GRAPH_AND_EXACT_RAW_BINARY64_GRAPHWIRE_PEERS_DEVELOPMENT',
             compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20))
start=time.monotonic_ns()
try:
    raw=read(COMPILER)
    assert (len(raw),digest(raw))==(668608,'0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        target=ROOT/row['path'];ast.parse(raw,filename=str(target));target.write_bytes(raw);read(target)
    for row in RAW_PINS:
        raw=read(REFERENCE/row['path'])
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
    for path in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
                 'tools/qualify_hia_selfhost.py','hepta/hia_program.py','hepta/hia_agent_assembly.py',
                 'hepta/hia_agent_data_json_native.py','hepta/hia_json_decode_native.py',
                 'hepta/hia_agent_binary64_native.py','hepta/hia_agent_store.py',
                 'hepta/hia_program_tools.py'):
        read(REFERENCE/path)
    read(Path(__file__))
    save(OUT/'source-inputs-before.json',rows())
    for i,(path,raw) in enumerate(pins.items()):
        frozen=OUT/'source-inputs'/str(i)/path.name
        frozen.parent.mkdir(parents=True,exist_ok=True);frozen.write_bytes(raw)
        frozen.chmod(stat.S_IMODE(path.stat().st_mode))
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    from generate_hia_agent_data_graph import document,source_program
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    authoring=source_program()
    (OUT/'expanded-authoring.py').write_text(authoring)
    value=document();functions=value['functions']
    counts=dict(functions=len(functions),blocks=sum(len(f['blocks']) for f in functions),
        instructions=sum(len(b['ops']) for f in functions for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in functions),
        max_block_parameters=max(len(b['params']) for f in functions for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16))),counts
    raw=render_assembly(value).encode();assemble_program(raw)
    generated=ROOT/'examples/hia_bootstrap/agent_data_graph.hiaasm'
    generated.write_bytes(raw);read(generated)
    sources={'data_graph':generated,
             'decoder':REFERENCE/RAW_PINS[0]['path'],
             'binary64':REFERENCE/RAW_PINS[1]['path']}
    for row in WIRE_PINS:
        path=WORK/'native-agent-edit-render-next/examples/hia_bootstrap'/row['path']
        raw=read(path)
        assert (len(raw),digest(raw))==(row['bytes'],row['sha256'])
        sources[row['role']]=path
    components={}
    for role,path in sources.items():
        raw=read(path);image,receipt=compile_stage(OUT,role,COMPILER,raw)
        image=Path(image).resolve();image_raw=read(image)
        receipt_path=OUT/(role+'.receipt.json');actual=json.loads(read(receipt_path))
        assert actual['input_sha256']==digest(raw) and actual['produced_sha256']==digest(image_raw)
        assert actual['image_sha256']==digest(read(COMPILER))
        summary['actual_compiles']+=1
        components[role]=dict(role=role,source_path=str(path),source_bytes=len(raw),source_sha256=digest(raw),
            image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
            compiler_sha256=digest(read(COMPILER)),receipt_path=str(receipt_path))
    bundle=dict(schema='hia-agent-data-graph-development-bundle-v1',status='PASS',scope=summary['scope'],
        components=components,generated_counts=counts,whole_worker_closed=False)
    save(OUT/'bundle.json',bundle);summary.update(status='PASS',bundle=bundle,counts=counts)
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if not unchanged:summary['status']='FAIL'
    summary.update(source_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-start)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if summary['status']!='PASS':raise SystemExit(1)
