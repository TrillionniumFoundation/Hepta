"""Fresh original-limit compile for the complete default decode_data prefix.

Every raw/preflight/value/binary peer is the exact frozen HIA source compiled
again by the bound historical f50 B3. This is component development, never a
claim about a new matching cold generation or a fixed ordinary Worker.
"""
from __future__ import annotations
import ast,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-default-json-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_default_json_common.py",
    "bytes": 9474,
    "sha256": "db35cda5e0b820b6ddfb21f409d49537778fc0953845fbb91849e6a50b00af46",
    "gitsha": "787579fa5385369f61483699e34c64e3171d3963"
  },
  {
    "path": "tools/agent_default_json_lexical.py",
    "bytes": 8158,
    "sha256": "351918b275284c6e642d88f5f1c9f78633f959c3ef88c560bc98b86598e67d6f",
    "gitsha": "682037cddb66147450538704effb63064adae456"
  },
  {
    "path": "tools/agent_default_json_errors.py",
    "bytes": 6491,
    "sha256": "2f0eae52cb025bfee793bd91899d0cadc8c8769b1a72cad57c419b6d37eca538",
    "gitsha": "e3bc23f776f6ca1e73b93641bc4023103cabc05a"
  },
  {
    "path": "tools/agent_default_json_services.py",
    "bytes": 7215,
    "sha256": "4d8a14cf22bcd6db0c1aa7c6836e79aa469384ea89d04a1c69ae0c537f7fc671",
    "gitsha": "f1df92211b685b50226c7bc4e1afe59e866425c8"
  },
  {
    "path": "tools/agent_default_json_late.py",
    "bytes": 7961,
    "sha256": "d6d2242211acf8cc532007f4e170e7b9b4fbb2272733cdb3d311bf0bcd90d1b5",
    "gitsha": "b17556832548c59c90b8efc983efda7e22777345"
  },
  {
    "path": "tools/generate_hia_agent_default_json.py",
    "bytes": 6857,
    "sha256": "6515316ad466f2cb522e1fe1d660d1553a57e324b2648732be95df39360b3db9",
    "gitsha": "0946663cce9688a65f36a4cd8b111498f93ebe25"
  },
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
  },
  {
    "path": "examples/hia_bootstrap/json_preflight.hiaasm",
    "bytes": 61397,
    "sha256": "6bb6f6cd0ff22c919fb4e8f8f7b08471d4552b06156050f267275b0b63715b20",
    "gitsha": "f753e365f919a40343a0459ae4fe192c1fa36142"
  }
]
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={};components={};attempts=[];failures=[]
summary=dict(status='INCOMPLETE',actual_compiles=0,native_entries=0,
    scope='DEFAULT_DATAJSON_COMPLETE_PREFIX_AND_EXACT_PEERS_DEVELOPMENT',
    original_compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20),
    production_activation=False,whole_worker_closed=False)
started=time.monotonic_ns()
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw
def pinrows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode))
            for p,raw in pins.items()]
def counts(value):
    fs=value['functions']
    result=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(result.values(),(128,1536,8192,256,16))),result
    return result
def compile_one(role,path,value_counts=None):
    raw=read(path)
    image,receipt=compile_stage(OUT,role,COMPILER,raw);image=Path(image).resolve()
    actual_image=read(image);receipt_path=OUT/(role+'.receipt.json')
    original=json.loads(read(receipt_path))
    assert original['input_sha256']==digest(raw)
    assert original['produced_sha256']==digest(actual_image)
    assert original['image_sha256']==digest(read(COMPILER))
    row=dict(role=role,source_path=str(path),source_bytes=len(raw),source_sha256=digest(raw),
        image_path=str(image),image_bytes=len(actual_image),image_sha256=digest(actual_image),
        receipt_path=str(receipt_path),compiler_sha256=digest(read(COMPILER)),counts=value_counts)
    components[role]=row;summary['actual_compiles']+=1
    save(OUT/(role+'.manifest.json'),row)
    attempts.append(dict(role=role,status='PASS',manifest=row))
def failed(role):
    exc=sys.exception();text=traceback.format_exc()
    (OUT/(role+'.failure.log')).write_text(text);traceback.print_exc()
    row=dict(role=role,error_class=type(exc).__name__,error=str(exc),status='FAIL')
    failures.append(row);attempts.append(row)
try:
    raw=read(COMPILER)
    assert (len(raw),digest(raw))==(668608,'0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        path=ROOT/row['path'];ast.parse(raw,filename=str(path));path.write_bytes(raw);read(path)
    for row in RAW_PINS:
        raw=read(REFERENCE/row['path'])
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
    for path in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
        'tools/qualify_hia_selfhost.py','hepta/hia_program.py','hepta/hia_agent_assembly.py',
        'hepta/hia_json_preflight.py','hepta/hia_json_preflight_native.py',
        'hepta/hia_agent_data_json_native.py','hepta/hia_json_decode_native.py',
        'hepta/hia_agent_binary64_native.py','hepta/hia_agent_store.py',
        'hepta/hia_program_tools.py'):
        read(REFERENCE/path)
    read(__file__);save(OUT/'source-before.json',pinrows())
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    import generate_hia_agent_default_json as generator
    import generate_hia_agent_data_graph as values
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    for role,(label,_) in generator.ROLES.items():
        try:
            (OUT/(label+'.expanded-authoring.py')).write_text(generator.source_program(role))
            value=generator.document(role);value_counts=counts(value)
            raw=render_assembly(value).encode();assemble_program(raw)
            path=ROOT/'examples/hia_bootstrap'/(label+'.hiaasm');path.write_bytes(raw)
            compile_one(label,path,value_counts)
        except BaseException:failed(label)
    try:
        (OUT/'data_graph.expanded-authoring.py').write_text(values.source_program())
        value=values.document();value_counts=counts(value)
        raw=render_assembly(value).encode();assemble_program(raw)
        assert (len(raw),digest(raw))==(131057,'06f7cf6b2ac4a9f323f28aa485f442bc311decbb4d6f72147364e23e03cf8e0b')
        path=ROOT/'examples/hia_bootstrap/agent_data_graph.hiaasm';path.write_bytes(raw)
        compile_one('data_graph',path,value_counts)
    except BaseException:failed('data_graph')
    for role,row in zip(('decoder','binary64','preflight'),RAW_PINS):
        try:compile_one(role,REFERENCE/row['path'])
        except BaseException:failed(role)
    if not failures:
        assert set(components)=={'default_json_raw','default_json_services','default_json_late',
            'data_graph','decoder','binary64','preflight'}
        bundle=dict(schema='hia-agent-default-json-development-bundle-v1',status='PASS',
            components=components,scope=summary['scope'],whole_worker_closed=False,
            compiler_sha256=digest(read(COMPILER)))
        save(OUT/'bundle.json',bundle);summary.update(status='PASS',bundle=bundle)
except BaseException:failed('generation-driver')
finally:
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if failures or not unchanged:summary['status']='FAIL'
    for i,(path,raw) in enumerate(pins.items()):
        frozen=OUT/'frozen-inputs'/str(i)/path.name
        frozen.parent.mkdir(parents=True,exist_ok=True);frozen.write_bytes(raw)
        frozen.chmod(stat.S_IMODE(path.stat().st_mode))
    summary.update(source_unchanged=unchanged,attempts=attempts,failures=failures,
        elapsed_ns=time.monotonic_ns()-started)
    save(OUT/'source-after.json',pinrows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if summary['status']!='PASS':raise SystemExit(1)
