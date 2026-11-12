"""Fresh registry and unchanged native peers: eight original-limit B3 compiles."""
from __future__ import annotations
import ast,importlib,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-initialization-registry-next';REFERENCE=WORK/'Hepta-agent-edit-native'
RENDER=WORK/'native-agent-edit-render-next'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PINS=[
  {
    "path": "tools/worker_init_registry_common.py",
    "bytes": 10229,
    "sha256": "d501b2c51cc8b8485599af9f4848a2fd69d06262de5aaf21d9e9f5111a0edccd",
    "gitsha": "e23d85112c35253bd3df8c349125e212a61bb614"
  },
  {
    "path": "tools/worker_init_registry_result.py",
    "bytes": 9003,
    "sha256": "533e8a95de9c1d13f3b9e05d159f522b63cacd653490af0bafafd0743d98a951",
    "gitsha": "8f5db6601f2a28e4a8b98231ce3c664052fd84f7"
  },
  {
    "path": "tools/generate_hia_agent_worker_init_registry.py",
    "bytes": 7195,
    "sha256": "0ec0e0699acc444824821e428309ca97cc74b88c87bd27c4235d8fed96b73a33",
    "gitsha": "7ee9b7cf7b01b28b50dec8a88a3213bea75e14eb"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZER_REGISTRY_ABI_R2.md",
    "bytes": 11987,
    "sha256": "6d23a7bb6a2b0f363034093db836cd23cd2ba6d9e5e0b1a246f1552e5cddfa01",
    "gitsha": "df39f3acff0b6889bccaea115845308c404c4093"
  },
  {
    "path": "tools/worker_init_pure_common.py",
    "bytes": 9085,
    "sha256": "f8f54a86ed80cd977ea54faf5c75007d8eca98be752c5ad8e9d9fce780bf68f5",
    "gitsha": "1151c9d63ce2f189fd0fcc72bf00870a55370544"
  },
  {
    "path": "tools/worker_init_pure_prepare.py",
    "bytes": 15262,
    "sha256": "0862ff31b76d71edc9a47fc48632801a69960e6739a8b3d763151c3e5bb0dfb7",
    "gitsha": "f556d39f9d65a17874586a3a9f1a2b9d8e2d839a"
  },
  {
    "path": "tools/worker_init_pure_result.py",
    "bytes": 10563,
    "sha256": "e26d47cdc4cc172183ae08ffbcbf3ec88db53d282a0d46f60a505a52dc823d38",
    "gitsha": "403d6012ca7833bc4da3fb5d40ee3cc66aad7966"
  },
  {
    "path": "tools/generate_hia_agent_worker_init_pure.py",
    "bytes": 7025,
    "sha256": "1b7d97ba633a40814586b0101d786b2b660ded3c59709dc34949f831b69a6974",
    "gitsha": "d95ce033f7d13ca8fa580de5eb8e83f9c85e3b18"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZER_PURE_JOIN_ABI_R1.md",
    "bytes": 13662,
    "sha256": "32f39cf44c8f097b0ffd4e166464fd4eb0d4fd3500ffdb2f683402dfc0bee38b",
    "gitsha": "93dec7410a4e6ae97456fdc284bf67a15ef0f66e"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_values.py",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_sequence.py",
    "bytes": 34300,
    "sha256": "fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef",
    "gitsha": "f9cd612bad5707d95acef736afe03b6600724d9b"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_maps.py",
    "bytes": 19560,
    "sha256": "8a837ae4acaf11a68054c030c51d6d667d93dee4c825c8fee5bb324b9a6fc2fb",
    "gitsha": "275a8c3a5d63a94241d0651adf425ae2530d2380"
  },
  {
    "path": "tools/agent_worker_init_templates.py",
    "bytes": 13155,
    "sha256": "65d048c0eb027cbbe83be4d20f1708b96b40415c760322f1c79c4c7d3d1e93d0",
    "gitsha": "fe96d796fe71120ddef15707d6add729f96c7aec"
  },
  {
    "path": "development/sequence_oracle_source.py",
    "bytes": 32141,
    "sha256": "b809f06c0c1a0e56d5a49555e6b3010ce7c78d18707571f87c4a9b78d7d62f2b",
    "gitsha": "610dad775c08cddb0daa7be6d465318151bc95bb"
  },
  {
    "path": "development/value_mechanics_source.py",
    "bytes": 27233,
    "sha256": "1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753",
    "gitsha": "b12248a7ad4aa4875e78af33922182b3fffc1636"
  },
  {
    "path": "dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json",
    "bytes": 226542,
    "sha256": "61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8",
    "gitsha": "9b6ff8f96518a50b7d348ec732981610aa4c9ed1"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_pure.py",
    "bytes": 7025,
    "sha256": "1b7d97ba633a40814586b0101d786b2b660ded3c59709dc34949f831b69a6974",
    "gitsha": "d95ce033f7d13ca8fa580de5eb8e83f9c85e3b18"
  },
  {
    "path": "dependencies/worker_init_pure_common.py",
    "bytes": 9085,
    "sha256": "f8f54a86ed80cd977ea54faf5c75007d8eca98be752c5ad8e9d9fce780bf68f5",
    "gitsha": "1151c9d63ce2f189fd0fcc72bf00870a55370544"
  },
  {
    "path": "dependencies/worker_init_pure_result.py",
    "bytes": 10563,
    "sha256": "e26d47cdc4cc172183ae08ffbcbf3ec88db53d282a0d46f60a505a52dc823d38",
    "gitsha": "403d6012ca7833bc4da3fb5d40ee3cc66aad7966"
  },
  {
    "path": "development/pure_join_fixture_source.py",
    "bytes": 35601,
    "sha256": "508a9e6050943be1ff3053ea4e1ace2d9761a38cede7d55f02995139ef451a6d",
    "gitsha": "703c4d78fae1cbc4bfe4ced89ea441f5a7f47d61"
  },
  {
    "path": "dependencies/generate_hia_graph_merge.py",
    "bytes": 11265,
    "sha256": "b4cda58e84da76a17a2daa919f37483eb2973dcfdbb00cd30c074ebc9aca8ed9",
    "gitsha": "9eea9deec088878dc5889d8218e7b422c73efea3",
    "mode": 420,
    "original_member": "development/report-compile-r1/source/16/generate_hia_graph_merge.py"
  }
]
ROLES={
 'sequence':('generate_hia_agent_worker_init_sequence','agent_worker_initialization_sequence.hiaasm'),
 'maps':('generate_hia_agent_worker_init_maps','agent_worker_initialization_maps.hiaasm'),
 'values':('generate_hia_agent_worker_init_values','agent_worker_initialization_values.hiaasm'),
 'pure':('generate_hia_agent_worker_init_pure','agent_worker_initializer_pure_join.hiaasm'),
 'registry':('generate_hia_agent_worker_init_registry','agent_worker_initializer_registry.hiaasm'),
 'merge':('generate_hia_graph_merge','graph_merge.hiaasm')}
FIXED={
 'scan':(147822,'c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3'),
 'emit':(173680,'9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2')}
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={};modes={};components={};status='FAIL';failure=None;started=time.monotonic_ns()
template_manifest=None;template_path=None;template=None
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in pins:assert pins[path]==raw and modes[path]==mode
    pins[path]=raw;modes[path]=mode;return raw
def rows():
    return [dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=modes[path])
        for path,raw in pins.items()]
def same():
    return all(path.is_file() and path.read_bytes()==raw
        and stat.S_IMODE(path.stat().st_mode)==modes[path] for path,raw in pins.items())
try:
    read(__file__)
    assert (len(read(COMPILER)),digest(read(COMPILER)))==(668608,COMPILER_SHA)
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        path=ROOT/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
        if path.suffix=='.py':ast.parse(raw,filename=str(path))
        with path.open('xb') as out:out.write(raw)
        read(path)
    for name in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
        'tools/qualify_hia_selfhost.py','hepta/hia_program.py','hepta/hia_agent_assembly.py',
        'hepta/hia_agent_service.py','hepta/hia_agent_store.py','hepta/hia_json_preflight_native.py'):
        read(REFERENCE/name)
    assert digest(read(REFERENCE/'hepta/hia_agent_service.py'))=='684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'
    sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'dependencies'),str(REFERENCE)]
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    import agent_worker_init_templates as templates
    template_manifest=templates.build(REFERENCE,OUT/'static-templates')
    template_path=Path(template_manifest['packet']['path']).resolve();template=read(template_path)
    assert (len(template),digest(template))==(template_manifest['packet']['bytes'],template_manifest['packet']['sha256'])
    for row in template_manifest['dependencies']:
        assert digest(read(row['path']))==row['sha256']
    for role,(module_name,filename) in ROLES.items():
        generation=importlib.import_module(module_name)
        assert Path(generation.__file__).resolve() in {
            (ROOT/'tools'/(module_name+'.py')).resolve(),
            (ROOT/'dependencies'/(module_name+'.py')).resolve()}
        (OUT/(role+'.expanded-authoring.py')).write_text(generation.source_program())
        value=generation.document();fs=value['functions']
        counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
            instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
            max_function_blocks=max(len(f['blocks']) for f in fs),
            max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
        assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16))),counts
        raw=render_assembly(value).encode();assemble_program(raw)
        path=ROOT/'examples/hia_bootstrap'/filename;assert not path.exists();path.write_bytes(raw)
        source=read(path)
        image,_=compile_stage(OUT,role,COMPILER,source)
        image=Path(image).resolve();image_raw=read(image)
        receipt_path=OUT/(role+'.receipt.json');receipt=json.loads(read(receipt_path))
        assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image_raw)
        assert receipt['image_sha256']==COMPILER_SHA
        row=dict(role=role,source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
            image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
            receipt_path=str(receipt_path),compiler_sha256=COMPILER_SHA,counts=counts)
        components[role]=row;save(OUT/(role+'.manifest.json'),row)
    for role,(expected_bytes,expected_sha) in FIXED.items():
        path=RENDER/'examples/hia_bootstrap'/('graph_json_wire_'+role+'.hiaasm')
        source=read(path)
        assert (len(source),digest(source))==(expected_bytes,expected_sha)
        assemble_program(source)
        image,_=compile_stage(OUT,role,COMPILER,source)
        image=Path(image).resolve();image_raw=read(image)
        receipt_path=OUT/(role+'.receipt.json');receipt=json.loads(read(receipt_path))
        assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image_raw)
        assert receipt['image_sha256']==COMPILER_SHA
        row=dict(role=role,source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
            image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
            receipt_path=str(receipt_path),compiler_sha256=COMPILER_SHA,
            counts=None,exact_fixed_original_hia_source=True)
        components[role]=row;save(OUT/(role+'.manifest.json'),row)
    for module in tuple(sys.modules.values()):
        file=getattr(module,'__file__',None)
        if file:
            candidate=Path(file).resolve()
            if candidate.suffix=='.py' and candidate.is_relative_to(REFERENCE):read(candidate)
    assert same()
    save(OUT/'bundle.json',dict(schema='hia-worker-initializer-registry-development-v1',
        status='PASS',components=components,original_compiler_sha256=COMPILER_SHA,
        template_path=str(template_path),template_bytes=len(template),template_sha256=digest(template),
        template_manifest=str(OUT/'static-templates/manifest.json'),
        actual_runtime_entries=0,ordinary_initialization=False,whole_worker_closed=False,
        complete_graph_merge_original_source=True,registry_runtime_entries=0))
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    unchanged=same()
    if not unchanged:status='FAIL'
    save(OUT/'source-after.json',rows())
    for index,(path,raw) in enumerate(pins.items()):
        target=OUT/'frozen-inputs'/str(index)/path.name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(modes[path])
    summary=dict(status=status,scope='INITIALIZER_REGISTRY_FRESH_EIGHT_IMAGE_ORIGINAL_LIMIT_COMPILE',
        components=components,actual_compiles=len(components),failure=failure,
        source_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
        original_compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20),
        runtime_entries=0,namespace_effects_closed=False,cross_graph_import_runtime_executed=False,
        ordinary_initialization=False,whole_worker_closed=False,production_activation=False)
    save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
