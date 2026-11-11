"""HIA packs actual main/query and immutable program owners into one ELF.

All 63 semantic owners are present. This build itself is not a semantic
qualification; the native JSON input revision is tested independently.
"""
from pathlib import Path
from hashlib import sha256
import importlib.util,json,struct,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
sys.path[:0]=[str(BASE/'native-composite-driver-reconstructed/development'),
    str(BASE/'native-composite-driver-reconstructed'),str(BASE/'Hepta-agent-edit-native')]
from mechanical_executor import Buffer
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_agent_assembly import render_assembly,assemble_program
from tools.qualify_hia_selfhost import compile_stage

PACK=BASE/'native-edit-json-next'
OUT=ROOT/'development/build-r1';OUT.mkdir(exist_ok=False)
pins={};components={};images={};start=time.monotonic_ns();summary=dict(status='INCOMPLETE')
def read(p):
    p=Path(p).resolve();raw=p.read_bytes()
    if p in pins:assert pins[p]==raw
    pins[p]=raw
    return raw
def add(role,row):
    source=read(row['source_path']);image=read(row['image_path'])
    assert sha256(source).hexdigest()==row['source_sha256'] and sha256(image).hexdigest()==row['image_sha256']
    assert 0<len(image)<=1<<20
    components[role]=dict(row,role=role,image_bytes=len(image),source_bytes=len(source));images[role]=image

read(Path(__file__))
compiler=BASE/'native-agent-edit-development/facts-source-and-compile-r1/source/compiler/B3.image.bin'
assert sha256(read(compiler)).hexdigest()=='35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
parent=BASE/'native-edit-apply-next/development/complete-build-r1/bundle.json'
complete=json.loads(read(parent));assert complete['status']=='PASS'
for role,row in complete['components'].items():add(int(role),row)
add(56,json.loads(read(PACK/'development/main-compile-r3/agent-edit-main.manifest.json')))
optimized=json.loads(read(BASE/'native-edit-performance-next/development/word-unroll-compile-r1/summary.json'));assert optimized['status']=='PASS'
for role,row in optimized['components'].items():add(int(role),row)
candidate=json.loads(read(ROOT/'development/compile-r1/summary.json'));assert candidate['status']=='PASS'
for role,row in candidate['components'].items():add(int(role),row)
assert sorted(components)==list(range(1,64))

src=PACK/'tools/edit_native_executor.S';read(src)
commands=[['as','--64','-o',str(OUT/'executor.o'),str(src)],['readelf','-rW',str(OUT/'executor.o')],
    ['nm','-n',str(OUT/'executor.o')],['objcopy','-O','binary','-j','.text',str(OUT/'executor.o'),str(OUT/'executor.bin')]]
for index,command in enumerate(commands):
    done=subprocess.run(command,capture_output=True,timeout=30)
    (OUT/f'command-{index}.stdout').write_bytes(done.stdout);(OUT/f'command-{index}.stderr').write_bytes(done.stderr)
    assert done.returncode==0,(command,done.stderr)
assert b'There are no relocations in this file.' in (OUT/'command-1.stdout').read_bytes()
symbols={words[2]:int(words[0],16) for line in (OUT/'command-2.stdout').read_text().splitlines() if len(words:=line.split())==3}
binary=(OUT/'executor.bin').read_bytes()
layout=dict(entry=symbols['executor_start'],image_table=symbols['image_table'],policy=symbols['executable_policy'],
    end=symbols['executor_end'],template_bytes=len(binary),template_sha256=sha256(binary).hexdigest(),
    source_sha256=sha256(read(src)).hexdigest(),relocation_count=0)
assert layout['entry']==0 and layout['end']==len(binary)
assert read(PACK/'tools/edit_native_executor.bin')==binary
assert json.loads(read(PACK/'tools/edit_native_executor_layout.json'))==layout
path=PACK/'tools/generate_hia_edit_cli.py';read(path)
spec=importlib.util.spec_from_file_location('integrated_hia_edit_packer',path)
packer_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(packer_module)
roles=tuple(sorted(components));doc=packer_module.document(roles);assembly=render_assembly(doc).encode()
(OUT/'packer.hiaasm').write_bytes(assembly);assemble_program(assembly)
profile=dict(functions=len(doc['functions']),blocks=sum(len(f['blocks']) for f in doc['functions']),
    max_blocks=max(len(f['blocks']) for f in doc['functions']),ops=sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),
    max_block_params=max(len(b['params']) for f in doc['functions'] for b in f['blocks']))
assert profile['functions']<=128 and profile['blocks']<=1536 and profile['max_blocks']<=256 and profile['ops']<=8192 and profile['max_block_params']<=16
for p in PACK.joinpath('tools').iterdir():
    if p.is_file():read(p)
for index,(p,raw) in enumerate(pins.items()):
    q=OUT/'source'/str(index)/p.name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw)
(OUT/'source-before.json').write_text(json.dumps({str(p):dict(bytes=len(v),sha256=sha256(v).hexdigest()) for p,v in pins.items()},indent=2,sort_keys=True)+'\n')
packer=None
try:
    image,receipt=compile_stage(OUT,'packer',compiler,assembly)
    packer=NativeHiaJsonImage(image.read_bytes(),receipt['produced_sha256'])
    prefix,table,policy=packer_module.template()
    entries=b''.join(struct.pack('<3Q',role,len(images[role]),0) for role in roles)
    size=64+len(entries)+sum(map(len,images.values()))
    payload=struct.pack('<8Q',packer_module.MAGIC,len(roles),4,4300,size,0,0,0)+entries+b''.join(images[r] for r in roles)
    (OUT/'packer-input.bin').write_bytes(payload)
    a=Buffer(len(payload),payload,True);o=Buffer(len(prefix)+sum(len(r)+15 for r in images.values()));w=Buffer(64)
    try:
        result=int(packer._entry(a.address,a.size,o.address,o.size,w.address,w.size))
        a.check();o.check();w.check();assert a.read(0,a.size)==payload and len(prefix)<result<=o.size
        executable=o.read(0,result);assert struct.unpack_from('<2Q',executable,96)==(result,result)
        actual=[]
        for role in roles:
            at=struct.unpack_from('<Q',executable,table+role*8)[0]-0x400000;raw=images[role]
            assert at>=len(prefix) and at%16==0 and executable[at:at+len(raw)]==raw
            actual.append(dict(role=role,offset=at,bytes=len(raw),sha256=sha256(raw).hexdigest()))
        target=OUT/'hia-edit-candidate-limit';target.write_bytes(executable);target.chmod(0o755)
        summary.update(status='PASS',components=components,packer_profile=profile,packer_receipt=receipt,
            executable=dict(path=str(target),bytes=len(executable),sha256=sha256(executable).hexdigest(),images=actual))
    finally:a.close();o.close();w.close()
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));raise
finally:
    if packer is not None:packer._mapping.close()
    summary.update(source_before_after_equal=all(p.read_bytes()==raw for p,raw in pins.items()),elapsed_ns=time.monotonic_ns()-start,
        scope='ACTUAL_HIA_ELF_PACKING_COMPLETE_EDIT_WITH_PRECISE_CANDIDATE_BYTE_LIMIT_WITNESS',whole_stack_closed=False)
    assert summary['source_before_after_equal']
    (OUT/'bundle.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('components','packer_receipt','executable')},sort_keys=True),flush=True)
