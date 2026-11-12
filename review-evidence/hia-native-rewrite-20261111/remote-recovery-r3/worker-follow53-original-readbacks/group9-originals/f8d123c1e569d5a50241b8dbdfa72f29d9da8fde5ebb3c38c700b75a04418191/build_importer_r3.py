"""Actual original-limit B3 compilation and actual HIA packing, new identity."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
ORDINARY=ROOT.parent/'native-composite-driver-reconstructed'
BASE=ROOT.parent/'Hepta-v66-restored'
sys.path[:0]=[str(ROOT),str(ORDINARY/'development'),str(ORDINARY),str(BASE)]
from publication_mechanical_executor import PublicBundle,Buffer
from tools.qualify_hia_selfhost import compile_stage
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.author_legacy_executor import author

dest=ROOT/'development/build-r3';dest.mkdir(parents=True,exist_ok=False)
source=ROOT/'tools/legacy_native_executor.S'
assert source.read_text()==author()
commands=[['as','--64','-o',str(dest/'executor.o'),str(source)],
          ['readelf','-rW',str(dest/'executor.o')],
          ['nm','-n',str(dest/'executor.o')],
          ['objcopy','-O','binary','-j','.text',str(dest/'executor.o'),str(dest/'executor.bin')]]
logs=[]
for i,cmd in enumerate(commands):
    r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    (dest/f'authoring-command-{i}.stdout').write_bytes(r.stdout)
    (dest/f'authoring-command-{i}.stderr').write_bytes(r.stderr)
    logs.append({'command':cmd,'returncode':r.returncode})
    assert r.returncode==0,(cmd,r.stderr)
assert b'There are no relocations in this file.' in (dest/'authoring-command-1.stdout').read_bytes()
symbols={}
for row in (dest/'authoring-command-2.stdout').read_text().splitlines():
    parts=row.split()
    if len(parts)==3:symbols[parts[2]]=int(parts[0],16)
binary=(dest/'executor.bin').read_bytes()
layout={'entry':symbols['executor_start'],'image_table':symbols['image_table'],
    'policy':symbols['executable_policy'],'end':symbols['executor_end'],
    'template_bytes':len(binary),'template_sha256':sha256(binary).hexdigest(),
    'source_sha256':sha256(source.read_bytes()).hexdigest(),'relocation_count':0}
assert layout['entry']==0 and layout['end']==len(binary)
(ROOT/'tools/legacy_native_executor.bin').write_bytes(binary)
(ROOT/'tools/legacy_native_executor_layout.json').write_text(json.dumps(layout,indent=2,sort_keys=True)+'\n')
(dest/'authoring-commands.json').write_text(json.dumps(logs,indent=2)+'\n')
from tools.generate_hia_legacy_cli import document,template,ROLES,MAGIC
packer_source=ROOT/'examples/hia_bootstrap/legacy_composite_cli_packer.hiaasm'
packer_source.write_text(render_assembly(document()))
compiler=ROOT.parent/'native-composite-core-final-recovery-next/dependencies/f50-B3.image.bin'
compiler_bytes=compiler.read_bytes()
assert sha256(compiler_bytes).hexdigest()=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
bundle_path=ORDINARY/'development/publication-bundle-r2/bundle.json'
old=PublicBundle(bundle_path)
pins=dict(old.pins);pins[compiler]=compiler_bytes;pins[Path(__file__)]=Path(__file__).read_bytes()
for folder in ('tools','examples','docs'):
    for p in (ROOT/folder).rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:pins[p]=p.read_bytes()
assert all(p.read_bytes()==raw for p,raw in pins.items())
(dest/'source-before.json').write_text(json.dumps({str(p):{'bytes':len(raw),'sha256':sha256(raw).hexdigest()} for p,raw in pins.items()},indent=2,sort_keys=True)+'\n')
frozen=dest/'frozen-source'
for p,raw in pins.items():
    if p.is_relative_to(ROOT):
        target=frozen/p.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
rows={str(k):dict(v) for k,v in old.components.items()}
summary={'scope':'COMPLETE_HISTORICAL_IMPORTER_ACTUAL_B3_AND_NATIVE_HIA_PACKER_DEVELOPMENT',
    'status':'INCOMPLETE','whole_stack_closed':False,'production_activation':False,'components':rows,
    'compiler_sha256':sha256(compiler_bytes).hexdigest(),'original_compiler_limits_unchanged':True,
    'frozen_ordinary_bundle_sha256':sha256(bundle_path.read_bytes()).hexdigest()}
names={28:'projection',29:'compare',46:'import_driver',47:'publication'}
packer=None;start=time.monotonic_ns()
try:
    for role,name in names.items():
        src=ROOT/'examples/hia_bootstrap'/f'legacy_composite_{name}.hiaasm';raw=pins[src]
        folder=dest/f'image-{role}';folder.mkdir()
        (folder/'source.hiaasm').write_bytes(raw)
        image,receipt=compile_stage(folder,f'component-{role}',compiler,raw)
        assert receipt['input_sha256']==sha256(raw).hexdigest() and receipt['artifact_sha256']==sha256(compiler_bytes).hexdigest()
        rows[str(role)]={'role':role,'source_path':str(folder/'source.hiaasm'),'expected_source_path':str(src),
            'source_bytes':len(raw),'source_sha256':sha256(raw).hexdigest(),'image_path':str(image),
            'image_bytes':image.stat().st_size,'image_sha256':receipt['produced_sha256'],
            'receipt_path':str(folder/f'component-{role}.receipt.json'),'compiler_sha256':sha256(compiler_bytes).hexdigest()}
        print(json.dumps({'role':role,'status':'COMPILED','source_sha256':sha256(raw).hexdigest(),'image_sha256':receipt['produced_sha256']}),flush=True)
    folder=dest/'packer';folder.mkdir()
    image,receipt=compile_stage(folder,'packer',compiler,pins[packer_source])
    packer=NativeHiaJsonImage(image.read_bytes(),receipt['produced_sha256'])
    summary['packer']={'source':str(packer_source),'source_sha256':sha256(pins[packer_source]).hexdigest(),
        'image':str(image),'image_sha256':receipt['produced_sha256'],'receipt':receipt}
    prefix,table_at,policy_at=template()
    images=[]
    for role in ROLES:
        row=rows[str(role)];p=Path(row['image_path']);raw=p.read_bytes()
        assert len(raw)==row['image_bytes'] and sha256(raw).hexdigest()==row['image_sha256']
        if p in pins:assert pins[p]==raw
        else:pins[p]=raw
        images.append(raw)
    entries=b''.join(struct.pack('<3Q',role,len(raw),0) for role,raw in zip(ROLES,images))
    size=64+len(entries)+sum(map(len,images))
    payload=struct.pack('<8Q',MAGIC,len(ROLES),2,4300,size,0,0,0)+entries+b''.join(images)
    (dest/'packer-input.bin').write_bytes(payload)
    bound=len(prefix)+sum(len(raw)+15 for raw in images)
    s=Buffer(len(payload),payload,True);o=Buffer(bound);w=Buffer(64)
    try:
        result=int(packer._entry(s.address,s.size,o.address,o.size,w.address,w.size))
        s.check();o.check();w.check();assert s.read(0,len(payload))==payload
        assert 176+len(prefix)<result<=bound,result
        executable=o.read(0,result)
        assert struct.unpack_from('<2Q',executable,96)==(result,result)
        assert struct.unpack_from('<2Q',executable,policy_at)==(2,4300)
        emitted=[]
        for role,raw in zip(ROLES,images):
            at=struct.unpack_from('<Q',executable,table_at+8*role)[0]-0x400000
            assert at>=len(prefix) and at%16==0 and executable[at:at+len(raw)]==raw
            emitted.append({'role':role,'offset':at,'bytes':len(raw),'sha256':sha256(raw).hexdigest()})
        target=dest/'hia-import-legacy-composite';target.write_bytes(executable);target.chmod(0o755)
        summary['executable']={'path':str(target),'bytes':len(executable),'sha256':sha256(executable).hexdigest(),'components':emitted,
            'actual_packer_return':result,'input_sha256':sha256(payload).hexdigest(),'runtime_python_required':False}
    finally:s.close();o.close();w.close()
    summary['status']='PASS'
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));raise
finally:
    if packer is not None:packer._mapping.close()
    old.close();assert all(p.read_bytes()==raw for p,raw in pins.items())
    summary['source_and_actual_image_pins_unchanged']=True
    summary['wall_elapsed_ns']=time.monotonic_ns()-start
    (dest/'bundle.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('components','packer','executable')},sort_keys=True),flush=True)
