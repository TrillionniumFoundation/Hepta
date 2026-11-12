"""Exercise the exact fixed executor with an explicit development controller.

The HIA controller exposes actual peer replies; it deliberately bypasses the
product kit gate and is not a public builder or a qualification candidate.
"""
from pathlib import Path
from hashlib import sha256
import json, struct, subprocess, sys, time, traceback

ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent/'Hepta-v67-workflow-qualified'
sys.path[:0]=[str(ROOT/'tools'),str(ROOT.parent/'Hepta-agent-edit-native'),str(BASE)]
from build_authoring import document, expanded, profile
from hepta.hia_agent_assembly import render_assembly
from tools.qualify_hia_selfhost import compile_stage, invoke

OUT=ROOT/'development/executor-mechanics-r2';OUT.mkdir()
compiler=ROOT.parent/'hia-v67-0ef-qualification-local-01/cold.cold/qualification.evidence/B3.image.bin'
packer_manifest=ROOT/'development/driver-compile-r2/clean-build-packer.manifest.json'
decoder_manifest=ROOT/'development/gate-compile-r2/agent-data-json.manifest.json'
paths=[Path(__file__),ROOT/'development/mechanics_probe.S',ROOT/'tools/clean_build_executor.S',compiler,packer_manifest,decoder_manifest]
pins={p:p.read_bytes() for p in paths}
for p in (packer_manifest,decoder_manifest):
    m=json.loads(pins[p]);sp=Path(m['source_path']);ip=Path(m['image_path']);pins[sp]=sp.read_bytes();pins[ip]=ip.read_bytes()
    assert sha256(pins[sp]).hexdigest()==m['source_sha256'] and sha256(pins[ip]).hexdigest()==m['image_sha256']
summary={'status':'INCOMPLETE','scope':'PRIVATE_DEVELOPMENT_MECHANICAL_CONTROLLER','cases':[]};start=time.monotonic_ns()
try:
    for label,cmd in [('assemble',['/usr/bin/as','--64',str(ROOT/'development/mechanics_probe.S'),'-o',str(OUT/'probe.o')]),
                      ('relocations',['/usr/bin/readelf','-r',str(OUT/'probe.o')]),
                      ('extract',['/usr/bin/objcopy','-O','binary','--only-section=.text',str(OUT/'probe.o'),str(OUT/'probe.bin')])]:
        p=subprocess.run(cmd,capture_output=True);(OUT/(label+'.stdout')).write_bytes(p.stdout);(OUT/(label+'.stderr')).write_bytes(p.stderr)
        assert p.returncode==0,(label,p.stderr)
        if label=='relocations':assert b'There are no relocations' in p.stdout
    probe=(OUT/'probe.bin').read_bytes()
    body='''
def observe(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 8192:
        return 4294967293
    if length(s) >= 32 and uint(s, 0) == ARGMAGIC:
        put(w, 2048, IMAGIC)
        put(w, 2056, 1)
        put(w, 2096, uint(s, 24))
        put(w, 0, 1)
        return event(w, 9, 2048, 64)
    if get(w, 0) == 1:
        if length(s) != 64 + PROBE + 1:
            return 4294967293
        put(w, 0, 2)
        put(w, 16, 0)
        put(w, 24, 4096)
        return request(w)
    if get(w, 0) != 2 or length(r) < 64:
        return 4294967293
    if uint(r, 0) != RMAGIC or uint(r, 8) != get(w, 16) + 1 or uint(r, 16) != 2:
        return 4294967293
    if uint(r, 32) != length(r) - 64 or length(r) > 320:
        return 4294967293
    at = get(w, 24)
    i = 0
    while i < length(r):
        store(w, at + i, byte(r, i))
        i = i + 1
    put(w, 24, at + length(r))
    put(w, 16, get(w, 16) + 1)
    if get(w, 16) < 2:
        return request(w)
    put(w, 0, 3)
    return event(w, 0, 4096, get(w, 24) - 4096)

def request(w:mutbuf) -> u32:
    event(w, 5, 64 + PROBE, 1)
    put(w, 1040, get(w, 16) + 1)
    put(w, 1064, 256)
    put(w, 1072, 256)
    put(w, 1088, 64)
    put(w, 1096, PROBE)
    put(w, 1104, 1)
    return 128

def event(w:mutbuf, action:u64, at:u64, size:u64) -> u32:
    i = 0
    while i < 128:
        store(w, 1024 + i, 0)
        i = i + 1
    put(w, 1024, EMAGIC)
    put(w, 1032, action)
    put(w, 1048, at)
    put(w, 1056, size)
    return 128

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
    constants={key:int.from_bytes(value,'little') for key,value in [('ARGMAGIC',b'HIABAR01'),('IMAGIC',b'HIABIN01'),('RMAGIC',b'HIABRP01'),('EMAGIC',b'HIABBE01')]}
    constants['PROBE']=len(probe)
    authored=expanded(body,constants);(OUT/'mechanical_controller.py').write_text(authored)
    doc=document(authored,'clean_build_mechanics');source=render_assembly(doc).encode();(OUT/'mechanical_controller.hiaasm').write_bytes(source)
    image,receipt=compile_stage(OUT,'controller',compiler,source)
    assert receipt['input_sha256']==sha256(source).hexdigest() and receipt['artifact_sha256']==sha256(pins[compiler]).hexdigest()
    pm=json.loads(pins[packer_manifest]);dm=json.loads(pins[decoder_manifest]);code=image.read_bytes();decoder=pins[Path(dm['image_path'])]
    frame=struct.pack('<4Q',int.from_bytes(b'HIABPK01','little'),len(code),len(decoder),0)+code+decoder
    result,output=invoke(OUT,'actual-mechanical-pack',Path(pm['image_path']),frame)
    size=result['core_u32'];assert result['status']=='returned' and 0<size<=len(output)
    exe=OUT/'observe-executor';exe.write_bytes(output[:size]);exe.chmod(0o700)
    summary.update(controller_profile=profile(doc),controller_image_sha256=sha256(code).hexdigest(),executable_sha256=sha256(output[:size]).hexdigest())
    for mode,label in [(0,'fresh-pid-zero-limits'),(1,'actual-source-readonly'),(2,'actual-code-rx')]:
        folder=OUT/label;folder.mkdir();raw=probe+bytes([mode]);(folder/'input.raw').write_bytes(raw)
        p=subprocess.run([str(exe),'0'*64],input=raw,capture_output=True,env={'PATH':'','HOME':str(OUT)},timeout=25)
        (folder/'stdout.raw').write_bytes(p.stdout);(folder/'stderr.raw').write_bytes(p.stderr)
        record={'case':label,'mode':mode,'exit':p.returncode,'stdout_bytes':len(p.stdout),'stderr_bytes':len(p.stderr),'replies':[]}
        summary['cases'].append(record)
        assert p.returncode==0 and len(p.stderr)==128,(label,p.returncode,p.stderr.hex())
        at=0
        for seq in (1,2):
            header=struct.unpack_from('<8Q',p.stdout,at);at+=64
            assert header[0]==constants['RMAGIC'] and header[1]==seq and header[2]==2 and header[7]==0
            payload=p.stdout[at:at+header[4]];at+=header[4]
            row={'header':list(header),'payload_hex':payload.hex()};record['replies'].append(row)
            if mode==0:
                assert header[3]==128 and header[4]==256 and header[5]==0 and header[6]>0
                words=struct.unpack_from('<16Q',payload);row['observation']=list(words)
                assert words[0]>0 and words[1]>0
                assert words[2:10]==(10,10,268435456,268435456,8388608,8388608,0,0)
                assert 0<words[10]<=20 and words[12:16]==(1,1,256,256)
                assert payload[128:]==bytes(128)
            else:
                assert header[4]==0 and header[5]==11 and header[3]==0
        assert at==len(p.stdout)
        if mode==0:
            a,b=[x['observation'] for x in record['replies']]
            assert a[0]!=b[0] and a[1]==b[1] and a[0]!=a[1] and b[0]!=b[1]
        (folder/'result.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    summary['status']='PASS'
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));traceback.print_exc();raise
finally:
    summary['all_pins_unchanged']=all(p.read_bytes()==raw for p,raw in pins.items())
    summary['elapsed_ns']=time.monotonic_ns()-start
    (OUT/'pins.json').write_text(json.dumps({str(p):{'bytes':len(raw),'sha256':sha256(raw).hexdigest()} for p,raw in pins.items()},indent=2,sort_keys=True)+'\n')
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,sort_keys=True),flush=True)
    assert summary['all_pins_unchanged']
