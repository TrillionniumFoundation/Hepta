"""Record reproducible source construction without claiming native execution."""
from pathlib import Path
import hashlib,importlib,json,struct
from hepta.hia_agent_assembly import render_assembly

ROOT=Path(__file__).resolve().parents[1]
def pin(path):
    raw=(ROOT/path).read_bytes()
    return {'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
rows=[]
for role in('background_optimizer_constructor_checks','background_optimizer_constructor_binding',
            'background_optimizer_constructor_binding_packer'):
    m=importlib.import_module('tools.generate_hia_'+role)
    d=m.program()if hasattr(m,'program')else m.document(m.source_program(),role)
    p='examples/hia_bootstrap/'+role+'.hepta'
    (ROOT/p).write_text(render_assembly(d))
    fs=d['functions']
    row={'role':role,'author':pin('tools/generate_hia_'+role+'.py'),'source':pin(p),
      'functions':len(fs),'blocks':sum(len(f['blocks'])for f in fs),
      'operations':sum(len(b['ops'])for f in fs for b in f['blocks']),
      'maximum_function_blocks':max(len(f['blocks'])for f in fs),
      'maximum_function_values':max(len({x['name']for b in f['blocks']for x in b['params']}|
           {x['name']for b in f['blocks']for op in b['ops']for x in op.get('out',[])})for f in fs),
      'maximum_block_parameters':max(len(b['params'])for f in fs for b in f['blocks'])}
    assert row['functions']<=128 and row['blocks']<=1536 and row['operations']<=8192
    assert row['maximum_function_blocks']<=256 and row['maximum_function_values']<=2048 and row['maximum_block_parameters']<=16
    rows.append(row)
from tools import generate_hia_background_optimizer_constructor_binding_packer as pack
obj=pack.reference_object((b'\x31\xc0\xc3',b'\x31\xc0\xc3'))
assert obj[:4]==b'\x7fELF' and pack.RELOCATIONS==() and pack.ROLES==('policy','checks')
def byte(buf,p):
    assert 0<=p<len(buf)
    return buf[p]
def store(buf,p,v):
    assert 0<=p<len(buf)
    buf[p]=v&255
    return 0
env={'readbuf':object,'mutbuf':object,'u32':int,'u64':int,'length':len,'byte':byte,'store':store}
exec(pack.source_program(),env)
frame=struct.pack('<4Q',pack.MAGIC,2,3,3)+b'\x31\xc0\xc3'*2
out=bytearray([0xa5])*len(obj)
assert env['pack'](frame,out,bytearray(128))==len(obj) and bytes(out)==obj
for bad in(frame[:31],frame[:-1],frame+b'\0',frame[:8]+struct.pack('<Q',1)+frame[16:]):
    out=bytearray([0xa5])*len(obj);before=bytes(out)
    assert env['pack'](bad,out,bytearray(128))==4294967295 and bytes(out)==before
out=bytearray([0xa5])*(len(obj)-1);before=bytes(out)
assert env['pack'](frame,out,bytearray(128))==4294967294 and bytes(out)==before
mechanical=Path('/dev/shm/native-release-constructor-binding/bridge.o').read_bytes()
h=struct.unpack_from('<16sHHIQQQIHHHHHH',mechanical)
ss=[struct.unpack_from('<IIQQQQIIQQ',mechanical,h[6]+i*h[11])for i in range(h[12])]
names=mechanical[ss[h[13]][4]:ss[h[13]][4]+ss[h[13]][5]]
for section in ss:
    name=names[section[0]:names.index(0,section[0])]
    if name==b'.text':assert mechanical[section[4]:section[4]+section[5]]==pack.BRIDGE
    if section[1]in(4,9):assert section[5]==0
report={'schema':'hepta.hia.background.constructor-binding.offline.v1',
 'authoring_verifier':'original verify_program before and after compact_authoring_cfg',
 'native_limits_changed':False,'native_built':False,'runtime_qualified':False,'whole_background_qualified':False,
 'roles':rows,'bridge':pin('tools/hia_background_optimizer_constructor_binding_bridge.S'),
 'mechanical_template_bytes':len(pack.BRIDGE),'mechanical_template_sha256':hashlib.sha256(pack.BRIDGE).hexdigest(),
 'mechanical_imports':[],'mechanical_holes':pack.HOLES,
 'source_packer_controls':6,
 'development_probes':pin('docs/HIA_BACKGROUND_NATIVE_CONSTRUCTOR_BINDING_SOURCE_PROBES.json'),
 'shared_author_dependencies':[pin('tools/generate_hia_background_optimizer_admission.py'),
                              pin('tools/generate_hia_background_optimizer_structure.py'),
                              pin('tools/generate_hia_background_optimizer_value_freeze.py'),
                              pin('tools/hia_background_retirement_source.py')],
 'required_new_dependency_profiles':['HIABVFY3/4','HIABVYC2','HIABVFR2','HIABVQ02/29,31'],
 'remaining':['native construction and actual dependency gates','actual public runtime class gate',
              'actual Path objects after live mapping construction','complete BG allocation/start/rollback',
              'full original public constructor and whole lifecycle qualification']}
(ROOT/'docs/HIA_BACKGROUND_NATIVE_CONSTRUCTOR_BINDING.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'roles':[{k:v for k,v in r.items()if k not in('author',)}for r in rows],
                  'mechanical_bytes':len(pack.BRIDGE),'native':False}))
