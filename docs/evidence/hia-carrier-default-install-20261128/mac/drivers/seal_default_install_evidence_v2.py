from pathlib import Path
from hashlib import sha256
import gzip,json,shutil,subprocess,tarfile
R=Path(__file__).resolve().parent;S=R/'source';Q=R/'default-install-complete-cas-v1'
E=S/'docs/evidence/hia-carrier-default-install-20261128';E.mkdir(mode=0o700,parents=True,exist_ok=True)
archive=Q/'complete-physical.tar.gz';raw=archive.read_bytes();receipt=json.loads((Q/'mac-readback.json').read_bytes())
assert {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}==receipt['archive']
chunks=[]
for i,off in enumerate(range(0,len(raw),16<<20)):
 name=f'complete-physical.part-{i:03d}.bin';value=raw[off:off+(16<<20)];(E/name).write_bytes(value);chunks.append({'name':name,'bytes':len(value),'sha256':sha256(value).hexdigest()})
assert b''.join((E/x['name']).read_bytes() for x in chunks)==raw
(E/'archive-parts.json').write_text(json.dumps({'archive':receipt['archive'],'parts':chunks},sort_keys=True,indent=2)+'\n')
for name in ('members.json','receipt.json','mac-readback.json'):
 value=(Q/name).read_bytes()
 (E/(name+'.gz' if name=='members.json' else name)).write_bytes(gzip.compress(value,mtime=0) if name=='members.json' else value)
M=E/'mac';M.mkdir()
selected=('default-install-v1','default-install-v2','default-install-v3','default-install-v4','default-slot-installed-controls-v1','default-install-complete-cas-v1')
physical={}
for d in selected:
 for p in sorted((R/d).iterdir()):
  if p.is_file() and p.name not in ('complete-physical.tar.gz','members.json'):
   dest=M/d/p.name;dest.parent.mkdir(parents=True,exist_ok=True);data=p.read_bytes();dest.write_bytes(data)
   physical[str(p.relative_to(R))]={'bytes':len(data),'sha256':sha256(data).hexdigest()}
for p in sorted(R.glob('*.py')):
 if 'default_install' in p.name or p.name=='run_slot_installed_control_v1.py':
  data=p.read_bytes();dest=M/'drivers'/p.name;dest.parent.mkdir(exist_ok=True);dest.write_bytes(data)
  physical[p.name]={'bytes':len(data),'sha256':sha256(data).hexdigest()}
p=Path('/Users/qianqi/.local/state/hepta-runtime-mac-worker/terminals/dpty-f172f3186df63156a69599716ab6f7517593e436f90922aff941ed036a14ad70/output.log');data=p.read_bytes();(M/'v3-first-launch-before-dispatch.stderr').write_bytes(data)
physical['v3-first-launch-before-dispatch.stderr']={'bytes':len(data),'sha256':sha256(data).hexdigest(),'exit_code':1,'native_dispatch':False,'reason':'__file__ absent in python -c; corrected to execute the prepared driver file'}
(E/'mac-originals.json').write_text(json.dumps(physical,sort_keys=True,indent=2)+'\n')
source_names=('hepta/hia_carrier_default.py','tools/install_hia_carrier_compat.py','tests/test_hia_carrier_default_install.py','hepta/hia_current_carrier_worker_bundle.py','hepta/hia_native_helpers.py','setup.py','tools/capture_hia_current_carrier_bundle.py','tools/capture_hia_native_carrier_bundle.py')
pins={name:{'bytes':len((S/name).read_bytes()),'sha256':sha256((S/name).read_bytes()).hexdigest()} for name in source_names}
(E/'source-registration.json').write_text(json.dumps({'schema':'hepta.host-source-registration.v1','parent':'918454d54f021495fce3743e8c841960dd986c10','new_host_paths':list(source_names[:3]),'changed_host_paths':list(source_names[3:]),'native_changed_paths':[],'source_pins':pins},sort_keys=True,indent=2)+'\n')
needed=('default-install-v4/installation/result.json','default-install-v4/qualification/result.json','default-install-v4/qualification/installed-controls/result.json','default-slot-installed-controls-v1/controls/result.json','default-slot-installed-controls-v1/terminal.json')
m=json.loads((Q/'members.json').read_bytes());byhash={m['entries'][name]['sha256']:name for name in needed}
with tarfile.open(archive,'r:gz') as tf:
 for member in tf:
  digest=member.name.removeprefix('blobs/')
  if digest in byhash:
   value=tf.extractfile(member).read();dest=E/'selected'/byhash[digest];dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(value)
for name in needed:assert (E/'selected'/name).is_file()
for name,expected in pins.items():assert len((S/name).read_bytes())==expected['bytes'] and sha256((S/name).read_bytes()).hexdigest()==expected['sha256']
print(json.dumps({'evidence':str(E),'source_files':len(pins),'archive':receipt['archive'],'entries':receipt['entries'],'unique_blobs':receipt['unique_blobs'],'new_host_paths':list(source_names[:3])}),flush=True)
