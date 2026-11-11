import hashlib, json, os
from pathlib import Path
import sys
PYTHON_SHA='b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
OWNER_SHA='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
GUARDIAN_SHA='d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
request=json.load(sys.stdin)
root=Path(request['root'])
if not root.is_absolute() or root.parent != Path('/home/qian-qi') or root.name != 'he26corelowering-authoring-r2':
    raise RuntimeError('unexpected fresh Core authoring root')
actual_python=Path(sys.executable).resolve()
if hashlib.sha256(actual_python.read_bytes()).hexdigest()!=PYTHON_SHA:
    raise RuntimeError('actual Python identity differs')
os.umask(0o077)
root.mkdir(mode=0o700)
control=root/'control'
guard=root/'guard'
control.mkdir(mode=0o700)
guard.mkdir(mode=0o700)
identities={str(actual_python):PYTHON_SHA}
for name in ('guardian.py','process_owner_impl.py','authoring.py'):
    item=request['controls'][name]
    raw=item['content'].encode('utf-8')
    actual=hashlib.sha256(raw).hexdigest()
    if actual!=item['sha256'] or len(raw)!=item['size']:
        raise RuntimeError('control payload differs: '+name)
    path=control/name
    with path.open('xb') as stream: stream.write(raw)
    identities[str(path)]=actual
if identities[str(control/'guardian.py')]!=GUARDIAN_SHA or identities[str(control/'process_owner_impl.py')]!=OWNER_SHA:
    raise RuntimeError('original external guardian bytes differ')
payload=(json.dumps(request['inputs'],indent=2,sort_keys=True)+'\n').encode()
path=control/'SOURCE-INPUTS.json'
with path.open('xb') as stream: stream.write(payload)
identities[str(path)]=hashlib.sha256(payload).hexdigest()
for name in tuple(os.environ):
    if name.startswith('HEPTA_HIA_') or name=='PYTHONPATH':
        del os.environ[name]
os.environ['PYTHONDONTWRITEBYTECODE']='1'
os.environ['PYTHONUNBUFFERED']='1'
configuration={
    'schema':'hia-external-guardian-request.v1',
    'controller_seconds':180,
    'command':[sys.executable,'-B',str(control/'authoring.py'),'--root',str(root)],
    'cwd':str(root),
    'source_identities':identities,
}
raw=(json.dumps(configuration,indent=2,sort_keys=True)+'\n').encode()
path=guard/'request.json'
with path.open('xb') as stream: stream.write(raw)
fingerprint=hashlib.sha256(raw).hexdigest()
print(json.dumps({'stage':'CORE_LOWERING_AUTHORING_GUARDIAN_ONLY','root':str(root),
                  'configuration_sha256':fingerprint,'source_candidate':request['inputs']['canonical_candidate'],
                  'native_execution_requested':False}),flush=True)
os.execv(sys.executable,[sys.executable,'-B',str(control/'guardian.py'),
         '--config',str(path),'--config-sha256',fingerprint,
         '--implementation',str(control/'process_owner_impl.py')])
