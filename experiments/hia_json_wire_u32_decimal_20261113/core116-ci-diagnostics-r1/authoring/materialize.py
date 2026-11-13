"""Create-only static custody controls; never import or execute their code."""
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat

CONFIG=Path("/home/qq/hia-rewrite-20261113-e26e-r1/wire-u32-ci-core116-diagnostics-r1-MATERIALIZE-CONFIG.json")
CONFIG_SHA="2aecfb9c7c3e236f188281ec45aa9a707f926fe02e184aa0c983ec0d4942e826"
ROOT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/wire-u32-ci-core116-diagnostics-r1")
raw=CONFIG.read_bytes()
assert hashlib.sha256(raw).hexdigest()==CONFIG_SHA
cfg=json.loads(raw)
assert cfg['root']==str(ROOT) and cfg['schema']=='hia.u32-diagnostics-static-materialization.v1'
assert not ROOT.exists()
ROOT.mkdir(mode=0o700)
def create(path, data):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    assert path.read_bytes()==data
    return {'path':str(path.relative_to(ROOT)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'posix_mode':stat.S_IMODE(path.stat().st_mode),'git_mode':'100644'}
rows=[]
names=set()
for item in cfg['files']:
    name=item['path']
    assert name not in names and name and not name.startswith('/') and '..' not in name.split('/')
    names.add(name)
    body=item['text'].encode()
    assert len(body)==item['bytes'] and hashlib.sha256(body).hexdigest()==item['sha256']
    row=create(ROOT/name,body)
    assert row['git_blob']==item['git_blob']
    rows.append(row)
delta=json.loads((ROOT/'CONTROL-DELTA.json').read_bytes())
diff=[]
for item in delta['changes']:
    name=item['file']
    old=(ROOT/'reference/donor'/name).read_text()
    new=(ROOT/name).read_text()
    reverse=new
    for sub in reversed(item['replacements']):
        assert reverse.count(sub['to'])==sub['count']
        reverse=reverse.replace(sub['to'],sub['from'])
    assert reverse==old
    diff.extend(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='a/'+name,tofile='b/'+name,n=3))
rows.append(create(ROOT/'CONTROL-DELTA.patch',''.join(diff).encode()))
parsed=[]
for name in ('controller.py','worker.py','diagnostics.py','original_receiver.py','guardian.py','process_owner_impl.py','render_workflow.py'):
    ast.parse((ROOT/name).read_bytes(),filename=str(ROOT/name))
    parsed.append(name)
policy=json.loads((ROOT/'policy.json').read_bytes())
request=json.loads((ROOT/'REQUEST.json').read_bytes())
assert policy['control_files']==request['control_files']
assert policy['artifact']==request['original_artifact']
for name,pin in policy['control_files'].items():
    body=(ROOT/name).read_bytes()
    assert len(body)==pin['bytes'] and hashlib.sha256(body).hexdigest()==pin['sha256']
assert policy['artifact']['run_attempt']==1 and policy['artifact']['id']==14063258783
assert policy['limits']['controller_seconds']==900 and policy['limits']['cleanup_seconds']==3
assert policy['limits']['transfer_seconds']==720 and policy['limits']['maximum_original_bytes']==3<<30
assert policy['diagnostics']['maximum_selected_file_bytes']==64<<20
assert policy['diagnostics']['maximum_selected_bytes']==128<<20
assert policy['diagnostics']['maximum_public_small_bytes']==224<<20
report={'schema':'hia.u32-diagnostics-static-materialize-readback.v1','status':'STATIC_FILES_CREATED_NOT_EXECUTED','root':str(ROOT),'config_sha256':CONFIG_SHA,'files':rows,'file_count':len(rows),'total_bytes':sum(x['bytes'] for x in rows),'ast_parse_only':parsed,'exact_inverse_complete':True,'new_original_GETs':0,'new_product_executions':0,'new_receiver_executions':0,'ref_created':False,'workflow_triggered':False}
create(ROOT/'MATERIALIZE-READBACK.json',(json.dumps(report,indent=2,sort_keys=True)+'\n').encode())
print(json.dumps({'status':report['status'],'files':len(rows),'total_bytes':report['total_bytes'],'readback':str(ROOT/'MATERIALIZE-READBACK.json')},sort_keys=True))
