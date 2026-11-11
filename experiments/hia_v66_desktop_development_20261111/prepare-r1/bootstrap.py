"""Create one private development root, then exec the unchanged owned guardian."""
from hashlib import sha1,sha256
import json
import os
from pathlib import Path
import stat
import sys

os.umask(0o077)
raw_payload=sys.stdin.buffer.read(1048577)
assert len(raw_payload)<=1048576
payload=json.loads(raw_payload)
ROOT=Path('/home/qian-qi/he26v66devr1')
PYTHON=Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
B3=Path('/home/qian-qi/he26v65r2/q/cold.cold/qualification.evidence/B3.image.bin')
B3_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
required={
'prepare_development.py':'93ad9df23c46553455fdc2a152950606a716aad7bffcc76618a3120076f67015',
'old-input-pins.json':'f241c001230fc6c829ae583f27da9e1b1267a9675d6ed615911091bbafdb22f1',
'guardian.py':'d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
'process_owner_impl.py':'36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
'workflow_process.py':'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
'run_wire_r7_development_recovery.py':'d391b61f4023914155497449f57e42e24659f558ee82a414efe5d19a230812ee',
}
blobs={'generate_hia_json_wire.py':'f4e2648158896f26e46a2e8a7a0b22f94de50e7e',
       'test_hia_json_wire_native.py':'f4ece1f7d8e61d4e19c98b43a44843525a6b8eb8'}
assert payload['stable_key']=='hia-e26e-desktop-e09-development-prepare-r1'
assert payload['head']=='e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6'
assert payload['tree']=='bfcbb39e22371cbb2292c89a2fa1ca010353a56f'
assert set(payload['files'])==set(required)|{'bootstrap.py'}
assert set(payload['recovery'])==set(blobs)
assert not any(p.is_symlink()for p in (ROOT,*ROOT.parents))
assert not os.path.lexists(ROOT)
parent=ROOT.parent.lstat()
assert stat.S_ISDIR(parent.st_mode)and parent.st_uid==os.geteuid()and not parent.st_mode&0o022
capacity=os.statvfs(ROOT.parent)
assert capacity.f_bavail*capacity.f_frsize>=8<<30 and capacity.f_favail>=100000
for name,item in payload['files'].items():
    assert Path(name).name==name
    b=item['source'].encode()
    assert sha256(b).hexdigest()==item['sha256']
    if name in required:assert item['sha256']==required[name]
for name,item in payload['recovery'].items():
    b=item['source'].encode()
    assert sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==blobs[name]==item['blob_sha']
    assert sha256(b).hexdigest()==item['sha256']
pins=json.loads(payload['files']['old-input-pins.json']['source'])
for path,expected in pins.items():assert sha256(Path(path).read_bytes()).hexdigest()==expected
assert Path(sys.executable).resolve()==PYTHON.resolve()
assert sha256(PYTHON.read_bytes()).hexdigest()=='b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
old_b3=B3.lstat();assert stat.S_ISREG(old_b3.st_mode)and old_b3.st_uid==os.geteuid()and old_b3.st_nlink==1
compiler=B3.read_bytes();assert sha256(compiler).hexdigest()==B3_SHA
after_b3=B3.lstat();assert (old_b3.st_dev,old_b3.st_ino,old_b3.st_size,old_b3.st_mtime_ns,old_b3.st_ctime_ns)==(after_b3.st_dev,after_b3.st_ino,after_b3.st_size,after_b3.st_mtime_ns,after_b3.st_ctime_ns)
ROOT.mkdir(mode=0o700)
directories=['control','guard','inputs','preparation-logs','evidence','recovery','recovery/r7-candidate','wire-r7','cli']
for name in directories:(ROOT/name).mkdir(mode=0o700)

def create(path,data,mode=0o400):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'wb')as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    assert path.read_bytes()==data

identities=dict(pins)
identities[str(B3)]=B3_SHA
identities[str(ROOT/'inputs/B3.image.bin')]=B3_SHA
create(ROOT/'inputs/B3.image.bin',compiler)
for name,item in payload['files'].items():
    path=ROOT/'control'/name;create(path,item['source'].encode());identities[str(path)]=item['sha256']
for name,item in payload['recovery'].items():
    path=ROOT/'recovery/r7-candidate'/name;create(path,item['source'].encode());identities[str(path)]=item['sha256']
recovery={'schema':'hia.remote-wire-r7-candidate-custody.v1','scope':'NEW_REMOTE_CANDIDATE_NOT_ORIGINAL_LOCAL_R7_RECOVERY',
          'source_commit':'aef3b5813aa49b2356fbd4dd7314e40737b3e4cf',
          'files':{name:{'sha256':item['sha256'],'git_blob':item['blob_sha']}for name,item in payload['recovery'].items()},
          'whole_native_delivery_qualified':False}
create(ROOT/'recovery/r7-candidate/MANIFEST.json',(json.dumps(recovery,indent=2,sort_keys=True)+'\n').encode())
config={'schema':'hia-external-guardian-request.v1','controller_seconds':1800,
        'command':[str(PYTHON),'-B',str(ROOT/'control/prepare_development.py')],
        'cwd':str(ROOT),'source_identities':identities}
raw=(json.dumps(config,indent=2,sort_keys=True)+'\n').encode()
create(ROOT/'guard/request.json',raw)
intent={'schema':'hia.desktop-development-preparation-intent.v1','stable_key':payload['stable_key'],
        'head':payload['head'],'tree':payload['tree'],'root':str(ROOT),'source':str(ROOT/'s'),
        'wire_candidate_source':str(ROOT/'wire-r7/s'),'cli_candidate_source':str(ROOT/'cli/s'),
        'capacity_before':{'available_bytes':capacity.f_bavail*capacity.f_frsize,'free_inodes':capacity.f_favail},
        'control_files':{name:item['sha256']for name,item in payload['files'].items()},
        'recovery_files':recovery['files'],'tests_requested':False,'qualification_requested':False,
        'final_full_root_touched':False,'whole_native_delivery_qualified':False,
        'outer_guardian_acceptance_required':True,
        'hard_sigkill_or_host_loss_cleanup_claimed':False}
create(ROOT/'launch-intent.json',(json.dumps(intent,indent=2,sort_keys=True)+'\n').encode())
for path in [ROOT/name for name in reversed(directories)]+[ROOT,ROOT.parent]:
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print(json.dumps({'stage':'DEVELOPMENT_PREPARATION_GUARDIAN_LAUNCH','root':str(ROOT),'controller_seconds':1800}),flush=True)
os.execv(str(PYTHON),[str(PYTHON),'-B',str(ROOT/'control/guardian.py'),
         '--config',str(ROOT/'guard/request.json'),'--config-sha256',sha256(raw).hexdigest(),
         '--implementation',str(ROOT/'control/process_owner_impl.py')])
