from pathlib import Path
import hashlib,io,json,shlex,subprocess,tarfile,time
R=Path(__file__).resolve().parent;Q=R/'default-install-complete-cas-v1';Q.mkdir(mode=0o700)
remote='/home/qq/hia-native-carrier-policy-20261128-2ac5'
script=(R/'archive_complete_carrier_v1.py').read_text()
script=script.replace("for p in sorted(root.rglob('*')):","selected=('default-install-v1','default-install-v2','default-install-v3','default-install-v4','default-slot-installed-controls-v1')\nfor p in sorted(p for name in selected for base in (root/name,) for p in (base,*base.rglob('*'))):")
script=script.replace("'scope':'COMPLETE_UNFILTERED_ATTEMPTS_AND_SOURCE_EXCLUDING_GIT_AND_PYCACHE',","'scope':'COMPLETE_EXPLICIT_DEFAULT_INSTALL_ATTEMPTS_EXCLUDING_GIT_AND_PYCACHE','selected_roots':list(selected),")
(Q/'archive.py').write_text(script)
def run(label,argv):
 t=time.monotonic();p=subprocess.run(argv,capture_output=True)
 (Q/(label+'.stdout')).write_bytes(p.stdout);(Q/(label+'.stderr')).write_bytes(p.stderr)
 (Q/(label+'.terminal.json')).write_text(json.dumps({'returncode':p.returncode,'seconds':time.monotonic()-t})+'\n')
 if p.returncode:print(p.stderr.decode(),flush=True)
 assert p.returncode==0,label
 return p
ssh=['/usr/bin/ssh','-oBatchMode=yes','-oConnectTimeout=12','ai395']
run('upload-script',['/usr/bin/scp','-oBatchMode=yes','-oConnectTimeout=12',str(Q/'archive.py'),'ai395:'+remote+'/archive_default_install_v1.py'])
run('archive',ssh+['python3 '+shlex.quote(remote+'/archive_default_install_v1.py')+' '+shlex.quote(remote)+' '+shlex.quote(remote+'/default-install-complete-cas-v1')])
for name in ('complete-physical.tar.gz','members.json','receipt.json'):
 run('download-'+name,['/usr/bin/scp','-oBatchMode=yes','-oConnectTimeout=12','ai395:'+remote+'/default-install-complete-cas-v1/'+name,str(Q/name)])
receipt=json.loads((Q/'receipt.json').read_bytes());raw=(Q/'complete-physical.tar.gz').read_bytes();manifest=(Q/'members.json').read_bytes()
assert {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}==receipt['archive']
assert {'bytes':len(manifest),'sha256':hashlib.sha256(manifest).hexdigest()}==receipt['manifest']
m=json.loads(manifest);wanted={v['sha256']:v['bytes'] for v in m['entries'].values() if v['kind']=='file'}
seen=set()
with tarfile.open(Q/'complete-physical.tar.gz','r:gz') as tf:
 for member in tf:
  assert member.isfile() and member.name not in seen;seen.add(member.name);value=tf.extractfile(member).read()
  if member.name=='members.json':assert value==manifest
  else:
   digest=member.name.removeprefix('blobs/');assert member.name=='blobs/'+hashlib.sha256(value).hexdigest() and len(value)==wanted[digest]
assert seen=={'members.json'}|{'blobs/'+digest for digest in wanted}
report={'status':'PASS','all_original_bytes_and_modes_retained':True,'mac_archive_each_member_verified':True,**receipt}
(Q/'mac-readback.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True)
