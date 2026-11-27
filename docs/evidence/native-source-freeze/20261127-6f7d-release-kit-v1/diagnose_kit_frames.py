from pathlib import Path
import json,hashlib,os,fcntl,subprocess,struct
R=Path('/home/qian-qi/hia-native-cold-edge-6f7d-20261127-2ac5');S=R/'source';D=R/'release-lease-kit-diagnostic-v1';D.mkdir(mode=0o700)
receipt=json.loads((S/'docs/HIA_NATIVE_GENERATION_LEASE_RELEASE_BUILD.json').read_bytes());pins=json.loads((R/'chain/cold/final-cold.json').read_bytes())['source_manifest']
composer=(R/'release-frontend-diagnostic-v1/composer-pack.stdout').read_bytes()
fd=os.memfd_create('original-composer',os.MFD_ALLOW_SEALING);os.write(fd,composer);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
report={'scope':'actual native kit frame versus authenticated executable-body identities','calls':[]}
for kind,packer in [('small','native_filter_packer.hepta'),('wide','native_controller_filter_packer.hepta')]:
 wire=bytearray(struct.pack('<8sQ',b'HIAKOBJ1',3))
 for alias,name in zip(['source_build_policy.hepta','selfhost.hepta','source_build_packer.hepta'],['source_native_filter_pack.hepta','selfhost.hepta',packer]):
  path='examples/hia_bootstrap/'+name;b=(S/path).read_bytes();assert hashlib.sha256(b).hexdigest()==pins[path];a=alias.encode();wire+=struct.pack('<2Q',len(a),len(b))+a+b
 (D/(kind+'.input')).write_bytes(wire)
 p=subprocess.run(['/proc/self/fd/'+str(fd),'build'],pass_fds=(fd,),input=wire,capture_output=True,env={'PATH':''},timeout=60)
 (D/(kind+'.stdout')).write_bytes(p.stdout);(D/(kind+'.stderr')).write_bytes(p.stderr)
 assert p.returncode==0 and not p.stderr
 frame=p.stdout;footer=struct.unpack('<7Q8s',frame[-64:]);body=frame[:footer[0]]
 row={'kind':kind,'returncode':p.returncode,'frame_bytes':len(frame),'frame_sha256':hashlib.sha256(frame).hexdigest(),'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'footer':list(footer[:-1])+[footer[-1].decode()],'expected':receipt['kits'][kind]}
 row['body_matches_frozen']=row['expected']=={'bytes':len(body),'sha256':row['body_sha256']};report['calls'].append(row)
print(json.dumps(report,indent=2));(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
p=S/'tools/generate_hia_native_controller_release.py';lines=p.read_text().splitlines()
for i,l in enumerate(lines):
 if l.startswith('    def checked_kit') or l.startswith('    def length') or l.startswith('    def slice') or l.startswith('    def native_filter') or l.startswith('    def run'):
  print('SOURCE',i+1);print('\n'.join(lines[i:i+40]))
