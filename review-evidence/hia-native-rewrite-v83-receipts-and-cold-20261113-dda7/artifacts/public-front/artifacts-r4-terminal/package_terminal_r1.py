from pathlib import Path
import hashlib,json,os,tarfile,io,stat,time,shutil
BASE=Path('/workspace/scratch/dda74a4fae35/v82-service-artifacts-development-r4/ci-r1')
OUT=BASE/'terminal-custody-r1'
OUT.mkdir(exist_ok=False)
START=time.time_ns()
names=[
'actual314-r1/COMPLETE-RAW.zip','actual314-r1/COMPLETE-INTEGRITY.json','actual314-r1/DOWNLOAD.json','actual314-r1/VERIFICATION.json','actual314-r1/ACTUAL-SUMMARY.json','actual314-r1/JOB.log','actual314-r1/VERIFY-R1.stdout','actual314-r1/VERIFY-R1.stderr',
'actual-source314-r1/COMPLETE-RAW.zip','actual-source314-r1/COMPLETE-INTEGRITY.json','actual-source314-r1/DOWNLOAD.json','actual-source314-r1/VERIFICATION.json','actual-source314-r1/ACTUAL-SUMMARY.json','actual-source314-r1/JOB.log','actual-source314-r1/VERIFY-R1.stdout','actual-source314-r1/VERIFY-R1.stderr',
'normal-core-original-r1/archive/original-artifact.zip','normal-core-original-r1/archive/DOWNLOAD.json','normal-core-original-r1/MEMBERS.json','normal-core-original-r1/VERIFICATION.json','normal-core-original-r1/JOB-native.log','normal-core-original-r1/JOB-source.log','normal-core-original-r1/VERIFY-R1.stdout','normal-core-original-r1/VERIFY-R1.stderr',
'ACTUAL-TERMINAL-ADDENDUM.json','TERMINAL-AUTHORITY-R2.json','ORIGINAL-AUTHORITY-R1.json','PUBLICATION-MANIFEST.json','download_original.py','verify_original.py','verify_original_r2.py','summarize_actual_r4.py','verify_normal_core_r4.py'
]
def identity(path):
 h=hashlib.sha256(); size=path.stat().st_size; g=hashlib.sha1(('blob '+str(size)+'\0').encode())
 with path.open('rb') as f:
  while data:=f.read(1<<20): h.update(data);g.update(data)
 return {'bytes':size,'sha256':h.hexdigest(),'git_blob':g.hexdigest(),'mode':format(stat.S_IMODE(path.stat().st_mode),'04o')}
files={name:identity(BASE/name) for name in names}
assert files['actual314-r1/COMPLETE-RAW.zip']['sha256']=='05d6ae68afecb1ded99f0ee90913f829f535b8d46639fdb38bbc5e9305e260d5'
assert files['actual-source314-r1/COMPLETE-RAW.zip']['sha256']=='c2d770bc1e84b044cb31624742efc420c116a21c0b6069ec2e041221aaf7dbed'
assert files['normal-core-original-r1/archive/original-artifact.zip']['sha256']=='5caf060da0c522d5813df23f678385eb48c201f9363cdd0a196740d33f712231'
manifest={
 'schema':'hia.artifacts-r4.complete-terminal-custody.v1',
 'repository':'TrillionniumFoundation/Hepta',
 'source':{'head':'1cd416ab028a4c59ac76bf4b8e2c4018fb552d9d','tree':'eca3dd8ba5067d77fb56454ee354bd0eddb9cfe9','files':3306},
 'runs':{'development':43328942162,'normal_core':43330392476},
 'scope':{'new_business_execution':False,'current_cold':False,'whole_native':False,'all_failures_preserved':True},
 'complete_original_binary_members':{
  'actual314-r1/COMPLETE-RAW.zip':{'original_members':259,'all_original_inner_members_preserved':True},
  'actual-source314-r1/COMPLETE-RAW.zip':{'original_members':500,'all_original_inner_members_preserved':True},
  'normal-core-original-r1/archive/original-artifact.zip':{'original_members':6658,'complete_original_actions_outer_zip':True}
 },
 'other_whole_outer_zips':{
  'actual311':{'bytes':72406030,'sha256':'4da0cee4509c3791790faa42466b2a2fcc47345483377b77fc27fff66735f00d','custody':'local unique ZIP plus Actions retained; complete raw subset separately Git preserved','raw_transport_index':'99731e3a87f8db93589ab404280a08437581f45c'},
  'actual314':{'bytes':83610401,'sha256':'993f6a01be8d6a743b8fb7ddb8e3e80e777e3d3fc3aa6bffa1801b280a3bf345','custody':'local unique ZIP plus Actions retained; complete 259 raw members included here'},
  'actual_source314':{'bytes':122890709,'sha256':'1f4ffe788e59a787865968fd53557b0b7666313fc0aea94f4f7b9f5acc48670e','custody':'local unique ZIP plus Actions retained; complete 500 raw members included here'}
 },
 'files':files
}
raw=(json.dumps(manifest,ensure_ascii=True,indent=2,sort_keys=True)+'\n').encode()
(OUT/'MANIFEST.json').write_bytes(raw)
archive=OUT/'COMPLETE-TERMINAL.tar.xz'
with tarfile.open(archive,'w:xz',preset=3,format=tarfile.PAX_FORMAT) as t:
 for name in names:
  info=tarfile.TarInfo(name);info.size=files[name]['bytes'];info.mode=int(files[name]['mode'],8);info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=''
  with (BASE/name).open('rb') as f:t.addfile(info,f)
 info=tarfile.TarInfo('MANIFEST.json');info.size=len(raw);info.mode=0o644;info.mtime=0;t.addfile(info,io.BytesIO(raw))
seen=[]
with tarfile.open(archive,'r:xz') as t:
 for m in t:
  f=t.extractfile(m);assert f is not None
  h=hashlib.sha256();g=hashlib.sha1(('blob '+str(m.size)+'\0').encode());size=0
  while data:=f.read(1<<20):h.update(data);g.update(data);size+=len(data)
  if m.name=='MANIFEST.json':assert size==len(raw) and h.hexdigest()==hashlib.sha256(raw).hexdigest()
  else:
   expected=files[m.name]
   assert size==expected['bytes'] and h.hexdigest()==expected['sha256'] and g.hexdigest()==expected['git_blob'] and m.mode==int(expected['mode'],8)
   seen.append(m.name)
assert seen==names
for name in names:assert identity(BASE/name)==files[name]
receipt={'schema':'hia.complete-terminal-custody.receipt.v1','archive':identity(archive),'manifest':identity(OUT/'MANIFEST.json'),'members':len(names)+1,'source_members':len(names),'source_bytes':sum(x['bytes'] for x in files.values()),'all_archive_members_verified':True,'all_source_inputs_after_equal':True,'elapsed_ns':time.time_ns()-START,'free_after':shutil.disk_usage(BASE).free,'scope':manifest['scope']}
(OUT/'RECEIPT.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(receipt,sort_keys=True))

