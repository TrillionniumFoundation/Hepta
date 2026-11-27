"""Read all actual Git text responses and decode exact author/failure payloads only."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-publication-r2-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def seven(s):return {k:getattr(s,k)for k in FIELDS}
rows=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes());actual={}
assert len(rows)==13
for i,row in enumerate(rows):
 tag='%03d'%i;ack=json.loads((ROOT/'actual-git'/f'{tag}-ACK.json').read_bytes());receipt=json.loads((ROOT/'actual-git'/f'{tag}-VERIFIED.json').read_bytes());raw=(ROOT/'actual-git'/f'{tag}-GET.txt').read_bytes()
 assert ack['sha']==receipt['sha']==row['git_blob']and receipt['full_get_exact']is True
 assert raw==row['text'].encode()and pin(raw)=={k:row[k]for k in('bytes','sha256','git_blob')}
 actual[row['name']]=raw
capsule=json.loads(actual['custody/AUTHORING-CAPSULE.json']);compressed=base64.b64decode(capsule['data'],validate=True)
assert pin(compressed)==capsule['compressed']
decoder=zlib.decompressobj();payload=decoder.decompress(compressed)+decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(payload)==capsule['payload']
restored=json.loads(payload);assert len(restored['files'])==32
for row in restored['files']:
 p=Path(row['source_path']);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and seven(s)==row['stat']==seven(p.lstat())
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(s.st_size+1)
  assert raw==row['text'].encode()and pin(raw)==row['pin']and stat.S_IMODE(s.st_mode)==row['mode']
  assert seven(os.fstat(fd))==row['stat']==seven(p.lstat())
 finally:os.close(fd)
for role,r in restored['directories'].items():
 p=Path(r['path']);assert seven(p.lstat())==r['stat']
 assert sorted(x.name for x in p.iterdir())==(['STAGES.json']if role=='actual-r1'else[])
for revision in('r1','r2'):
 members=[r for r in restored['files']if r['name'].startswith('author-'+revision+'/')]
 root=Path(members[0]['source_path']).parent
 assert sorted(p.name for p in root.iterdir())==sorted(r['name'].split('/',1)[1]for r in members)
report={'status':'PASS_ACTUAL_GIT_FULL_GET_COMPLETE_AUTHOR_AND_FAILURE_DECODE',
 'full_get_leaves':len(rows),'full_get_bytes':sum(r['bytes']for r in rows),'restored_files':len(restored['files']),
 'logical_bytes':sum(r['pin']['bytes']for r in restored['files']),'all_bytes_modes_seven_stats_equal':True,
 'complete_zlib':True,'capsule':pin(actual['custody/AUTHORING-CAPSULE.json']),
 'r1_actual_exit':137,'r2_actual_exit':137,'r2_output_pathset':[],
 'termination_cause_proven':False,'reader_execution':0,'products':0,'source_copy':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
with (ROOT/'ACTUAL-GIT-READBACK.json').open('xb')as f:f.write(raw)
assert (ROOT/'ACTUAL-GIT-READBACK.json').read_bytes()==raw
print(json.dumps(report,sort_keys=True))
