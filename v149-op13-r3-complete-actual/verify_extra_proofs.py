"""Read only the small additional proof leaves; original archive is not rerun."""
from pathlib import Path
import hashlib,json,stat
ROOT=Path('/tmp/hia-op13-actual-transport-r3-dda7')
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b):
 return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def full(p,expected,mode):
 p=Path(p);s=p.lstat();before=[getattr(s,k) for k in KEYS]
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode
 b=p.read_bytes();assert [getattr(p.lstat(),k) for k in KEYS]==before and pin(b)==expected
 return b,before
rows=json.loads((ROOT/'FINAL-PROOF-INPUTS.json').read_bytes());assert len(rows)==19
observed=[]
for offset,row in enumerate(rows):
 i=275+offset;raw,s=full(row['path'],row['pin'],row['mode'])
 got,t=full(ROOT/'actual-get'/row['logical'],row['pin'],row['mode']);assert got==raw
 receipt=json.loads((ROOT/'receipts'/('%03d.json'%i)).read_bytes())
 post=json.loads((ROOT/'tool-envelopes'/('%03d.POST.json'%i)).read_bytes())
 fetched=json.loads((ROOT/'tool-envelopes'/('%03d.GET.json'%i)).read_bytes())
 assert receipt['index']==i and receipt['logical']==row['logical'] and receipt['pin']==row['pin']
 assert receipt['post_ack_git']==post['structuredContent']['sha']==row['pin']['git_blob'] and receipt['full_get_equal'] is True
 assert fetched['structuredContent']['content'].encode()==raw
 observed.append({'index':i,'logical':row['logical'],'identity':row['pin'],'original_seven_stats':s,'actual_get_seven_stats':t,'actual_POST_and_full_GET':True})
result={'schema':'hepta.op13.actual.r3.extra-proof-readback.v1','status':'PASS_EXTRA_PROOF_FULL_BYTES_AND_ACTUAL_API_ENVELOPES','proof_leaves':19,'files':observed,'product_executions':0,'original_archive_decode_repeated':False,'seal_rerun':0}
with (ROOT/'EXTRA-PROOF-READBACK.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'status':result['status'],'proof_leaves':19,'products':0}))
