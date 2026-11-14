"""Read back draft text, not execute the read-only preflight itself."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
R=Path(__file__).absolute().parent
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),mode='100644',git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),sha256=hashlib.sha256(b).hexdigest())
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def put(n,v):
 b=enc(v)
 with (R/n).open('xb') as f:f.write(b)
 return dict(file=n,pin=pin(b))
rows=json.loads((R/'PUBLICATION-INPUTS.json').read_bytes());values={}
for row in rows:
 post=json.loads((R/'GIT-ACK'/(row['file']+'.POST.json')).read_bytes());get=json.loads((R/'GIT-ACK'/(row['file']+'.GET.json')).read_bytes())
 assert not post.get('isError') and not get.get('isError') and post['structuredContent']['sha']==row['pin']['git_blob']
 b=get['structuredContent']['content'].encode();assert pin(b)==row['pin'] and b==(R/row['file']).read_bytes();values[row['file']]=json.loads(b)
cap=values['SOURCE-CAPSULE.json'];z=base64.b64decode(cap['data'],validate=True);assert pin(z)==cap['compressed_pin']
raw=zlib.decompress(z);assert pin(raw)==cap['payload_pin'];p=json.loads(raw);assert len(p['files'])==9
by={}
for row in p['files']:
 b=row['text'].encode();assert pin(b)==row['pin'];path=Path(row['path']);s=path.lstat();current=path.read_bytes();t=path.lstat()
 assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==row['posix_mode'] and b==current and seven(s)==seven(t)==row['seven_stats'];by[row['logical']]=b
proj=json.loads(by['PREFLIGHT-PROJECTION.json']);a=by['before/verify_inspect_cli_r4_preflight.py'].decode().splitlines(keepends=True);b=by['verify_inspect_cli_r5_preflight.py'].decode().splitlines(keepends=True)
forward=list(a)
for row in reversed(proj['segments']):
 x,y=row['old_range'];assert forward[x:y]==row['before'];forward[x:y]=row['after']
inverse=list(b)
for row in reversed(proj['segments']):
 x,y=row['new_range'];assert inverse[x:y]==row['after'];inverse[x:y]=row['before']
assert forward==b and inverse==a
proof=dict(status='PASS_ACTUAL_GIT_AUTHOR_TEXT_READBACK',files=9,actual_ack_full_get_blobs=2,payload_pin=cap['payload_pin'],all_nine_current_bytes_modes_seven_stats_equal=True,complete_preflight_text_forward_and_inverse_equal=True,this_agent_preflight_executions=0,product_executions=0,binder_executions=0,source_copies=0)
pr=put('ACTUAL-GIT-READBACK.json',proof);script=dict(file='readback_actual_git.py',pin=pin(Path(__file__).read_bytes()))
recipe=dict(schema='hepta.immutable-git-recipe.v1',repository='TrillionniumFoundation/Hepta',scope='R5 independent read-only preflight draft only; not executed by its author',leaves=rows+[script,pr],complete_author_files=9,root_preflight_preimage='6831d58bb278b9bf42e6c9e99ee971b62dc010e8',metadata_authority='196d623ba33a6f45bc1f594c8c5b53df06e23f3b',new_draft=pin(by['verify_inspect_cli_r5_preflight.py']),complete_diff=pin(by['PREFLIGHT.diff']),launch=pin(by['READONLY-LAUNCH.json']),readback=proof)
rr=put('MOUNT-RECIPE.json',recipe);put('FOLLOWUP-PUBLICATION-INPUTS.json',[script,pr,rr])
print(json.dumps(dict(proof=pr,recipe=rr),sort_keys=True))
