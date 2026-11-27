import hashlib,json,os,sys
from pathlib import Path
old=Path('/tmp/hia-op13-terminal-reader-draft-r1-dda7')
r=Path('/tmp/hia-op13-terminal-reader-draft-r2-dda7')
def git(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
a=(old/'verify_terminal.py').read_bytes();b=(r/'verify_terminal.py').read_bytes()
assert git(a)=='e591c788b6a4a11d384091323fa184e5c6a84bcd'
assert len(b)==38176 and git(b)=='6f1a454726ddafd32438e255e2add7d2e65800b3'
assert hashlib.sha256(b).hexdigest()=='b2b098c008483314d288500bfb43de5705d8e94a33f01f1728ed99478ecf83ab'
inverse=json.loads((r/'EXACT-INVERSE.json').read_bytes())
back=b
for c in inverse['changes']:
 x,y=c['after'].encode(),c['before'].encode()
 assert back.count(x)==1;back=back.replace(x,y)
assert back==a and len(inverse['changes'])==2
plan=(r/'READBACK-PLAN.json').read_bytes()
assert len(plan)==7190 and hashlib.sha256(plan).hexdigest()=='b1aa727145ce53d95f5259802f5110c85d75bb9ce5f3555499f89ce121392d41'
p=json.loads(plan);q=json.loads((old/'READBACK-PLAN.json').read_bytes())
assert p['root_metadata'][:len(q['root_metadata'])]==q['root_metadata']
assert len(p['root_metadata'])==len(q['root_metadata'])+3
for k in q:
 if k not in ('reader','root_metadata'):assert p[k]==q[k],k
assert p['reader']['pin']['git_blob']==git(b)
out=Path('/tmp/hia-op13-terminal-readback-actual-r2-dda7');assert not out.exists()
os.execv(sys.executable,[sys.executable,'-I','-B',str(r/'verify_terminal.py'),'--plan',str(r/'READBACK-PLAN.json'),'--plan-sha256','b1aa727145ce53d95f5259802f5110c85d75bb9ce5f3555499f89ce121392d41','--output',str(out)])
