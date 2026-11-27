import ast,hashlib,json,os,sys
from pathlib import Path
r=Path('/tmp/hia-op13-terminal-reader-draft-r1-dda7')
old=Path('/tmp/hia-op13-binding-readback-draft-r3-dda7/verify_binding.py')
p=r/'verify_terminal.py';b=p.read_bytes();q=r/'READBACK-PLAN.json';plan=q.read_bytes()
assert len(b)==37605 and hashlib.sha256(b).hexdigest()=='41b1acc5eb322534a0e9a8b8215c9ec432d85676253afd6d80740aadcdf105ae'
assert len(plan)==5540 and hashlib.sha256(plan).hexdigest()=='b45e89d0b3c2f265a148a0054cad8d3464f617a423ec45b7e5a1de9843dc087e'
raw=old.read_bytes()
assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()=='4a0e30a44c9cf2150c420b273f46de951abd238e'
before={x.name:ast.get_source_segment(raw.decode(),x) for x in ast.parse(raw).body if isinstance(x,ast.FunctionDef)}
after={x.name:ast.get_source_segment(b.decode(),x) for x in ast.parse(b).body if isinstance(x,ast.FunctionDef)}
names=('require','seven','pin','pairs','decode','read','fixed','inventory','parents','tree','directory_chain','guard_chain','runtime_record','write')
assert all(before[n]==after[n] for n in names)
out=Path('/tmp/hia-op13-terminal-readback-actual-r1-dda7')
assert not out.exists()
os.execv(sys.executable,[sys.executable,'-I','-B',str(p),'--plan',str(q),'--plan-sha256','b45e89d0b3c2f265a148a0054cad8d3464f617a423ec45b7e5a1de9843dc087e','--output',str(out)])
