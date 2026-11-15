from pathlib import Path
import ast,hashlib,json
R=Path('/tmp/hia-progress-v152-20261115-dda7')
O=R/'launch_r11_predicate_r1.py'
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
old=O.read_bytes();new=old;edits=[]
def change(a,b):
 global new
 a=a.encode()if isinstance(a,str)else a;b=b.encode()if isinstance(b,str)else b
 positions=[];cursor=0
 while True:
  at=new.find(a,cursor)
  if at<0:break
  positions.append(at);cursor=at+len(a)
 assert positions,a
 for at in reversed(positions):
  assert new[at:at+len(a)]==a;new=new[:at]+b+new[at+len(a):];edits.append({'at':at,'before':a.decode(),'after':b.decode()})
def line(prefix,replacement):
 rows=[x for x in new.decode().splitlines(keepends=True)if x.startswith(prefix)]
 assert len(rows)==1;change(rows[0],replacement+'\n')
review=(R/'R12-ORDERED-BOUNDARY-ROOT-REVIEW.json').read_bytes()
launch=Path('/tmp/hia-r12-ordered-read-controls-author-r1-dda7/LAUNCH.json').read_bytes()
assert json.loads(review)['status']=='PASS_ROOT_STATIC_R12_ORDERED_READ_BOUNDARY_AUTHOR_ONLY'
change('/tmp/hia-r11-predicate-controls-author-r1-dda7/LAUNCH.json','/tmp/hia-r12-ordered-read-controls-author-r1-dda7/LAUNCH.json')
change('/tmp/hia-r11-predicate-controls-outer-r1-dda7','/tmp/hia-r12-ordered-read-controls-outer-r1-dda7')
line('    assert pin(launch_raw)==','    assert pin(launch_raw)=='+repr(pin(launch)))
change('R11-PREDICATE-R2-ROOT-REVIEW.json','R12-ORDERED-BOUNDARY-ROOT-REVIEW.json')
line('    assert pin(read(BASE/','    assert pin(read(BASE/"R12-ORDERED-BOUNDARY-ROOT-REVIEW.json")[0])=='+repr(pin(review)))
change('PASS_ROOT_STATIC_R11_PREDICATE_BOUNDARY_AUTHOR_ONLY','PASS_ROOT_STATIC_R12_ORDERED_READ_BOUNDARY_AUTHOR_ONLY')
change('/workspace/hia-r11-predicate-controls-r1-dda7','/workspace/hia-r12-ordered-read-controls-r1-dda7')
change('==1806','==2268');change('==3612','==4536')
change('"planned_predicate_pairs":1806','"planned_ordered_read_pairs":2268')
change('"maximum_VM_calls":3612','"maximum_VM_calls":4536')
change('ROOT_AUTHORIZED_ADDITIONAL_R11_PREDICATE_GATE_ONCE','ROOT_AUTHORIZED_ADDITIONAL_R12_ORDERED_READ_GATE_ONCE')
change('hia.root.r11.private-predicate.outer-result.v1','hia.root.r12.private-ordered-read.outer-result.v1')
change('PASS_R11_PREDICATE_PARENT_PROCESS_ONLY','PASS_R12_ORDERED_READ_PARENT_PROCESS_ONLY')
back=new
for e in reversed(edits):
 at=e['at'];a=e['before'].encode();b=e['after'].encode();assert back[at:at+len(b)]==b;back=back[:at]+a+back[at+len(b):]
assert back==old and ast.dump(ast.parse(back))==ast.dump(ast.parse(old))
def functions(raw):
 lines=raw.splitlines(keepends=True);return {n.name:b''.join(lines[n.lineno-1:n.end_lineno])for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
a,b=functions(old),functions(new);assert all(a[k]==b[k]for k in a if k!='main')
with (R/'launch_r12_ordered_boundary_r1.py').open('xb')as f:f.write(new)
out={'status':'PASS_STATIC_R12_ORDERED_BOUNDARY_OUTER_WHOLE_INVERSE','before':pin(old),'after':pin(new),'launch':pin(launch),'review':pin(review),'original_helpers':5,'whole_byte_AST_inverse':True,'edits':edits,'outer_seconds':1800,'owner_seconds':180,'cleanup_seconds':3,'maximum_attempts':1,'case_pairs':2268,'maximum_VM_calls':4536,'product_executions':0,'original_3GiB_launch_floor_preserved':True}
with (R/'R12-ORDERED-BOUNDARY-OUTER-INVERSE.json').open('x')as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps({k:v for k,v in out.items()if k!='edits'},sort_keys=True))
