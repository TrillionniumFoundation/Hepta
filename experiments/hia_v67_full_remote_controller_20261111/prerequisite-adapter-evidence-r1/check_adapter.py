#!/usr/bin/env python3
from pathlib import Path
from types import SimpleNamespace
import ast,hashlib,json,os,tempfile,types
r=Path(__file__).resolve().parent
p=r/'prepare_v67_cargo_environment.py';raw=p.read_bytes()
m=types.ModuleType('adapter_control');exec(compile(raw,str(p),'exec'),m.__dict__)
obs=[]
def check(name,fn):
 try: fn();obs.append({'name':name,'passed':True})
 except BaseException as e:obs.append({'name':name,'passed':False,'error':repr(e)});raise

def rejects(fn):
 try: fn()
 except (ValueError,OSError):return
 raise AssertionError('expected refusal')
manifest=json.loads((r/'cargo-cache-archives.original.json').read_bytes())
check('actual_original_manifest_55_records',lambda: (_ for _ in ()).throw(AssertionError()) if len(m._archive_records(manifest))!=55 else None)
for name,mutate in [
 ('wrong_schema',lambda x:x.update(schema='other')),
 ('omitted_crate',lambda x:x['archives'].pop(next(iter(x['archives'])))),
 ('bad_sha',lambda x:x['archives'].__setitem__(next(iter(x['archives'])),'a'*63)),
 ('unknown_field',lambda x:x.update(extra=True)),
 ('wrong_root',lambda x:x.update(path='/tmp/foreign'))]:
 x=json.loads(json.dumps(manifest));mutate(x);check(name,lambda x=x:rejects(lambda:m._archive_records(x)))
class Original:
 def __init__(self,args):raise AssertionError('constructor is not part of these isolated run controls')
 def run(self):self.original_calls+=1
 def save(self):pass
 def missing(self,name,effect):self.missing_calls.append((name,effect))
C=m.adapted_class(SimpleNamespace(Preparation=Original))
assert C.save is Original.save and 'save' not in C.__dict__
for refuse in [True,False]:
 q=object.__new__(C);q.report={'v67_adapter':{}};q.original_calls=0;q.missing_calls=[];q.selected_inputs=lambda:None
 def pinned():
  if refuse:raise ValueError('observed fixed binary mismatch')
 q.pinned_inputs=pinned;q.run()
 check('refused_fixed_input_never_enters_original_probes' if refuse else 'admitted_input_runs_original_once',lambda:None if q.original_calls==(0 if refuse else 1) and bool(q.missing_calls)==refuse else (_ for _ in ()).throw(AssertionError()))
with tempfile.TemporaryDirectory(prefix='v67-cargo-adapter-control-') as tmp:
 home=Path(tmp)/'cargo-home';cache=home/'registry/cache/index';cache.mkdir(parents=True)
 m.CONFIG=dict(m.CONFIG,cargo_home=str(home))
 p=cache/'sample-1.crate';data=b'exact crate bytes';p.write_bytes(data);digest=hashlib.sha256(data).hexdigest()
 check('actual_regular_archive_read',lambda:m._owned_archive(p,digest,len(data)))
 check('actual_wrong_archive_sha_rejected',lambda:rejects(lambda:m._owned_archive(p,'0'*64)))
 link=cache/'link.crate';link.symlink_to(p)
 check('actual_symlink_archive_rejected',lambda:rejects(lambda:m._owned_archive(link,digest)))
 link.unlink();os.link(p,link)
 check('actual_hardlink_archive_rejected',lambda:rejects(lambda:m._owned_archive(p,digest)))
 link.unlink()
 check('actual_wrong_size_rejected',lambda:rejects(lambda:m._owned_archive(p,digest,len(data)+1)))
value={'schema':'hia.v67.prerequisite-adapter-local-controls.v1','adapter_sha256':hashlib.sha256(raw).hexdigest(),'original_manifest_sha256':hashlib.sha256((r/'cargo-cache-archives.original.json').read_bytes()).hexdigest(),'checks':obs,'passed':all(x['passed'] for x in obs),'remote_execution':False,'actual_tool_or_fixture_probes_executed':False,'full_preparation_ready_claimed':False,'qualification_claimed':False,'original_save_method_inherited_unchanged':True}
(r/'adapter-control-observations.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
print(json.dumps({'passed':value['passed'],'controls':len(obs),'adapter_sha256':value['adapter_sha256']},sort_keys=True))
