from pathlib import Path
from hashlib import sha256
import ast,ctypes,json,sys,copy,importlib.util,time
import argparse
parser=argparse.ArgumentParser(description='Development-only Core cursor differential controls; no product runtime dependency.')
parser.add_argument('--original-source',type=Path,required=True)
parser.add_argument('--old-flat',type=Path,required=True)
parser.add_argument('--new-flat',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
G=Path(__file__).resolve().parents[1];K=args.original_source.resolve();D=args.output.resolve();D.mkdir()
sys.path.insert(0,str(G))
from tools import generate_hia_core_admission as new_author
old_path=K/'tools/generate_hia_core_admission.py';spec=importlib.util.spec_from_file_location('old_core_admission_author',old_path);old_author=importlib.util.module_from_spec(spec);spec.loader.exec_module(old_author)
old_ast=ast.parse(old_author.source_program());new_ast=ast.parse(new_author.source_program())
assert [n.name for n in old_ast.body]==[n.name for n in new_ast.body]
unchanged=0
class Restore(ast.NodeTransformer):
 def visit_Name(self,n):
  if isinstance(n.ctx,ast.Load) and n.id in {'edge_argument','edge_parameter'}:
   return ast.Call(func=ast.Name(id='item',ctx=ast.Load()),args=[ast.Name(id='w',ctx=ast.Load()),ast.Name(id='args' if n.id=='edge_argument' else 'params',ctx=ast.Load()),ast.Name(id='i',ctx=ast.Load())],keywords=[])
  return n
 def visit_Assign(self,n):
  if len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in {'edge_argument','edge_parameter'}:return None
  return self.generic_visit(n)
for old,new in zip(old_ast.body,new_ast.body):
 if old.name=='transfer':assert ast.dump(Restore().visit(copy.deepcopy(new)),include_attributes=False)==ast.dump(old,include_attributes=False)
 else:
  assert ast.dump(new,include_attributes=False)==ast.dump(old,include_attributes=False),old.name
  unchanged+=1
doc=new_author.document()
profile={'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),'ops':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),'max_block_params':max(len(b['params']) for f in doc['functions'] for b in f['blocks'])}
assert profile['functions']<=128 and profile['blocks']<=1536 and profile['ops']<=8192 and profile['max_block_params']<=16
from hepta.hia_core_admission_native import scratch_sizes
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tests.test_hia_core_admission_native import VALID,wire,borrowed_owner,returned_aliases
from tests.test_hia_program import joined_loan_program
from tests.hia_core_diagnostic_cases import closure_before_join,structured_mutations
oldflat=args.old_flat.read_bytes();newflat=args.new_flat.read_bytes()
images=[NativeHiaJsonImage(x,sha256(x).hexdigest()) for x in [oldflat,newflat]]
cases=[('valid',VALID),('borrowed-owner',borrowed_owner()),('joined-loan',joined_loan_program()),('closure-before-join',closure_before_join())]
for label,value in structured_mutations(joined_loan_program()):cases.append(('mutation-'+json.dumps(label,ensure_ascii=False),value))
for types in [('mutbuf','mutbuf'),('readbuf','readbuf'),('u32','mutbuf','buffer','readbuf')]:cases.append(('returned-'+','.join(types),returned_aliases(types)))
for n in [0,1,2,7,32,129,257]:
 base=copy.deepcopy(VALID);fn=base['functions'][0]
 fn['blocks'][0]['ops']=[{'op':'const','args':[],'out':[{'name':'z','type':'u8'}],'attrs':{'value':0}}]
 fn['blocks'][0]['term']={'op':'jump','target':'tail','args':['z']*n}
 fn['blocks'].append({'id':'tail','params':[{'name':'v'+str(i),'type':'u8'} for i in range(n)],'ops':[],'term':{'op':'ret','values':[]}})
 cases.append(('arity-'+str(n),base))
 if n:
  for pos in sorted({0,n//2,n-1}):
   bad=copy.deepcopy(base);bad['functions'][0]['blocks'][1]['params'][pos]['type']='u64';cases.append(('type-'+str(n)+'-'+str(pos),bad))
   both=copy.deepcopy(bad);both['functions'][0]['blocks'][0]['term']['args'][-1]='absent';cases.append(('ssa-before-type-'+str(n)+'-'+str(pos),both))
records=[];start=time.monotonic_ns()
def observe(image,raw,fill):
 sizes=scratch_sizes(len(raw));body=ctypes.create_string_buffer(raw,max(1,len(raw)));outputs=[]
 arrays=[]
 for size in sizes:
  b=bytearray(bytes([0xD7])*32+bytes([fill])*size+bytes([0xD7])*32);arrays.append(b)
 addresses=[ctypes.addressof(ctypes.c_ubyte.from_buffer(b))+32 for b in arrays]
 result=image._entry(body,len(raw),addresses[0],sizes[0],addresses[1],sizes[1])
 assert body.raw[:len(raw)]==raw
 for b in arrays:
  assert b[:32]==bytes([0xD7])*32 and b[-32:]==bytes([0xD7])*32
  outputs.append(bytes(b[32:-32]))
 return result,outputs
for label,value in cases:
 raw=wire(value)
 for fill in [0,0xA7]:
  a=observe(images[0],raw,fill);b=observe(images[1],raw,fill)
  assert a==b,(label,fill,a[0],b[0])
  records.append({'id':label,'fill':fill,'input_sha256':sha256(raw).hexdigest(),'status':a[0],'state_sha256':sha256(a[1][0]).hexdigest(),'arena_sha256':sha256(a[1][1]).hexdigest()})
report={'status':'PASS','cases':len(records),'records':records,'elapsed_ns':time.monotonic_ns()-start,'unchanged_other_functions':unchanged,'transfer_ast_exact_after_inverse_cursor_rewrite':True,'profile':profile,'old_sha256':sha256(oldflat).hexdigest(),'new_sha256':sha256(newflat).hexdigest(),'source_sha256':sha256((G/'examples/hia_bootstrap/core_admission.hepta').read_bytes()).hexdigest(),'all_three_views_and_canaries_compared':True}
(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='records'}),flush=True)
