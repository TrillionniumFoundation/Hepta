"""Author a separate bootstrap frontend profile with exact helper rewrites.

The old source files remain unchanged. Matching uses complete canonical Core
function bodies, rather than names or a substring. Word reads retain the old
loop outside the complete legal range; word writes retain bytewise order and
therefore preserve every partial-write boundary.
"""
from pathlib import Path
from hashlib import sha256
import json,copy
from hepta.hia_agent_assembly import assemble_program,render_assembly
from tools.generate_hia_worker_config_json import document
ROOT=Path(__file__).resolve().parents[1]
MODULES=(
 'core_cli/assembly_syntax_diagnostics.hepta','core_admission.hepta','json_canonical.hepta',
 'core_cli/assembly_diagnostic_report.hepta','core_cli/assembly_pretty.hepta','core_cli/assembly_driver.hepta',
 'core_edit/publication_frontend.hepta','core_edit/publication_import.hepta','core_edit/publication_policy.hepta',
 'evaluate_reference_wire.hepta',
)

def canonical(body):
 return json.loads(assemble_program(render_assembly(document(body,'seed_front_helper'))).canonical_bytes)

def fingerprint(fn):
 value=copy.deepcopy(fn);value.pop('name',None);value.pop('effects',None)
 return json.dumps(value,sort_keys=True,separators=(',',':'))

def getter(kind='mutbuf'):
 return f'''def get(w:{kind},index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(w,index + count) << (count * 8))
        count = count + 1
    return value
'''

def getter_fast(kind='mutbuf'):
 raw=getter(kind);head,tail=raw.split('\n',1)
 fast=head+'''
    if index <= length(w) and length(w) - index >= 8:
        return wide(w,index)
'''+tail+f'''\ndef wide(w:{kind},index:u64) -> u64:
    return 0
'''
 fn=canonical(fast)['functions'][0];found=0
 for block in fn['blocks']:
  ops=[]
  for op in block['ops']:
   if op['op']=='call':
    assert op['attrs']=={'function':'f1'} and len(op['args'])==2
    name='bulk_word_offset';ops.extend(({'op':'int.cast','args':[op['args'][1]],'attrs':{'mode':'wrap'},'out':[{'name':name,'type':'usize'}]}, {'op':'buffer.load.u64.le','args':[op['args'][0],name],'attrs':{},'out':op['out']}));found+=1
   else:ops.append(op)
  block['ops']=ops
 assert found==1
 return fn

def putter(*,mask=False,zero=False):
 value='(value >> (count * 8)) & 255' if mask else 'value >> (count * 8)'
 return '''def put(w:mutbuf,index:u64,value:u64) -> u64:
    count = 0
    while count < 8:
        store(w,index + count,'''+value+''')
        count = count + 1
    return '''+('0' if zero else 'value')+'\n'

def putter_fast(*,mask=False,zero=False):
 lines=['def put(w:mutbuf,index:u64,value:u64) -> u64:']
 for i in range(8):
  value=f'(value >> {i*8}) & 255' if mask else f'value >> {i*8}'
  lines.append(f'    store(w,index + {i},{value})')
 lines.append('    return '+('0' if zero else 'value'))
 return canonical('\n'.join(lines)+'\n')['functions'][0]

def replacements():
 result={}
 for kind in ('readbuf','mutbuf'):
  old=canonical(getter(kind))['functions'][0]
  result[fingerprint(old)]=('checked_word_load_'+kind,getter_fast(kind))
 for mask in (False,True):
  for zero in (False,True):
   old=canonical(putter(mask=mask,zero=zero))['functions'][0]
   result[fingerprint(old)]=('unrolled_byte_store_'+str(int(mask))+str(int(zero)),putter_fast(mask=mask,zero=zero))
 return result

def main():
 patterns=replacements();base=ROOT/'examples/hia_bootstrap';rows=[]
 for rel in MODULES:
  source=(base/rel).read_bytes();doc=json.loads(assemble_program(source).canonical_bytes);changes=[]
  for i,fn in enumerate(doc['functions']):
   found=patterns.get(fingerprint(fn))
   if found is None:continue
   name,new=found;new=copy.deepcopy(new);new['name']=fn['name'];new['effects']=fn['effects'];doc['functions'][i]=new
   changes.append({'function':fn['name'],'transformation':name,'original_sha256':sha256(fingerprint(fn).encode()).hexdigest(),'replacement_sha256':sha256(fingerprint(new).encode()).hexdigest()})
  selected=rel
  if changes:
   doc['schema']='hepta.hia.program.v9';selected='seed_front_bulk/'+rel;path=base/selected;path.parent.mkdir(parents=True,exist_ok=True)
   image=render_assembly(doc).encode();assemble_program(image);path.write_bytes(image)
  else:image=source
  row={'original':rel,'selected':selected,'original_sha256':sha256(source).hexdigest(),'selected_sha256':sha256(image).hexdigest(),'source_bytes':len(image),'changes':changes};rows.append(row)
  print('SEED_FRONT_PROFILE',rel,len(image),[(x['function'],x['transformation']) for x in changes],flush=True)
 p=ROOT/'examples/hia_bootstrap/seed_front_bulk/source_map.json';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps({'schema':'hepta.hia.seed-front-bulk.sources.v1','modules':rows},indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
