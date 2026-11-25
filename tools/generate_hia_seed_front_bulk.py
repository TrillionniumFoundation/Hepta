"""Author a separate bootstrap frontend profile with exact helper rewrites.

The old source files remain unchanged. Matching uses complete canonical Core
function bodies, rather than names or a substring. Word reads retain the old
loop outside the complete legal range. Word writes use one word store only
inside the complete legal range, retaining the original bytewise fallback
and every partial-write boundary outside that range.
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
 lines=['def put(w:mutbuf,index:u64,value:u64) -> u64:',
        '    if index <= length(w) and length(w) - index >= 8:',
        '        store_word(w,index,value)',
        '        return '+('0' if zero else 'value')]
 for i in range(8):
  value=f'(value >> {i*8}) & 255' if mask else f'value >> {i*8}'
  lines.append(f'    store(w,index + {i},{value})')
 lines.append('    return '+('0' if zero else 'value'))
 lines.extend(['','def store_word(w:mutbuf,index:u64,value:u64) -> u64:', '    return 0'])
 fn=canonical('\n'.join(lines)+'\n')['functions'][0];found=0
 used={x for b in fn['blocks'] for op in b['ops'] for x in op['args']}
 def collect(value):
  if isinstance(value,str):used.add(value)
  elif isinstance(value,list):
   for x in value:collect(x)
  elif isinstance(value,dict):
   for x in value.values():collect(x)
 for b in fn['blocks']:collect(b['term'])
 for block in fn['blocks']:
  ops=[]
  for op in block['ops']:
   if op['op']=='call':
    assert op['attrs']=={'function':'f1'} and len(op['args'])==3
    assert not any(x['name'] in used for x in op['out'])
    name='bulk_store_word_offset'
    ops.extend(({'op':'int.cast','args':[op['args'][1]],'attrs':{'mode':'wrap'},'out':[{'name':name,'type':'usize'}]}, {'op':'buffer.store.u64.le','args':[op['args'][0],name,op['args'][2]],'attrs':{},'out':[]}))
    found+=1
   else:ops.append(op)
  block['ops']=ops
 assert found==1
 return fn

def inline_word_reads(body):
 text=body+'\ndef wide(w:mutbuf,index:u64) -> u64:\n    return 0\n'
 fn=canonical(text)['functions'][0];found=0
 for block in fn['blocks']:
  ops=[]
  for op in block['ops']:
   if op['op']=='call':
    assert op['attrs']=={'function':'f1'} and len(op['args'])==2
    name='bulk_literal_word_offset_'+str(found)
    ops.extend(({'op':'int.cast','args':[op['args'][1]],'attrs':{'mode':'wrap'},'out':[{'name':name,'type':'usize'}]}, {'op':'buffer.load.u64.le','args':[op['args'][0],name],'attrs':{},'out':op['out']}))
    found+=1
   else:ops.append(op)
  block['ops']=ops
 assert found>0
 return fn

def same_literal():
 return '''def same(w:mutbuf,start:u64,size:u64,n:u64,a:u64,b:u64,c:u64) -> u64:
    if size != n:
        return 0
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        if byte(w,start + i) != ((word >> shift) & 255):
            return 0
        i = i + 1
    return 1
'''

def same_literal_fast():
 head,tail=same_literal().split('\n',1)
 guard='    if size != n:\n        return 0\n'
 assert tail.startswith(guard)
 body=head+'\n'+guard+'''    if n == 0:
        return 1
    if n <= 24 and start <= length(w):
        needed = 8
        if n > 8:
            needed = 16
        if n > 16:
            needed = 24
        if length(w) - start >= needed:
            value = wide(w,start)
            if n < 8:
                mask = (1 << (n * 8)) - 1
                if (value & mask) != (a & mask):
                    return 0
                return 1
            if value != a:
                return 0
            if n == 8:
                return 1
            value = wide(w,start + 8)
            if n < 16:
                mask = (1 << ((n - 8) * 8)) - 1
                if (value & mask) != (b & mask):
                    return 0
                return 1
            if value != b:
                return 0
            if n == 16:
                return 1
            value = wide(w,start + 16)
            if n < 24:
                mask = (1 << ((n - 16) * 8)) - 1
                if (value & mask) != (c & mask):
                    return 0
                return 1
            if value != c:
                return 0
            return 1
'''+tail[len(guard):]
 return inline_word_reads(body)

def match_word():
 return '''def match_word(w:mutbuf,at:u64,width:u64) -> u64:
    value = 0
    index = 0
    while index < width:
        value = value | (byte(w,at + index) << (8 * index))
        index = index + 1
    return value
'''

def match_word_fast():
 head,tail=match_word().split('\n',1)
 body=head+'''
    if width == 0:
        return 0
    if width <= 8 and at <= length(w) and length(w) - at >= 8:
        value = wide(w,at)
        if width == 8:
            return value
        return value & ((1 << (width * 8)) - 1)
'''+tail
 return inline_word_reads(body)

def draining_putter():
 return '''def put(w:mutbuf,index:u64,value:u64) -> u64:
    count = 0
    while count < 8:
        store(w,index + count,value & 255)
        value = value >> 8
        count = count + 1
    return 0
'''

def replacements():
 result={}
 for kind in ('readbuf','mutbuf'):
  old=canonical(getter(kind))['functions'][0]
  result[fingerprint(old)]=('checked_word_load_'+kind,getter_fast(kind))
 for mask in (False,True):
  for zero in (False,True):
   old=canonical(putter(mask=mask,zero=zero))['functions'][0]
   result[fingerprint(old)]=('checked_word_store_with_byte_fallback_'+str(int(mask))+str(int(zero)),putter_fast(mask=mask,zero=zero))
 for name,old,new in [('checked_literal_word_compare',same_literal(),same_literal_fast()),('checked_variable_width_word_load',match_word(),match_word_fast()),('checked_draining_word_store',draining_putter(),putter_fast(mask=True,zero=True))]:
  original=canonical(old)['functions'][0]
  result[fingerprint(original)]=(name,new)
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
  from tools.hia_seed_front_hot import rewrite
  changes.extend(rewrite(doc,rel))
  selected=rel
  if changes:
   doc['schema']='hepta.hia.program.v9';selected='seed_front_bulk/'+rel;path=base/selected;path.parent.mkdir(parents=True,exist_ok=True)
   image=render_assembly(doc).encode();assemble_program(image);path.write_bytes(image)
  else:image=source
  row={'original':rel,'selected':selected,'original_sha256':sha256(source).hexdigest(),'selected_sha256':sha256(image).hexdigest(),'source_bytes':len(image),'changes':changes};rows.append(row)
  print('SEED_FRONT_PROFILE',rel,len(image),[(x['function'],x['transformation']) for x in changes],flush=True)
 p=ROOT/'examples/hia_bootstrap/seed_front_bulk/source_map.json';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps({'schema':'hepta.hia.seed-front-bulk.sources.v1','modules':rows},indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
