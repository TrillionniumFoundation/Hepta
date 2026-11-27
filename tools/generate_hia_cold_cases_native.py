"""Retain every original generic native gate as immutable fixture data."""
from pathlib import Path
from hashlib import sha256
import importlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
DATA=None
def put(source):
    raw=source.encode() if isinstance(source,str) else bytes(source)
    name='sources/'+sha256(raw).hexdigest()+'.hepta';path=DATA/name
    if path.exists():assert path.read_bytes()==raw
    else:path.write_bytes(raw)
    return name
def module(name):return importlib.import_module('tools.hia_selfhost_'+name)
def normalize(folder, *, data):
    global DATA
    folder=Path(folder).resolve();DATA=Path(data).resolve()
    if folder.is_relative_to(ROOT) or DATA.is_relative_to(ROOT):
        raise ValueError("development outputs must be outside the source tree")
    if not folder.is_dir() or not DATA.is_dir():
        raise ValueError("explicit authoring and data directories are required")
    summary={}
    names=['signed','scalar-casts','multi','keyword','effects','cfg','bulk','loan','resource','select','tail','capacity','explicit-traps']
    for family in names:
      original=json.loads((folder/(family+'-original-authoring.json')).read_text())
      rows=json.loads((DATA/(family+'.json')).read_text())
      programs={};refusals=[];promotions=[]
      def target(key,source,*,flat=True,obj=False,linked=False,short=None,fill=0,words=(),short_word=None):
        value={'id':family+'-'+key,'source':put(source),'flat':flat,'object':obj,'linked':linked,
          'owned':(b'v8 selfhost_elf\n' in (source.encode() if isinstance(source,str) else source)),
          'short':short,'fill':fill,'compile_words':list(words),'short_word':short_word,'calls':[]}
        if key in programs:
          assert {k:v for k,v in programs[key].items() if k!='calls'}=={k:v for k,v in value.items() if k!='calls'},key
          return programs[key]
        programs[key]=value;return value
      def call(p,key,source=b'',initial=b'',expected=None,result=0,trap=False,shared=False,reference=None):
        def raw(value):return bytes.fromhex(value) if isinstance(value,str) else bytes(value)
        initial=raw(initial);expected=initial if expected is None else raw(expected)
        assert len(initial)==len(expected)
        p['calls'].append({'id':family+'-'+key,'input_hex':raw(source).hex(),'initial_hex':initial.hex(),
           'expected_hex':expected.hex(),'core_u32':result,'signal':4 if trap else 0,
           'shared':shared or trap,'fresh_reference_return':reference})
      def reject(key,source,*,capacity=1<<20,fill=0,result=0xffffffff,words=()):
        refusals.append({'id':family+'-'+key,'source':put(source),'capacity':capacity,'fill':fill,
                         'core_u32':result,'workspace_words':list(words)})
      if family in ('signed','scalar-casts','multi','keyword'):
        for c in original['cases']:
          p=target(c['program'],c['source'],flat=not c['owned_elf_only'],obj=True,linked=True,short='object')
          call(p,c['id'],c['source_hex'],c['initial_hex'],c['expected_hex'],c['expected_result'],shared=True)
        for c in original.get('traps',[]):
          p=target('trap-'+sha256(c['source'].encode()).hexdigest()[:20],c['source'])
          call(p,'trap-'+c['id'],c['source_hex'],c['initial_hex'],c['expected_hex'],trap=True,shared=True)
        for c in original['refusals']:
          if c.get('native_profile_expected')=='compiled':
            matching=[x for x in original['cases'] if x.get('historical_refusal_id')==c['id']]
            assert matching and all(x['source']==c['source'] for x in matching)
            promotions.append({'id':c['id'],'source':put(c['source']),'cases':[x['id'] for x in matching]})
          else:reject('refuse-'+c['id'],c['source'],capacity=512)
      elif family in ('cfg','effects'):
        selected=set(original.get('native_case_ids', [x['id'] for x in original['cases']]))
        for c in original['cases']:
          if c['id'] not in selected:continue
          owned='v8 selfhost_elf\n' in c['source']
          p=target(c['id'],c['source'],flat=not owned,obj=owned,linked=owned,fill=0x5a,words=[(248,8,c['core_nodes'])])
          call(p,c['id'],c['source_hex'],c['initial_hex'],c['expected_hex'],c['expected_result'],shared=True)
        for c in original['refusals']:reject('refuse-'+c['id'],c['source'],capacity=512,fill=0x5a)
      elif family=='bulk':
        m=module('bulk');first={op:next(c['id'] for c in original['cases'] if c['opcode']==op) for op in m.OPS}
        for c in original['cases']:
          p=target(c['id'],m.fixture_source(c),obj=c['id'] in first.values())
          call(p,c['id'],c['source_hex'],c['initial_hex'],c['expected_hex'],trap=c['trap'],shared=True)
        for key,source in m.bulk_refusals().items():reject('refuse-'+key,source,capacity=512)
      elif family=='loan':
        m=module('loans')
        for c in original['cases']:
          p=target(c['id'],c['source'],obj=c['id'] in ('shared-depth-8','nested-mutable','loan-through-loop-backedge'))
          call(p,c['id'],c['source_hex'],c['initial_hex'],c['expected_hex'],c['expected_result'],shared=True)
        for key,source in {**m.loan_refusals(),**m.loan_profile_refusals()}.items():reject('refuse-'+key,source,capacity=512)
      elif family=='resource':
        m=module('resources')
        for c in original['cases']:
          p=target(c['case'],m.swap_source(c['left'],c['right']))
          call(p,c['case'],initial=c['initial_hex'],expected=c['expected_hex'],trap=c['trap'],shared=True)
        source=m.swap_source(0,4).replace(b'  _ = buffer.swap',b'  v6:u8 = const() {"value":99}\n  _ = buffer.store(v1,v3,v6)\n  _ = buffer.swap')
        p=target('observer-prior-store',source)
        call(p,'observer-prior-store',initial=bytes([10,20,30,40]),expected=bytes([99,20,30,40]),trap=True,shared=True)
        target('object',m.swap_source(0,3),obj=True)
        for key,source in m.swap_refusals().items():reject('refuse-'+key,source)
      elif family=='select':
        m=module('select')
        for typ in (*m.WIDTHS,'bool'):
          p=target(typ,m.select_source(typ),obj=True,short='flat')
          for index,c in enumerate(x for x in original['cases'] if x['type']==typ):
            data=bytes([int(c['condition'])])+int(c['left']).to_bytes(8,'little')+int(c['right']).to_bytes(8,'little')
            call(p,typ+'-'+str(index),data,b'\xa5'*8,int(c['expected']).to_bytes(8,'little'),int(c['expected'])&0xffffffff)
        for op in ('compare.eq','compare.ne'):
          p=target(op,m.boolean_equality_source(op),obj=True,short='flat')
          for index,c in enumerate(x for x in original['boolean_equality']['cases'] if x['opcode']==op):
            call(p,op+'-'+str(index),c['input_hex'],b'\xa5'*8,result=int(c['expected']))
        for key,source in {**m.select_refusals(),**m.boolean_equality_refusals()}.items():reject('refuse-'+key,source)
      elif family=='tail':
        m=module('tailcalls')
        for c in original['scalar_cases']:
          p=target(c['case'],m.scalar_tail_source(c['count']),fill=0xa7);call(p,c['case'],result=c['expected_result'])
        p=target('buffer',m.buffer_tail_source(),obj=True,short='flat')
        for i,c in enumerate(original['buffer_cases']):
          data=bytes.fromhex(c['input_hex']);call(p,'buffer-'+str(i),data,b'\xa5'*len(data),c['expected_output_hex'],c['expected_result'])
        c=original['deep_case'];p=target('deep-large-frame',m.scalar_tail_source(c['count'],large_frame=True));call(p,'deep-large-frame',result=c['expected_result'])
        for key,(source,accepted) in m.tail_refusals().items():
          if not accepted:reject('refuse-'+key,source)
        refs=[r for r in rows['references'] if r['original_assertion']['author'].endswith('hia_selfhost_recursion.py')]
        assert len(refs)==len(original['recursion']['cases'])
        for c,ref in zip(original['recursion']['cases'],refs,strict=True):
          p=target('recursive-'+c['id'],c['source'],obj=True,short='flat')
          call(p,'recursive-'+c['id'],result=0 if c['native_budget_trap'] else c['reference_result']['result'],
               trap=c['native_budget_trap'],shared=True,reference=ref['id'] if not c['native_budget_trap'] else None)
      elif family=='capacity':
        m=module('capacity');by={x['case']:x for x in original['observations']}
        for size in (3072,3073,m.MAX_INSTRUCTIONS):
          source,expected=m.instruction_capacity_source(size)
          p=target('instructions-'+str(size),source,obj=size==m.MAX_INSTRUCTIONS,short='flat' if size==m.MAX_INSTRUCTIONS else None,fill=0xa7,
                   words=[(112,8,size),(248,8,by['instructions-'+str(size)]['core_nodes'])],short_word=224 if size==m.MAX_INSTRUCTIONS else None)
          call(p,'instructions-'+str(size),result=expected)
        source,_=m.instruction_capacity_source(m.MAX_INSTRUCTIONS+1);reject('instructions-over-limit',source,words=[(40,8,54)])
        for allocating,over in ((False,False),(False,True),(True,False),(True,True)):
          source,_=m.structural_capacity_fixture(over,allocating=allocating)
          reject('nodes-'+str(int(allocating))+'-'+str(int(over)),source,capacity=32,fill=0xa7,
                 result=0xffffffff if over else 0xfffffffe,words=[(248,8,m.MAX_CORE_NODES+int(over)),(40,8,58 if over else 0)])
      elif family=='explicit-traps':
        for c in original['cases']:
          p=target(c['id'],c['source'],flat=not c['owned_elf_only'],obj=True,linked=True,short='object')
          call(p,c['id'],c['source_hex'],c['initial_hex'],c['expected_hex'],c.get('expected_result',0),trap='expected_trap' in c,shared=True)
        for c in original['refusals']:reject('refuse-'+c['id'],c['source'],capacity=512)
      rows['native_programs']=list(programs.values());rows['native_refusals']=refusals;rows['retained_promotions']=promotions
      (DATA/(family+'.json')).write_text(json.dumps(rows,indent=2)+'\n')
      summary[family]={'programs':len(programs),'calls_per_label':sum(len(x['calls']) for x in programs.values()),'refusals_per_label':len(refusals),
                       'object_gates_per_label':sum(x['object'] for x in programs.values()),'linked_programs':sum(x['linked'] for x in programs.values()),
                       'short_gates_per_label':sum(x['short'] is not None for x in programs.values())}
      print('NATIVE',family,summary[family],flush=True)
    inventory=json.loads((DATA/'inventory.json').read_text())
    inventory['sources']={str(p.relative_to(DATA)):{'sha256':sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for directory in ('sources','documents') for p in (DATA/directory).iterdir() if p.is_file()}
    inventory['native_gates']=summary
    (DATA/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
    (folder/'native-normalization.json').write_text(json.dumps({'passed':True,'families':summary},indent=2))
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--data',type=Path,required=True)
    args=parser.parse_args()
    normalize(args.output,data=args.data)
