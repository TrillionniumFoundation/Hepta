"""Freeze the original generic cold family source and assertion inputs.

Development-only migration author. The produced HIA sources and immutable case
data are replayed by native HIA tools; these Python executions are never accepted
as the final independent reference receipts.
"""
from pathlib import Path
from hashlib import sha256
import ast, importlib, inspect, json, traceback
from hepta import hia_agent_assembly as assembly
from hepta import hia_program as program
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'examples/hia_bootstrap/cold_cases_generic'
SOURCE=DATA/'sources'
SOURCE.mkdir(parents=True,exist_ok=True)
ASSEMBLE=assembly.assemble_program
EXECUTE=program.execute_program
SIGNATURE=inspect.signature(EXECUTE)
source_map={}
sources={}
admissions={}
references=[]
CURRENT=''
def put_source(value):
    raw=value.encode() if isinstance(value,str) else bytes(value)
    pin=sha256(raw).hexdigest();name='sources/'+pin+'.hepta'
    target=DATA/name
    if target.exists():assert target.read_bytes()==raw
    else:target.write_bytes(raw)
    sources[name]={'sha256':pin,'bytes':len(raw)}
    return name
def put_document(document):
    raw=json.dumps(document,sort_keys=True,separators=(',',':')).encode()
    pin=sha256(raw).hexdigest();name='documents/'+pin+'.hiacore';target=DATA/name
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():assert target.read_bytes()==raw
    else:target.write_bytes(raw)
    sources[name]={'sha256':pin,'bytes':len(raw)}
    return name
def checked(source,*args,**kwargs):
    name=put_source(source)
    key=(CURRENT,name)
    try:result=ASSEMBLE(source,*args,**kwargs)
    except program.HIAProgramRejected as error:
        row={'family':CURRENT,'source':name,'accepted':False,'code':error.code}
        if key in admissions:assert admissions[key]==row
        admissions[key]=row
        raise
    row={'family':CURRENT,'source':name,'accepted':True}
    if key in admissions:assert admissions[key]==row
    admissions[key]=row
    source_map[result.sha256]=name
    return result
def execute(*args,**kwargs):
    bound=SIGNATURE.bind(*args,**kwargs);bound.apply_defaults()
    values=bound.arguments
    core=args[0] if args else next(iter(values.values()))
    doc=core.as_dict() if hasattr(core,'as_dict') else core
    source=source_map.get(getattr(core,'sha256',None))
    if source is None:source=put_source(assembly.render_assembly(doc))
    entry=args[1] if len(args)>1 else values.get('entry',values.get('entry_function'))
    arguments=args[2] if len(args)>2 else values.get('arguments',[])
    function=next(fn for fn in doc['functions'] if fn['name']==entry)
    frame=inspect.currentframe().f_back
    caller={'author':str(Path(frame.f_code.co_filename).relative_to(ROOT)),
            'function':frame.f_code.co_name,'line':frame.f_lineno}
    row={'family':CURRENT,'id':CURRENT+'-reference-'+str(len(references)),
         'source':source,'entry':entry,'args':list(arguments),
         'types':[item['type'] for item in function['params']],
         'budgets':{key:kwargs.get(key,default) for key,default in
           (('max_steps',1000000),('max_call_depth',256),('max_heap_bytes',16<<20),('allocation_fail_at',None))},
         'original_assertion':caller}
    try:result=EXECUTE(*args,**kwargs)
    except BaseException as error:
        if not hasattr(error,'report'):raise
        result=error.report
        row['expect']={'status':result['status'],'code':result.get('error',{}).get('code')}
        references.append(row)
        raise
    row['expect']={'status':result['status'],'values':result.get('values',[])}
    references.append(row)
    return result
assembly.assemble_program=checked
program.execute_program=execute
FAMILIES=[
 ('signed','hia_selfhost_signed_cases','independent_reference'),
 ('scalar-casts','hia_selfhost_scalar_casts','independent_reference'),
 ('multi','hia_selfhost_multi_results','independent_reference'),
 ('keyword','hia_selfhost_keywords','independent_reference'),
 ('effects','hia_selfhost_effects','independent_reference'),
 ('cfg','hia_selfhost_cfg_worklist','independent_reference'),
 ('bulk','hia_selfhost_bulk','independent_bulk_reference'),
 ('loan','hia_selfhost_loans','independent_loan_reference'),
 ('resource','hia_selfhost_resources','independent_resource_reference'),
 ('select','hia_selfhost_select','independent_select_reference'),
 ('tail','hia_selfhost_tailcalls','independent_tail_reference'),
 ('capacity','hia_selfhost_capacity','independent_capacity_reference'),
 ('explicit-traps','hia_selfhost_traps','independent_reference')]
def generate(output):
    global CURRENT
    output=Path(output);summary={'passed':False,'families':{}}
    try:
      for name,module,function in FAMILIES:
        CURRENT=name;before=len(references);mod=importlib.import_module('tools.'+module)
        result=getattr(mod,function)()
        (output/(name+'-original-authoring.json')).write_text(json.dumps(result,indent=2))
        if name=='explicit-traps':
          for case in result['cases']:
            references.append({'family':name,'id':name+'-'+case['id'],'source':put_source(case['source']),
              'entry':'f0','args':[len(bytes.fromhex(case['source_hex'])),len(bytes.fromhex(case['initial_hex'])),0],
              'types':['readbuf','mutbuf','mutbuf'],'snapshots_hex':case['source_hex']+case['initial_hex'],
              'expected_snapshots_hex':case['source_hex']+case['expected_hex'],
              'budgets':{'max_steps':1000000,'max_call_depth':256,'max_heap_bytes':16<<20,'allocation_fail_at':None},
              'expect':{'status':'trapped','code':case['expected_trap']} if 'expected_trap' in case else {'status':'returned','values':[case['expected_result']]},
              'expected_live_owners':case.get('expected_live_owners',0),'expected_live_loans':case.get('expected_live_loans',0),
              'original_assertion':{'author':'tools/hia_selfhost_traps.py','function':'independent_reference'}})
        if name=='capacity':
          for allocating in (False,True):
            source,document=mod.structural_capacity_fixture(False,allocating=allocating)
            source_name=put_source(source)
            row=admissions[(name,source_name)]
            assert row['accepted']
            row['expected_core']=put_document(document)
        rows=[r for r in references if r['family']==name];gates=[r for r in admissions.values() if r['family']==name]
        summary['families'][name]={'references':len(rows),'admissions':len(gates),'original_source':str(Path(mod.__file__).relative_to(ROOT)),'original_source_sha256':sha256(Path(mod.__file__).read_bytes()).hexdigest()}
        (DATA/(name+'.json')).write_text(json.dumps({'schema':'hia.native.cold.generic-fixtures.v1','family':name,'references':rows,'admissions':gates},indent=2)+'\n')
        print('FAMILY',name,len(rows),len(gates),flush=True)
      summary['passed']=True
      (DATA/'inventory.json').write_text(json.dumps({'schema':'hia.native.cold.generic-inventory.v1','sources':sources,'families':summary['families']},indent=2)+'\n')
    except BaseException:summary['error']=traceback.format_exc();raise
    finally:(output/'author-status.json').write_text(json.dumps(summary,indent=2))
if __name__=='__main__':
    import sys
    generate(sys.argv[1])
