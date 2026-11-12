"""Only read old, completed compiler receipts; never start a compiler or app."""
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
CONTROL=ROOT/'control'; PAIR=Path('/tmp/hia-publication-compiler-pair-v85-r1')
OUT=ROOT/'control-only-r1';OUT.mkdir(mode=0o700)
sys.path.insert(0,str(CONTROL))
import common
import controller

config=json.loads((CONTROL/'CONFIG.json').read_bytes())
rows=[]
def check(name, fn, refusal=False):
    try:
        value=fn()
    except ValueError as error:
        rows.append({'name':name,'pass':refusal,'expected_refusal':refusal,
                     'exception_type':type(error).__name__,'exception':str(error)})
    except BaseException:
        rows.append({'name':name,'pass':False,'expected_refusal':refusal,'traceback':traceback.format_exc()})
    else:
        rows.append({'name':name,'pass':not refusal and value is not False,
                     'expected_refusal':refusal,'result':value})

before=common.external_inputs(config)
for name in ('common.py','controller.py','worker.py'):
    check('parse_'+name,lambda name=name:bool(ast.parse((CONTROL/name).read_bytes())))
check('parse_freeze',lambda:bool(ast.parse((ROOT/'freeze.py').read_bytes())))

folder=PAIR/'worker/v82'; compiler=folder/'B3.image.bin'
for label in ('artifact_publication_policy','artifact_publication_packer','sha256_stream'):
    check('actual_original_pair_compile_'+label,
          lambda label=label:common.join_child(folder,label,compiler,(folder/(label+'.input.bin')).read_bytes(),
                                               config,folder/(label+'.image.bin')))

label='sha256_stream'
base_paths={suffix:folder/(label+suffix) for suffix in
            ('.receipt.json','.stdout.log','.stderr.log','.output.bin','.input.bin','.image.bin','.request.json')}
base={suffix:path.read_bytes() for suffix,path in base_paths.items()}
original_read=Path.read_bytes
def join_with(changes):
    # These are declared in-memory negative controls on actual original bytes.
    # No original path is written and no fake native execution is claimed.
    def read(path):
        return changes.get(str(path),original_read(path))
    with patch.object(Path,'read_bytes',read):
        return common.join_child(folder,label,compiler,base['.input.bin'],config,folder/(label+'.image.bin'))

for field,value in [('image_sha256','0'*64),('source_sha256','1'*64),('output_sha256','2'*64),
                    ('core_u32',True),('source_unchanged',False)]:
    child=json.loads(base['.stdout.log']);receipt=json.loads(base['.receipt.json'])
    child[field]=value;receipt[field]=value
    changes={str(base_paths['.stdout.log']):json.dumps(child).encode(),
             str(base_paths['.receipt.json']):json.dumps(receipt).encode()}
    check('actual_child_reject_'+field,lambda changes=changes:join_with(changes),True)
child=json.loads(base['.stdout.log']);receipt=json.loads(base['.receipt.json'])
child['limits']['cpu_seconds']=11;receipt['limits']['cpu_seconds']=11
check('actual_child_reject_changed_CPU_limit',lambda:join_with({
    str(base_paths['.stdout.log']):json.dumps(child).encode(),
    str(base_paths['.receipt.json']):json.dumps(receipt).encode()}),True)
for suffix in ('.output.bin','.image.bin'):
    raw=bytearray(base[suffix]);raw[0]^=1
    check('actual_child_reject_mutated'+suffix,
          lambda suffix=suffix,raw=bytes(raw):join_with({str(base_paths[suffix]):raw}),True)
child=json.loads(base['.stdout.log']);child['unexpected_extra']=1
check('actual_child_reject_stdout_receipt_extra_field',lambda:join_with({
    str(base_paths['.stdout.log']):json.dumps(child).encode()}),True)

actual_final=json.loads((PAIR/'FINAL.json').read_bytes())
request=json.loads((PAIR/'owner.json.request.json').read_bytes())
returned=actual_final['owner_returned']
check('actual_original_180_3_owner_producer_join',lambda:common.owner_readback(
    PAIR,returned,request['command'],request['env'],Path(request['cwd']),config)['natural'])
unknown=copy.deepcopy(returned);unknown['cleanup']['observed_echild']=False
check('actual_owner_reject_unknown_cleanup',lambda:common.owner_readback(
    PAIR,unknown,request['command'],request['env'],Path(request['cwd']),config),True)
bad=copy.deepcopy(returned);bad['supervisor_returncode']=False
check('actual_owner_reject_boolean_supervisor_return',lambda:common.owner_readback(
    PAIR,bad,request['command'],request['env'],Path(request['cwd']),config),True)

tree=ast.parse((CONTROL/'controller.py').read_bytes())
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
loop=next(n for n in ast.walk(main) if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='phase')
call_index=next(i for i,n in enumerate(loop.body) if isinstance(n,ast.Assign)
    and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='run_owned')
previous=loop.body[call_index-1]
check('owner_call_is_preceded_by_unknown_closed_state',lambda:
    isinstance(previous,ast.Assign) and isinstance(previous.targets[0],ast.Name)
    and previous.targets[0].id=='all_closed' and isinstance(previous.value,ast.Constant)
    and previous.value.value is False)

expected=list(config['development_method_map'])
suite={'loaded_ids':expected,'executed_ids':expected,'tests_run':12,'pass':True,
       **{n:[] for n in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses')}}
check('complete_12_method_population',lambda:controller.suite_ok(suite,expected))
for field in ('loaded_ids','executed_ids'):
    altered=copy.deepcopy(suite);altered[field]=altered[field][:-1]
    check('reject_omitted_'+field,lambda altered=altered:not controller.suite_ok(altered,expected))
altered=copy.deepcopy(suite);altered['skipped']=[[expected[0],'not executed']]
check('reject_skip_even_when_counts_claim_success',lambda:not controller.suite_ok(altered,expected))
after=common.external_inputs(config)
check('sealed_original_input_bytes_unchanged',lambda:before==after)
report={'schema':'hepta.hia.v86-development-readonly-control-check.v1',
        'status':'PASS' if all(r['pass'] for r in rows) else 'HOLD',
        'control_count':len(rows),'controls':rows,'prior_pair_inputs_before':before,'prior_pair_inputs_after':after,
        'control_sources':{name:common.small_pin(CONTROL/name) for name in ('common.py','controller.py','worker.py')},
        'config_sha256':sha256((CONTROL/'CONFIG.json').read_bytes()).hexdigest(),
        'original_pair_native_executions_added':0,'new_v86_native_executions':0,
        'original_or_development_product_methods_executed':0,
        'negative_controls_use_explicit_in_memory_alterations_of_original_bytes':True}
common.write(OUT/'REPORT.json',report)
print(json.dumps({'status':report['status'],'control_count':len(rows),
                  'failed':[r['name'] for r in rows if not r['pass']],'product_executed':False}))
raise SystemExit(0 if report['status']=='PASS' else 1)
