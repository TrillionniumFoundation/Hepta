"""Read and join the complete original v81 source-stage evidence; no tests run."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

from common import *

def main():
    inventory=json.loads((HERE/'TEST-INVENTORY.json').read_bytes())
    expected=json.loads((HERE/'SOURCE-INITIAL.json').read_bytes())
    require(snapshot()==expected,'final complete source differs from frozen post-derivation source')
    require(inventory['complete_methods']==111 and inventory['source_methods']==81
            and inventory['native_methods_not_executed']==30,'original complete inventory differs')
    require(json.loads((HERE/'DERIVATION-ADMISSION.json').read_bytes())['status']=='DERIVATION_ORIGINALS_ACCEPTED',
            'actual original derivation not admitted')
    frozen=json.loads((HERE/'CONTROL-PINS.json').read_bytes())
    for name,row in frozen.items(): require(file_record(HERE/name)==row,'preexecution control differs')
    for group in inventory['source_groups']+inventory['native_groups_not_executed']:
        path=SOURCE/group['source_path'];require(file_record(path)==group['source'],'test module bytes changed')
        module=ast.parse(path.read_bytes());cls=next(n for n in module.body if isinstance(n,ast.ClassDef) and n.name==group['class'].rsplit('.',1)[1])
        methods={n.name:n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith('test_')}
        require([group['class']+'.'+n for n in sorted(methods)]==group['ids'],'complete method set drifted')
        require({n:sha256(ast.dump(methods[n],include_attributes=False).encode()).hexdigest() for n in sorted(methods)}
                ==group['method_ast_sha256'],'original method AST drifted')
    rows=[];all_ids=[];owners=[]
    for phase in ['caps']+[f'class-{i}' for i in range(8)]:
        root=HERE/('actual-'+phase)
        acceptance=json.loads((root/'ACCEPTANCE.json').read_bytes())
        request=json.loads((root/'guard/request.json').read_bytes())
        guardian=json.loads((root/'guard/guardian.json').read_bytes())
        report=json.loads((root/'stage/report.json').read_bytes())
        natural_guardian(guardian,request)
        require(acceptance['status']=='PASS' and acceptance['supervisor_returncode']==0
            and acceptance['request_sha256']==sha256((root/'guard/request.json').read_bytes()).hexdigest()
            and acceptance['worker_report']==file_record(root/'stage/report.json')
            and acceptance['guardian']==file_record(root/'guard/guardian.json'), 'original acceptance join failed')
        require(acceptance['source_changes']==[] and acceptance['source_preserved_except_declared_derivation'] is True
            and json.loads((root/'source-before.json').read_bytes())==expected
            and json.loads((root/'source-after.json').read_bytes())==expected,'phase complete source mismatch')
        require(report['status']=='PASS' and report['phase']==phase,'worker result mismatch')
        for path,digest in request['source_identities'].items():
            require(sha256(Path(path).read_bytes()).hexdigest()==digest,'current pinned input differs')
        for path,digest in guardian['logs'].items():require(sha256(Path(path).read_bytes()).hexdigest()==digest,'log join differs')
        events=guardian['lifecycle']['events'];owner_elapsed=events[-1]['monotonic_ns']-events[0]['monotonic_ns']
        row={'phase':phase,'worker_elapsed_ns':report['elapsed_ns'],'driver_elapsed_ns':acceptance['driver_elapsed_ns'],
            'owner_started_to_reaped_ns':owner_elapsed,'source_files':len(expected),'immutable_inputs':len(request['source_identities']),
            'guardian':file_record(root/'guard/guardian.json'),'report':file_record(root/'stage/report.json'),
            'natural_180_3':True,'full_source_unchanged':True}
        if phase!='caps':
            index=int(phase.split('-')[1]);group=inventory['source_groups'][index]
            test=json.loads((root/'stage/unittest-result.json').read_bytes())
            require(test==report['observations'],'unittest report serialization differs')
            require(test['class']==group['class'] and test['loaded_ids']==test['executed_ids']==test['successful_ids']==group['ids']
                and test['tests_run']==test['loaded']==group['count'],'original complete class count/order mismatch')
            require(all(not test[k] for k in ('errors','failures','skipped','expected_failures','unexpected_successes','loader_errors')),
                'source suite anomaly')
            require(all(s['passed'] is True for s in test['subtests']),'original subtest failed')
            row.update(test_class=group['class'],tests=group['count'],subtests=len(test['subtests']),
                       unittest_elapsed_ns=test['elapsed_ns'],original_unittest_log=file_record(root/'stage/unittest.log'))
            all_ids.extend(test['executed_ids']);owners.append(owner_elapsed)
        rows.append(row)
    require(len(all_ids)==len(set(all_ids))==81,'complete original81 denominator differs')
    caps=json.loads((HERE/'actual-caps/stage/report.json').read_bytes())['observations']
    maxima={key:max(r[key] for r in caps['per_function']) for key in (
        'blocks','operations','max_ssa_index_all_definitions_and_uses','distinct_ssa_names','function_parameters',
        'max_block_parameters','max_operation_arguments','max_edge_arguments','function_results','max_operation_results')}
    changed=subprocess.check_output(['git','diff','--name-only'],cwd=SOURCE).decode().splitlines()
    exact=['docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json',
           'examples/hia_bootstrap/selfhost.hiaasm','tools/generate_hia_selfhost.py','tools/hia_selfhost_contract.py']
    require(sorted(changed)==exact,'product delta is not exactly the five authorized files')
    delta=[]
    for name in exact:
        old=subprocess.check_output(['git','show','HEAD:'+name],cwd=SOURCE)
        delta.append({'path':name,'base_bytes':len(old),'base_sha256':sha256(old).hexdigest(),'actual':file_record(SOURCE/name)})
    result={'schema':'hia.v81.complete-source-validation.v1','status':'SOURCE_81_AND_COMPLETE_CAPS_PASS',
            'scope':'eight complete original source classes, independently owned; not native/cold/full qualification',
            'source_methods_loaded':81,'source_methods_executed':81,'source_ids':all_ids,'source_groups':rows[1:],
            'whole_original_inventory':111,'native_methods_not_executed':30,'native_groups_not_executed':inventory['native_groups_not_executed'],
            'original_derivation_reader_HOLD_preserved':True,'derivation_replayed':False,
            'cap_stage':rows[0],'actual_caps':caps['totals'],'per_function_maxima':maxima,
            'complete_original_125_function_capacity_ledger':file_record(HERE/'actual-caps/stage/report.json'),
            'assembly':caps['assembly'],'core':caps['core'],'roundtrip':caps['assembly_core_roundtrip'],
            'full_tracked_source_count':len(expected),'full_tracked_bytes':sum(x['bytes'] for x in expected.values()),
            'eight_owner_started_to_reaped_ns_sum':sum(owners),
            'eight_stage_timing_is_not_a_single_180_second_run':True,'native_performance_measured':False,
            'full_5400_executed':False,'original_180_3_and_3_5_caller_limits_unchanged':True,
            'product_delta':delta,'initial_manifest':file_record(HERE/'SOURCE-INITIAL.json'),
            'all_original_logs_requests_receipts_retained':True,'historical_descendant_inventory_complete_claimed':False}
    save(HERE/'FINAL-SOURCE-VALIDATION.json',wire(result))
    save(HERE/'PRODUCT-DELTA.json',wire(delta))
    print(json.dumps({'status':result['status'],'classes':8,'methods':81,'native_unexecuted':30,
        'caps':caps['totals'],'per_function_maxima':maxima,'owner_sum_ns':sum(owners),'product_delta':delta},sort_keys=True))

if __name__=='__main__':main()
