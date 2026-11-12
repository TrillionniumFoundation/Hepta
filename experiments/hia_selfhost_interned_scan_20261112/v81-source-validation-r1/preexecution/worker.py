"""Run one original source-only stage under the unchanged external guardian."""
import argparse
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, SOURCE, GROUPS, SUPPORT, COVERAGE, require, save, wire, file_record
sys.path.insert(0, str(SOURCE))

def derive(out):
    commands = [
        [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract'],
        [sys.executable, '-B', '-m', 'tests.test_hia_selfhost_language_coverage', '--generate-inventory'],
        [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract'],
        [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract', '--check'],
    ]
    rows = []
    try:
        for i, command in enumerate(commands):
            with (out / f'command-{i}.stdout.log').open('xb') as stdout, (out / f'command-{i}.stderr.log').open('xb') as stderr:
                start = time.monotonic_ns()
                result = subprocess.run(command, cwd=SOURCE, stdout=stdout, stderr=stderr, check=False)
            row = {'command': command, 'returncode': result.returncode,
                   'elapsed_ns': time.monotonic_ns() - start,
                   'stdout': file_record(out / f'command-{i}.stdout.log'),
                   'stderr': file_record(out / f'command-{i}.stderr.log')}
            rows.append(row); save(out / f'command-{i}.json', wire(row))
            require(result.returncode == 0, f'original derived-source command {i} failed')
        from tools.hia_selfhost_contract import validate_contract, support_contract
        from tests.test_hia_selfhost_language_coverage import validate_inventory, coverage_manifest
        contract = validate_contract(); validate_inventory()
        require((SOURCE / SUPPORT).read_bytes() == wire(support_contract()), 'support raw bytes not reproducible')
        require((SOURCE / COVERAGE).read_bytes() == wire(coverage_manifest()), 'coverage raw bytes not reproducible')
        return {'commands': rows, 'profile': contract['profile'], 'declared_sources': len(contract['source_identity']['files']),
                'support': file_record(SOURCE / SUPPORT), 'coverage': file_record(SOURCE / COVERAGE)}
    finally:
        for name in (SUPPORT, COVERAGE):
            if (SOURCE / name).is_file():
                save(out / Path(name).name, (SOURCE / name).read_bytes())

def cap_check(out):
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from hepta.hia_program import verify_program
    from tools.hia_selfhost_contract import validate_contract
    from tools import hia_selfhost_limits
    raw = (SOURCE / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
    checked = assemble_program(raw); doc = checked.as_dict()
    require(render_assembly(checked).encode() == raw, 'assembly rendering differs')
    require(verify_program(checked.canonical_bytes).canonical_bytes == checked.canonical_bytes, 'Core reparse differs')
    require(assemble_program(render_assembly(doc)).canonical_bytes == checked.canonical_bytes, 'Core assembly roundtrip differs')
    stack=[doc]; structural_nodes=0
    while stack:
        node=stack.pop(); structural_nodes+=1
        if isinstance(node,dict): stack.extend(node.values())
        elif isinstance(node,list): stack.extend(node)
    require(structural_nodes<=262144, 'original structural node cap exceeded')
    limit = validate_contract()['limits']
    fixed = {'source_bytes': 1048576, 'output_capacity_bytes': 1048576, 'workspace_required_bytes': 1048576,
             'functions': 128, 'blocks_per_function': 256, 'blocks_total': 1536, 'instructions': 8192,
             'ssa_names_per_function': 2048, 'ssa_index_max': 2047, 'parameters_or_arguments': 16,
             'relative_relocations': 12000, 'core_structural_nodes': 262144}
    require(all(limit[k] == v for k,v in fixed.items()), 'original profile bounds changed')
    require(hia_selfhost_limits.MAX_INSTRUCTIONS == 8192 and hia_selfhost_limits.MAX_CORE_NODES == 262144,
            'authoring limits changed')
    def value_ids(x):
        if isinstance(x, str) and re.fullmatch(r'v[0-9]+', x):
            yield int(x[1:])
        elif isinstance(x, dict):
            for value in x.values(): yield from value_ids(value)
        elif isinstance(x, list):
            for value in x: yield from value_ids(value)
    rows=[]; edge_count=0
    for fn in doc['functions']:
        blocks=fn['blocks']; ops=[op for b in blocks for op in b['ops']]
        edges=[]
        for b in blocks:
            term=b['term']
            if term['op']=='jump': edges.append(term['args'])
            elif term['op']=='branch': edges.extend([term['then']['args'],term['else']['args']])
        ids=list(value_ids(fn)); edge_count+=len(edges)
        row={'function':fn['name'], 'blocks':len(blocks), 'operations':len(ops),
             'max_ssa_index_all_definitions_and_uses':max(ids,default=-1), 'distinct_ssa_names':len(set(ids)),
             'function_parameters':len(fn['params']), 'max_block_parameters':max(map(lambda b:len(b['params']),blocks),default=0),
             'max_operation_arguments':max(map(lambda op:len(op['args']),ops),default=0),
             'edges':len(edges), 'max_edge_arguments':max(map(len,edges),default=0),
             'function_results':len(fn['returns']), 'max_operation_results':max(map(lambda op:len(op['out']),ops),default=0)}
        require(row['blocks']<=256 and row['max_ssa_index_all_definitions_and_uses']<=2047
                and row['distinct_ssa_names']<=2048, 'per-function capacity exceeded: '+fn['name'])
        require(all(row[k]<=16 for k in ('function_parameters','max_block_parameters','max_operation_arguments','max_edge_arguments')),
                '16-item parameter/argument/edge bound exceeded: '+fn['name'])
        require(row['function_results']<=3 and row['max_operation_results']<=3, 'result capacity exceeded')
        rows.append(row)
    totals={'source_bytes':len(raw),'lines':len(raw.splitlines()),'max_line_bytes':max(map(len,raw.splitlines())),
            'functions':len(rows),'blocks':sum(r['blocks'] for r in rows),'operations':sum(r['operations'] for r in rows),
            'edges':edge_count,'core_bytes':len(checked.canonical_bytes),'core_structural_nodes':structural_nodes}
    require(totals['source_bytes']<=1048576 and totals['lines']<=16384 and totals['max_line_bytes']<=16384
            and totals['functions']<=128 and totals['blocks']<=1536 and totals['operations']<=8192,
            'original compiler global cap exceeded')
    save(out/'selfhost.core.json',checked.canonical_bytes)
    save(out/'selfhost.hiaasm',raw)
    return {'totals':totals,'limits':fixed,'per_function':rows,'core':file_record(out/'selfhost.core.json'),
            'assembly':file_record(out/'selfhost.hiaasm'),'assembly_core_roundtrip':True,
            'native_compilation':False,'native_reverse_1536_executed':False}

def suite(out, index):
    expected=json.loads((HERE/'TEST-INVENTORY.json').read_bytes())['source_groups'][index]
    require(expected['class']==GROUPS[index][0], 'wrong original class')
    module_name,class_name=expected['class'].rsplit('.',1)
    module=importlib.import_module(module_name)
    require(Path(module.__file__).resolve()==SOURCE/Path(*module_name.split('.')).with_suffix('.py'), 'test module origin differs')
    loader=unittest.TestLoader(); loaded=loader.loadTestsFromTestCase(getattr(module,class_name))
    def flatten(s):
        for test in s:
            if isinstance(test,unittest.TestSuite): yield from flatten(test)
            else: yield test
    loaded_ids=[test.id() for test in flatten(loaded)]
    require(not loader.errors and loaded_ids==expected['ids'], 'complete loaded test IDs differ')
    executed=[]; success=[]; subtests=[]
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            executed.append(test.id()); super().startTest(test)
        def addSuccess(self,test):
            success.append(test.id()); super().addSuccess(test)
        def addSubTest(self,test,subtest,err):
            subtests.append({'test':test.id(),'subtest':str(subtest),'passed':err is None})
            super().addSubTest(test,subtest,err)
    with (out/'unittest.log').open('x') as log:
        start=time.monotonic_ns()
        result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(loaded)
    report={'class':expected['class'],'loaded_ids':loaded_ids,'executed_ids':executed,'successful_ids':success,
            'loaded':len(loaded_ids),'tests_run':result.testsRun,'elapsed_ns':time.monotonic_ns()-start,
            'failures':[{'test':t.id(),'detail':d} for t,d in result.failures],
            'errors':[{'test':t.id(),'detail':d} for t,d in result.errors],
            'skipped':[{'test':t.id(),'reason':d} for t,d in result.skipped],
            'expected_failures':[{'test':t.id(),'detail':d} for t,d in result.expectedFailures],
            'unexpected_successes':[t.id() for t in result.unexpectedSuccesses],
            'subtests':subtests,'loader_errors':loader.errors}
    save(out/'unittest-result.json',wire(report))
    require(result.testsRun==len(loaded_ids)==GROUPS[index][1] and executed==loaded_ids and success==loaded_ids
            and all(not report[k] for k in ('failures','errors','skipped','expected_failures','unexpected_successes','loader_errors')),
            'original source class did not completely pass')
    return report

def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output
    result={'schema':'hia.v81.source-stage.v1','phase':a.phase,'status':'HOLD','native_or_cold_or_full_execution':False}
    start=time.monotonic_ns()
    try:
        if a.phase=='derive': value=derive(out)
        elif a.phase=='caps': value=cap_check(out)
        elif a.phase.startswith('class-'): value=suite(out,int(a.phase.split('-')[1]))
        else: raise RuntimeError('unknown fixed stage')
        result.update(status='PASS',observations=value)
    except BaseException as error:
        result['status']='HOLD';result['error']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
        traceback.print_exc()
    finally:
        result['elapsed_ns']=time.monotonic_ns()-start
        save(out/'report.json',wire(result))
    print(json.dumps({'status':result['status'],'phase':a.phase,'elapsed_ns':result['elapsed_ns']}),flush=True)
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__': raise SystemExit(main())
