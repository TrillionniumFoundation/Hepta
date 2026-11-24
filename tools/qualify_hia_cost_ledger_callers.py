"""Qualify seven complete ordinary caller modules with the old ledger forbidden.

The four identified integrations with their own administrator bundles keep
separate original gates; this command never adds an unpinned helper to them.
It does not claim a whole-project dynamic-caller or whole-native closure.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''): sys.path.insert(0, str(ROOT))
FIXTURE_NAME = 'tests/fixtures/cost_ledger_callers_b569c210.json'
FIXTURE_SHA256 = '18a7328a337344cc1f64c7df4d7487b7e94cb48d110fa4d70b5b947fcb538d1a'


_DIAGNOSTICS_CALLER = 'tests/test_hia_agent_native_tools.py'
_DIAGNOSTICS_HELPER = 'tests/hia_caller_diagnostics_admission.py'
_DIAGNOSTICS_HELPER_PIN = {'bytes': 5185, 'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578'}
_DIAGNOSTICS_AUTHORITY = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTICS_AUTHORITY_PIN = {'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'}


def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _admit_diagnostic_source(capture, name, raw, original_digest):
    if name == 'tests/test_hia_agent_native_machine_validation.py':
        from tests import hia_final_source_successor as final
        helper = capture('tests/hia_final_source_successor.py')
        if (_source_pin(helper) != {'bytes': 7012, 'sha256': '68ffd7b27fbd492915221a5894c7c1eb4f0101001b9fd400481e19cdf19744f7'}
                or Path(final.__file__).read_bytes() != helper):
            raise ValueError('complete machine caller source helper changed')
        return final.admit_machine_caller(capture, name, raw, original_digest)
    if name != _DIAGNOSTICS_CALLER:
        raise ValueError('an original complete caller module changed: ' + name)
    helper, authority = capture(_DIAGNOSTICS_HELPER), capture(_DIAGNOSTICS_AUTHORITY)
    if (_source_pin(helper) != _DIAGNOSTICS_HELPER_PIN
            or _source_pin(authority) != _DIAGNOSTICS_AUTHORITY_PIN):
        raise ValueError('caller diagnostic source authority changed')
    from tests import hia_caller_diagnostics_admission as diagnostic
    if Path(diagnostic.__file__).read_bytes() != helper:
        raise ValueError('caller imported a different diagnostic admission')
    if _source_pin(raw) != diagnostic.CURRENT:
        from tests import hia_final_source_successor as final
        final_source = capture('tests/hia_final_source_successor.py')
        if (_source_pin(final_source) != {'bytes': 7012, 'sha256': '68ffd7b27fbd492915221a5894c7c1eb4f0101001b9fd400481e19cdf19744f7'}
                or Path(final.__file__).read_bytes() != final_source):
            raise ValueError('complete caller diagnostic source helper changed')
        return final.admit_diagnostics(capture, name, raw, original_digest, authority, diagnostic)
    return diagnostic.admit(name, raw, original_digest, authority)


def bind_admission_to_source_capture(proof, source_digests):
    for name, expected in proof['captured_files'].items():
        if source_digests.get(name) != expected['sha256']:
            raise ValueError('caller admission differs from actual source capture: ' + name)



def admit_original_callers(root):
    """Keep the original seven modules/81 IDs with one exact diagnostic relation."""
    root, captured = Path(root), {}

    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('cost caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    fixture_bytes = capture(FIXTURE_NAME)
    if sha256(fixture_bytes).hexdigest() != FIXTURE_SHA256:
        raise ValueError('original cost-ledger caller inventory changed')
    original = json.loads(fixture_bytes)
    modules = original['modules']
    caller_files = {name.replace('.', '/') + '.py' for name in modules}
    if (original.get('schema') != 'hepta.hia.cost-ledger-original-callers.v1'
            or len(modules) != 7 or len(original['ordered_ids']) != 81):
        raise ValueError('the seven ordinary original caller modules differ')
    diagnostics = {}
    for name in sorted(caller_files):
        raw = capture(name)
        digest = original['original_source_sha256'][name]
        if sha256(raw).hexdigest() != digest:
            diagnostics[name] = _admit_diagnostic_source(capture, name, raw, digest)
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('cost caller captured bytes changed: ' + name)
    return original, {
        'schema': 'hepta.hia.cost-ledger-caller-source-admission.v1',
        'authority': {'path': FIXTURE_NAME, **_source_pin(fixture_bytes)},
        'original_files': {name: original['original_source_sha256'][name]
                           for name in sorted(caller_files)},
        'original_modules': list(modules), 'original_ordered_ids': list(original['ordered_ids']),
        'reviewed_diagnostic_source_adjustments': diagnostics,
        'captured_files': {name: _source_pin(raw) for name, raw in captured.items()},
        'terminal_reread_identical': True, 'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [], 'whole_native': False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report',type=Path)
    choice.add_argument('--development-manifest',type=Path)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_cost_ledger import INPUTS
    original,source_admission=admit_original_callers(ROOT)
    modules=original['modules']
    caller_files={name.replace('.','/')+'.py' for name in modules}
    suite,planned=load_declared_suite(modules);planned=list(planned)
    if planned!=original['ordered_ids']: raise ValueError('original complete 81-method caller inventory differs')
    def source_pins():
        return {**file_digests(),**{name:sha256((ROOT/name).read_bytes()).hexdigest()
                                   for name in (*INPUTS,*sorted(caller_files),*source_admission['captured_files'])}}
    before=source_pins()
    bind_admission_to_source_capture(source_admission,before)
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_cost_ledger import build
        cold=json.loads(args.cold_report.read_bytes());nested=json.loads(Path(cold['nested_report']).read_bytes())
        manifest=build(args.evidence/'qualified',Path(nested['generations'][-1]['produced_image']),args.cold_report)
        scope='MATCHING_SOURCE_COLD_SEVEN_ORDINARY_COST_LEDGER_CALLER_MODULES'
    else:
        manifest=args.development_manifest.resolve(strict=True)
        scope='EXPLICIT_DEVELOPMENT_SEVEN_ORDINARY_COST_LEDGER_CALLER_MODULES'
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_cost_ledger_native import CostLedgerFrame, SELECTOR, installed_cost_ledger
    image=installed_cost_ledger(str(manifest))
    bundle={str(path):sha256(path.read_bytes()).hexdigest() for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started,stopped,reference_calls=[],[],[]
    entries=Counter();frames=[0]
    class Result(unittest.TextTestResult):
        def startTest(self,test):started.append(test.id());super().startTest(test)
        def stopTest(self,test):stopped.append(test.id());super().stopTest(test)
    initializer,actual_entry=CostLedgerFrame.__init__,image._entry
    def counted_frame(frame,selected,*args,**kwargs):
        if selected is not image:raise AssertionError('ordinary caller selected another cost-ledger image')
        initializer(frame,selected,*args,**kwargs);frames[0]+=1
    def counted_entry(source,size,output,capacity,state,extent):
        code=actual_entry(source,size,output,capacity,state,extent)
        request=struct.unpack('<2Q',ctypes.string_at(source,16))
        if code!=(16 if request[1] in (10,11) else 80):raise AssertionError('ledger machine return differs')
        entries[str(request[1])]+=1
        return code
    def forbidden(*args,**kwargs):
        reference_calls.append(started[-1] if started else 'outside-test')
        raise AssertionError('ordinary caller entered retained Python cost-ledger policy')
    begin=time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ,{SELECTOR:str(manifest)}))
        stack.enter_context(patch.object(HIAAgentService,'_cost_ledger_reference',forbidden))
        stack.enter_context(patch.object(CostLedgerFrame,'__init__',counted_frame))
        stack.enter_context(patch.object(image,'_entry',counted_entry))
        with (args.evidence/'tests.log').open('x') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
    after=source_pins()
    bind_admission_to_source_capture(source_admission,after)
    stable=after==before and all(sha256(Path(name).read_bytes()).hexdigest()==digest for name,digest in bundle.items())
    anomalies=('errors','failures','skipped','expectedFailures','unexpectedSuccesses')
    clean=result.wasSuccessful() and all(not getattr(result,name) for name in anomalies)
    passed=clean and stable and started==stopped==planned and result.testsRun==81 and not reference_calls and frames[0]>0 and entries['10']>0 and entries['11']>0
    report={'schema':'hepta.hia.cost-ledger-seven-ordinary-callers.v1','status':'PASS' if passed else 'FAIL','scope':scope,
        'original_modules':modules,'planned':planned,'started':started,'stopped':stopped,
        'actual_tests':result.testsRun,'wall_seconds':time.monotonic()-begin,
        'errors':[(t.id(),e) for t,e in result.errors],'failures':[(t.id(),e) for t,e in result.failures],
        'skipped':[(t.id(),e) for t,e in result.skipped],'expected_failures':[(t.id(),e) for t,e in result.expectedFailures],
        'unexpected_successes':[t.id() for t in result.unexpectedSuccesses],
        'actual_ledger_frames':frames[0],'actual_native_event_counts':dict(entries),'native_image_sha256':image.image_sha256,
        'reference_calls':reference_calls,'retained_ledger_body_forbidden':True,
        'reference_poison_scope':'test process; subprocesses inherit selector, not Python patches',
        'all_seven_ordinary_modules_unfiltered':True,'original_test_budgets_changed':False,
        'source_and_bundle_unchanged':stable,'source_pins':before,'source_after':after,
        'caller_source_admission':source_admission,'bundle_pins':bundle,
        'separate_original_administrator_scope_gates':original['explicit_scope_integration_modules'],
        'whole_project_dynamic_caller_closure_claimed':False,'whole_native_delivery_qualified':False}
    (args.evidence/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({key:report[key] for key in ('status','scope','actual_tests','wall_seconds','actual_ledger_frames')}))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
