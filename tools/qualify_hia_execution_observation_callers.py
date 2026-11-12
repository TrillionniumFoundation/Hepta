"""Run complete existing interpreter/resource callers with old ledger disabled."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))

ORIGINAL_MODULES=(
    'tests.test_hia_program','tests.test_hia_bulk_memory',
    'tests.test_hia_recursive_chain','tests.test_hia_returned_loans',
    'tests.test_hia_returned_loan_interfaces','tests.test_hia_returned_chain_loans',
    'tests.test_hia_returned_loan_budgets','tests.test_hia_execution_contract',
    'tests.test_hia_optimization_contract','tests.test_hia_agent_external_roots',
    'tests.test_hia_runtime_argument_snapshot','tests.test_hia_runtime_policy_predecode',
    'tests.test_hia_runtime_source_preflight',
)


def leaves(suite):
    for test in suite:
        if isinstance(test,unittest.TestSuite):yield from leaves(test)
        else:yield test


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report',type=Path)
    parser.add_argument('--development-manifest',type=Path)
    parser.add_argument('--evidence',required=True,type=Path)
    args=parser.parse_args()
    if bool(args.cold_report)==bool(args.development_manifest):
        parser.error('exactly one matching cold or explicit development bundle is required')
    from hepta import hia_opcodes as policy
    from hepta.hia_core_lowering_native import LoweringSession
    from hepta.hia_execution_observation_selection import SELECTOR,installed_execution_observation
    from tools.hia_selfhost_contract import file_digests
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    before=file_digests(ROOT)
    if args.cold_report:
        from tools.build_hia_execution_observation import build
        cold=json.loads(args.cold_report.read_bytes())
        nested=json.loads(Path(cold['nested_report']).read_bytes())
        manifest=build(args.evidence/'qualified',Path(nested['generations'][-1]['produced_image']),args.cold_report)
        scope='MATCHING_SOURCE_COLD_ORIGINAL_RUNTIME_CALLERS'
    else:
        manifest=args.development_manifest.resolve(strict=True)
        scope='EXPLICIT_DEVELOPMENT_COMPILER_REUSE_NOT_CURRENT_COLD'
    owner=installed_execution_observation(str(manifest),vars(policy))
    bundle_pins={}
    for path in sorted(manifest.parent.rglob('*')):
        if path.is_file():bundle_pins[str(path)]=sha256(path.read_bytes()).hexdigest()
    suite=unittest.defaultTestLoader.loadTestsFromNames(ORIGINAL_MODULES)
    planned=[test.id() for test in leaves(suite)]
    assert planned and len(set(planned))==len(planned)
    started=[];stopped=[];entries=Counter()
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            started.append(test.id());super().startTest(test)
        def stopTest(self,test):
            stopped.append(test.id());super().stopTest(test)
    original_step=LoweringSession.step
    def step(session,packet):
        status=original_step(session,packet)
        if session.owner is owner:entries[(struct.unpack_from('<Q',session.initial,24)[0],status)]+=1
        return status
    started_at=time.monotonic()
    with patch.dict(os.environ,{SELECTOR:str(manifest)}),patch.object(policy,
            '_reference_validate_execution_observation',side_effect=AssertionError('retained observation policy entered')),patch.object(
            LoweringSession,'step',step):
        with (args.evidence/'tests.log').open('x') as log:
            result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(suite)
    stable=(file_digests(ROOT)==before and all(sha256(Path(path).read_bytes()).hexdigest()==value
                                            for path,value in bundle_pins.items()))
    passed=(started==stopped==planned and result.testsRun==len(planned)
            and result.wasSuccessful() and all(not getattr(result,k) for k in
                ('errors','failures','skipped','expectedFailures','unexpectedSuccesses'))
            and {mode for mode,status in entries}=={row['number'] for row in owner.modes.values()}
            and {0,1,2}.issubset({status for mode,status in entries}) and stable)
    report=dict(status='PASS' if passed else 'FAIL',scope=scope,original_modules=ORIGINAL_MODULES,
        planned=planned,started=started,stopped=stopped,actual_tests=result.testsRun,
        wall_seconds=time.monotonic()-started_at,errors=[(t.id(),e) for t,e in result.errors],
        failures=[(t.id(),e) for t,e in result.failures],skipped=[(t.id(),e) for t,e in result.skipped],
        expected_failures=[(t.id(),e) for t,e in result.expectedFailures],
        unexpected_successes=[t.id() for t in result.unexpectedSuccesses],
        actual_mode_status_counts=[dict(mode=m,status=s,count=n) for (m,s),n in sorted(entries.items())],
        all_original_modules_unfiltered=True,retained_ledger_policy_forbidden=True,
        source_and_bundle_unchanged=stable,source_pins=before,bundle_pins=bundle_pins,
        whole_runtime_native=False,whole_native_delivery_qualified=False)
    (args.evidence/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','scope','actual_tests','wall_seconds')}))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
