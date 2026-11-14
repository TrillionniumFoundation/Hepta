"""One original 180+3 Pager qualification worker; future Root-only entry.

The worker generates/compiles only the two HIA programs and three fixed
bootstrap objects, then runs the four frozen real-file scenarios. It does not
provide database pages, issue SQLite locks, choose WAL frames, or build C engines.
"""
from pathlib import Path
import json
import os
import resource
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pager_common_r1 as common
import pager_support_r1 as support
import pager_policy_r1 as policy
from pager_reference_supply_r1 import inspect_supply
from pager_audit_stream_r3 import PhysicalBudget
from pager_build_r1 import build
from pager_interop_cases_r3 import run_cases

ROOT = support.ROOT

def main():
    path = Path(sys.argv[1])
    pin, raw = common.read(path, 1 << 20)
    common.require(pin['sha256'] == sys.argv[2], 'exact frozen Pager request SHA')
    q = policy.validate(json.loads(raw), pin, new_output=False)
    output = Path(q['output'])
    common.require(output.is_dir(), 'launcher-created private output')
    report = {
        'schema': 'hia.sqlite-pager.first-native-worker.v1',
        'status': 'HOLD', 'request': pin, 'exception': None,
        'secondary_errors': [], 'build_started': False, 'scenarios_started': False,
        'C_reference_compiles_here': 0, 'VM_test_execution_authorized': False,
        'assembly_transport_is_bootstrap': True,
        'matching_current_cold_compiler': False,
        'full_SQLite_or_AgentStore_qualification': False}
    started = time.monotonic_ns()
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
        resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
        resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
        # Keep worker writes at 4MiB. The unchanged disposable B3 child sets
        # its own historical 16MiB FSIZE hard limit before its 1MiB-ABI call.
        # build() irrevocably seals the worker to (4MiB,4MiB) after B3,
        # before GAS, the HIA linker entry, or any Pager/reference process.
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20, 16 << 20))
        owner_pin, parent = support.read_json(output/'lifecycle.json.request.json', 1 << 20)
        common.require(parent['command'] == support.command(q, pin['sha256'])
            and parent['cwd'] == str(ROOT) and parent['env'] == q['environment']
            and parent['qualification_seconds'] == 180 and parent['cleanup_seconds'] == 3
            and parent['deadline_ns']-parent['started_ns'] == 180000000000
            and parent['implementation_sha256'] ==
                q['inputs']['qualification/process_owner_impl.py']['sha256'],
            'worker uses the actual original-owner deadline, not a renewed 180s')
        report['owner_request'] = owner_pin
        deadline = parent['deadline_ns']/1000000000
        report['runtime'] = support.runtime(q)
        before = support.input_records(q)
        source_before = support.source_records(q)
        system_before = support.system_records(q)
        report['inputs_before'] = common.create(output/'WORKER-INPUTS-BEFORE.json', before)
        report['source_before'] = common.create(output/'WORKER-SOURCE-BEFORE.json', source_before)
        report['system_before'] = common.create(output/'WORKER-SYSTEM-BEFORE.json', system_before)
        report['reference_supply'] = inspect_supply(q)
        budget = PhysicalBudget(q['trace_budget_token'])
        report['build_started'] = True
        executable, layout, build_report = build(q, output/'build', budget=budget)
        report['build'] = common.read(output/'build/BUILD-REPORT.json', 4 << 20)[0]
        configuration = {
            'owner_seconds': 180, 'owner_grace_seconds': 3,
            'case_ids': policy.PROFILE['case_ids'],
            'session_nonces': q['session_nonces'],
            'trace_budget_token': q['trace_budget_token'],
            'hia_elf': executable, 'hia_elf_layout': layout,
            'sqlite_runtimes': report['reference_supply']['executables']}
        report['configuration'] = common.create(output/'ACTUAL-CONFIGURATION.json', configuration)
        common.require(time.monotonic() < deadline, 'original owner deadline before scenarios')
        report['scenarios_started'] = True
        cases = run_cases(configuration, output/'scenarios',
                          deadline=deadline, budget=budget)
        report['cases'] = common.create(output/'SCENARIOS.json', cases)
        common.require(cases['status'] == 'FINITE_FOUR_PROCESS_INTEROP_PASS_ONLY'
            and [item['id'] for item in cases['cases']] == policy.PROFILE['case_ids']
            and all(len(item['native_mappings']) == 2 for item in cases['cases'])
            and cases['prior_linker_trace_bytes_charged'] ==
                build_report['link']['physical_bytes']
            and cases['aggregate_physical_trace_bytes_charged'] == budget.used
            and cases['shared_index_bytes_still_reserved'] == budget.reserved == 0
            and budget.used <= 256 << 20,
            'all four scenarios, eight exact mappings and one shared physical budget')
        report['physical_trace_bytes'] = budget.used
        report['raw_expanded_bytes'] = (
            build_report['link']['raw_bytes']+
            sum(value['raw_bytes'] for value in cases['raw_readback']['processes'].values()))
        common.require(report['raw_expanded_bytes'] <= policy.TRACE['combined_expanded_bound'],
                       'complete three-domain expanded bound')
        report['imports'] = support.current_imports(q)
        after = support.input_records(q)
        source_after = support.source_records(q)
        system_after = support.system_records(q)
        report['inputs_after'] = common.create(output/'WORKER-INPUTS-AFTER.json', after)
        report['source_after'] = common.create(output/'WORKER-SOURCE-AFTER.json', source_after)
        report['system_after'] = common.create(output/'WORKER-SYSTEM-AFTER.json', system_after)
        common.require(before == after and source_before == source_after
                       and system_before == system_after, 'all frozen input identities unchanged')
        common.require(inspect_supply(q) == report['reference_supply'],
                       'closed external reference supplies unchanged')
        report['status'] = 'FINITE_PAGER_WORKER_INTEROP_PASS_ONLY'
    except BaseException as exc:
        report['status'] = 'HOLD'
        report['exception'] = type(exc).__module__+'.'+type(exc).__qualname__+': '+str(exc)[:1024]
        report['traceback'] = traceback.format_exc()
    finally:
        report['elapsed_ns'] = time.monotonic_ns()-started
        if report['elapsed_ns'] > 180000000000 or report['exception'] is not None:
            report['status'] = 'HOLD'
        common.create(output/'WORKER.json', report)
        print(json.dumps({'status': report['status'],
                          'build_started': report['build_started'],
                          'scenarios_started': report['scenarios_started'],
                          'elapsed_ns': report['elapsed_ns']}))
    return 0 if report['status'] == 'FINITE_PAGER_WORKER_INTEROP_PASS_ONLY' else 1

if __name__ == '__main__':
    raise SystemExit(main())
