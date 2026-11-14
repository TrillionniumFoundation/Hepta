"""Original 369 owner and closed-only readback for one finite Pager request."""
from pathlib import Path
import importlib.util
import hashlib
import json
import os
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pager_common_r1 as common
import pager_support_r1 as support
import pager_policy_r1 as policy
from pager_reference_supply_r1 import inspect_supply
from pager_closed_build_readback_r1 import read_build
from pager_raw_readback_r3 import inspect_all

ROOT = support.ROOT

def load_owner():
    path = ROOT/'qualification/process_owner_impl.py'
    spec = importlib.util.spec_from_file_location('pager_original_369_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    path = Path(sys.argv[1])
    pin, raw = common.read(path, 1 << 20)
    common.require(pin['sha256'] == sys.argv[2], 'exact frozen Pager request SHA')
    q = policy.validate(json.loads(raw), pin, new_output=True)
    output = Path(q['output'])
    capacity = support.capacity(ROOT.parent, True)
    runtime = support.runtime(q)
    before = support.input_records(q)
    source_before = support.source_records(q)
    system_before = support.system_records(q)
    references = inspect_supply(q)
    with common.held_parent(output) as (parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)
    (output/'tmp').mkdir(mode=0o700)
    common.create(output/'REQUEST.original.json', raw, raw=True)
    common.create(output/'PARENT-INPUTS-BEFORE.json', before)
    common.create(output/'PARENT-SOURCE-BEFORE.json', source_before)
    common.create(output/'PARENT-SYSTEM-BEFORE.json', system_before)
    final = {
        'schema': 'hia.sqlite-pager.first-native-final.v1',
        'status': 'HOLD', 'request': pin, 'runtime': runtime,
        'initial_capacity': capacity, 'owner_closed': False, 'owner_natural': False,
        'errors': [], 'output': str(output),
        'assembly_transport_is_bootstrap': True,
        'matching_current_cold_compiler': False,
        'full_SQLite_or_AgentStore_qualification': False}
    started = time.monotonic_ns()
    try:
        owner = load_owner()
        returned = owner.run_owned(support.command(q, pin['sha256']),
            cwd=str(ROOT), env=q['environment'],
            stdout_path=output/'stdout.log', stderr_path=output/'stderr.log',
            receipt_path=output/'lifecycle.json',
            qualification_seconds=180, cleanup_seconds=3)
        common.create(output/'OWNER-RETURN.json', returned)
        lp, life = support.read_json(output/'lifecycle.json', 4 << 20)
        pp, parent = support.read_json(output/'lifecycle.json.request.json', 1 << 20)
        closed, natural = support.natural_owner(returned, life, parent, q, pin['sha256'], lp, pp)
        final['owner_closed'], final['owner_natural'] = closed, natural
        # The following is the FIRST enumeration/read of any child output by
        # this launcher. Unknown owner closure cannot reach this branch.
        originals = support.catalog(output)
        final['closed_originals'] = common.create(output/'CLOSED-ORIGINAL-CATALOG.json', originals)
        common.require(natural, 'closed natural failure retained; not a qualification pass')
        wp, worker = support.read_json(output/'WORKER.json', 4 << 20)
        common.require(worker['status'] == 'FINITE_PAGER_WORKER_INTEROP_PASS_ONLY'
            and worker['exception'] is None and worker['secondary_errors'] == []
            and worker['request'] == pin and worker['build_started'] is True
            and worker['scenarios_started'] is True
            and worker['C_reference_compiles_here'] == 0
            and worker['VM_test_execution_authorized'] is False
            and type(worker['elapsed_ns']) is int
            and 0 <= worker['elapsed_ns'] <= 180000000000,
            'complete actual finite worker result')
        final['worker'] = wp
        build = read_build(q, output/'build')
        final['independent_build'] = build
        cp, configuration = support.read_json(output/'ACTUAL-CONFIGURATION.json', 1 << 20)
        common.require(cp == worker['configuration']
            and configuration['owner_seconds'] == 180
            and configuration['owner_grace_seconds'] == 3
            and configuration['case_ids'] == policy.PROFILE['case_ids']
            and configuration['session_nonces'] == q['session_nonces']
            and configuration['trace_budget_token'] == q['trace_budget_token']
            and configuration['hia_elf'] == build['executable']
            and configuration['hia_elf_layout'] == build['ELF']
            and configuration['sqlite_runtimes'] == references['executables'],
            'actual exact executable and all fixed session inputs')
        sp, scenarios = support.read_json(output/'SCENARIOS.json', 4 << 20)
        joined = inspect_all(output/'scenarios', configuration, scenarios=scenarios['cases'])
        common.require(sp == worker['cases']
            and scenarios['status'] == 'FINITE_FOUR_PROCESS_INTEROP_PASS_ONLY'
            and scenarios['error'] is None
            and common.wire(joined) == common.wire(scenarios['raw_readback'])
            and [row['id'] for row in scenarios['cases']] == policy.PROFILE['case_ids']
            and sum(row['C_commands'] for row in scenarios['cases']) == 98
            and sum(row['HIA_client_commands'] for row in scenarios['cases']) == 40
            and all(row['status'] == 'SCENARIO_COMMANDS_COMPLETE_PENDING_RAW_AUDIT'
                    and len(row['native_mappings']) == 2 for row in scenarios['cases']),
            'complete four cases plus independently decoded 24 raw process streams')
        mappings = []
        for case in scenarios['cases']:
            native_children = {row['pid'] for row in case['children']
                               if row['process'].endswith(('old-reader', 'new-reader'))}
            common.require(len(native_children) == 2 and
                           {row['pid'] for row in case['native_mappings']} == native_children,
                           'actual recorded HIA mappings bind both real waited children')
            for row in case['native_mappings']:
                mp, maps_raw = common.read(row['maps']['path'], 1 << 20)
                common.require(mp == row['maps'] and row['elf'] == build['executable']
                    and row['entry'] == build['ELF']['entry']
                    and row['no_interpreter_or_host_library'] is True
                    and row['before_first_client_command'] is True
                    and [r['line'] for r in row['rows']] == maps_raw.decode('ascii').splitlines(),
                    'whole actual child maps original and fixed ELF binding')
                mappings.append({'pid': row['pid'], 'maps': mp})
        final['all_eight_recorded_native_mappings'] = mappings
        total = build['physical_linker_bytes']+joined['physical_trace_bytes']
        expanded = build['raw_linker_bytes']+sum(
            row['raw_bytes'] for row in joined['processes'].values())
        common.require(total == worker['physical_trace_bytes'] ==
                       scenarios['aggregate_physical_trace_bytes_charged']
            and scenarios['prior_linker_trace_bytes_charged'] == build['physical_linker_bytes']
            and scenarios['physical_trace_bytes_charged'] == joined['physical_trace_bytes']
            and scenarios['shared_index_bytes_still_reserved'] == 0
            and total <= policy.TRACE['physical_bytes_shared_including_indexes']
            and expanded == worker['raw_expanded_bytes'] <= policy.TRACE['combined_expanded_bound'],
            'one shared physical 256MiB and all expanded bytes')
        final['complete_raw_interop'] = joined
        final['physical_trace_bytes'] = total
        final['raw_expanded_bytes'] = expanded
        final['reference_supply'] = inspect_supply(q)
        common.require(final['reference_supply'] == references == worker['reference_supply'],
                       'same two closed external reference supplies')
        for name, expected in (('INPUTS', before), ('SOURCE', source_before), ('SYSTEM', system_before)):
            a_pin, a = support.read_json(output/('WORKER-'+name+'-BEFORE.json'))
            b_pin, b = support.read_json(output/('WORKER-'+name+'-AFTER.json'))
            common.require(a == b == expected
                and worker[name.lower()+'_before'] == a_pin
                and worker[name.lower()+'_after'] == b_pin,
                'full worker before/after source/system/input joins')
        after = support.input_records(q)
        source_after = support.source_records(q)
        system_after = support.system_records(q)
        common.require(before == after and source_before == source_after
                       and system_before == system_after, 'fresh complete parent input identity')
        final['inputs_after'] = common.create(output/'PARENT-INPUTS-AFTER.json', after)
        final['source_after'] = common.create(output/'PARENT-SOURCE-AFTER.json', source_after)
        final['system_after'] = common.create(output/'PARENT-SYSTEM-AFTER.json', system_after)
        final['capacity_after'] = support.capacity(output)
        final['status'] = 'FINITE_PAGER_FOUR_INTEROP_SCENARIOS_PASS_ONLY'
    except BaseException as exc:
        final['status'] = 'HOLD'
        final['errors'].append({'type': type(exc).__module__+'.'+type(exc).__qualname__,
                               'message': str(exc)[:1024], 'traceback': traceback.format_exc()})
    finally:
        final['elapsed_ns'] = time.monotonic_ns()-started
        terminal_success = False
        terminal_status = final['status']
        body = common.wire(final)
        pre_final = None
        if final['status'] == 'FINITE_PAGER_FOUR_INTEROP_SCENARIOS_PASS_ONLY':
            try:
                # Includes the original catalogue and all three PARENT-AFTER
                # originals. Serialize the complete FINAL body before admission;
                # it contains no self-referential size or hash.
                pre_final = support.catalog(output)
                common.require(all(row['relative_path'] != 'FINAL.json'
                                   for row in pre_final['files']),
                               'FINAL must be a new immutable original')
                common.require(pre_final['file_count']+1 <= 192
                    and pre_final['bytes']+len(body) <= 384 << 20,
                    'complete success tail exceeds unchanged 192/384MiB quota')
            except BaseException as exc:
                final['status'] = terminal_status = 'HOLD'
                final['errors'].append({
                    'stage': 'final_output_quota_preflight',
                    'type': type(exc).__module__+'.'+type(exc).__qualname__,
                    'message': str(exc)[:1024]})
                body = common.wire(final)
        final_pin = common.create(output/'FINAL.json', body, raw=True)
        if final['status'] == 'FINITE_PAGER_FOUR_INTEROP_SCENARIOS_PASS_ONLY':
            try:
                # Read the whole actual final directory before success. There
                # is no new success sidecar after this complete namespace gate.
                closed = support.catalog(output)
                old_rows = {row['relative_path']:
                            {key: value for key, value in row.items()
                             if key != 'relative_path'} for row in pre_final['files']}
                actual_rows = {row['relative_path']:
                               {key: value for key, value in row.items()
                                if key != 'relative_path'} for row in closed['files']}
                expected_rows = dict(old_rows)
                expected_rows['FINAL.json'] = final_pin
                common.require(len(old_rows) == pre_final['file_count']
                    and len(actual_rows) == closed['file_count']
                    and common.wire(actual_rows) == common.wire(expected_rows)
                    and closed['file_count'] == pre_final['file_count']+1 <= 192
                    and closed['bytes'] == pre_final['bytes']+len(body) <= 384 << 20
                    and final_pin['bytes'] == len(body)
                    and final_pin['sha256'] == hashlib.sha256(body).hexdigest(),
                    'actual final namespace/whole bytes/nine identities/quota mismatch')
                terminal_success = True
            except BaseException as exc:
                terminal_status = 'HOLD'
                failure = {
                    'schema': 'hia.sqlite-pager.final-output-quota-hold.v1',
                    'status': 'HOLD', 'original_FINAL': final_pin,
                    'original_FINAL_status_not_admitted': final['status'],
                    'stage': 'actual_final_output_quota_readback',
                    'type': type(exc).__module__+'.'+type(exc).__qualname__,
                    'message': str(exc)[:1024],
                    'no_original_overwritten_or_deleted': True}
                try:
                    common.create(output/'FINAL-QUOTA-HOLD.json', failure)
                except BaseException as secondary:
                    failure['hold_original_write_error'] = {
                        'type': type(secondary).__module__+'.'+type(secondary).__qualname__,
                        'message': str(secondary)[:1024]}
                print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        print(json.dumps({'status': terminal_status, 'owner_closed': final['owner_closed'],
                          'owner_natural': final['owner_natural'], 'output': str(output),
                          'final_output_quota_closed': terminal_success}))
    return 0 if terminal_success else 1

if __name__ == '__main__':
    raise SystemExit(main())
