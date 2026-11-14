"""Original 369 owner and closed-only readback for two CPython author calls."""
from pathlib import Path
import importlib.util
import hashlib
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
import pager_generation_r1 as generation

ROOT = support.ROOT

def load_owner():
    path = ROOT/'qualification/process_owner_impl.py'
    spec = importlib.util.spec_from_file_location('pager_original_369_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def read_generation(request, output, worker):
    directory=Path(output)/'generation'
    manifest_pin,manifest_raw=common.read(directory/'GENERATION.json',4<<20)
    manifest=json.loads(manifest_raw)
    common.require(manifest_pin==worker['generation'],
                   'actual generation manifest pin from the closed worker')
    names={'GENERATION.json'}
    records={}
    for label,name in generation.AUTHORS:
        names.update(label+suffix for suffix in ('.core.json','.hiaasm','.GENERATION.json'))
        core_pin,core_raw=common.read(directory/(label+'.core.json'),4<<20)
        assembly_pin,assembly=common.read(directory/(label+'.hiaasm'),1<<20)
        document=json.loads(core_raw)
        common.require(common.wire(document)==core_raw,'complete canonical Core body')
        values=generation.cap_values(document,assembly)
        expected={
            'author':request['inputs']['inputs/tools/'+name+'.py'],
            'core':core_pin,'assembly':assembly_pin,'caps':values,
            'cap_limits':generation.CAPS,'native_or_VM_executed':False}
        _,report_raw=common.read(directory/(label+'.GENERATION.json'),4<<20)
        common.require(report_raw==common.wire(expected),
                       'full per-author actual products and original caps')
        records[label]=expected
    expected={
        'schema':'hia.sqlite-pager.finite-generation.v1',
        'status':'TWO_CORE_ASSEMBLY_CAPS_PASS_ONLY',
        'parts':{name:request['inputs']['inputs/tools/'+name+'.py']
                 for name in generation.PARTS},
        'programs':records,
        'retained_hia_source':{
            'before':request['inputs']['inputs/tools/sqlite_pager_retained_owner.hia'],
            'after':request['inputs']['inputs/tools/sqlite_pager_retained_owner.hia']},
        'native_or_VM_executed':False}
    common.require(manifest_raw==common.wire(expected)
        and common.wire(worker['programs'])==common.wire(records),
        'exact two complete generations and full retained-source before/after')
    actual=support.catalog(directory)
    common.require({row['relative_path'] for row in actual['files']}==names
        and actual['file_count']==7,'exact seven generation originals')
    return {'manifest':manifest_pin,'programs':records,
            'caps_independently_recomputed':True,
            'roundtrip_checks_executed_only_inside_original_owner':True,
            'CPython_author_tooling':True}

def main():
    path = Path(sys.argv[1])
    pin, raw = common.read(path, 1 << 20)
    common.require(pin['sha256'] == sys.argv[2], 'exact frozen Pager request SHA')
    q = policy.validate(json.loads(raw), pin, new_output=True)
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20, 4 << 20))
    output = Path(q['output'])
    capacity = support.capacity(ROOT.parent, True)
    runtime = support.runtime(q)
    before = support.input_records(q)
    source_before = support.source_records(q)
    system_before = support.system_records(q)
    common.require(all(len(common.wire(value)) <= 4 << 20
                       for value in (before, source_before, system_before)),
                   'complete original snapshots fit the unchanged physical file limit')
    with common.held_parent(output) as (parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)
    (output/'tmp').mkdir(mode=0o700)
    common.create(output/'REQUEST.original.json', raw, raw=True)
    common.create(output/'PARENT-INPUTS-BEFORE.json', before)
    common.create(output/'PARENT-SOURCE-BEFORE.json', source_before)
    common.create(output/'PARENT-SYSTEM-BEFORE.json', system_before)
    final = {
        'schema': 'hia.sqlite-pager.retained-generation-final.v1',
        'status': 'HOLD', 'request': pin, 'runtime': runtime,
        'initial_capacity': capacity, 'owner_closed': False, 'owner_natural': False,
        'errors': [], 'output': str(output),
        'CPython_author_tooling': True,
        'native_execution_authorized': False,
        'VM_execution_authorized': False,
        'interop_qualification': False,
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
        common.require(worker['schema'] == 'hia.sqlite-pager.retained-generation-worker.v1'
            and worker['status'] == 'TWO_HIA_GENERATIONS_PASS_ONLY'
            and worker['exception'] is None and worker['request'] == pin
            and worker['generation_started'] is True
            and worker['generation_completed'] is True
            and worker['CPython_author_tooling'] is True
            and worker['native_execution_authorized'] is False
            and worker['VM_execution_authorized'] is False
            and worker['interop_qualification'] is False
            and worker['matching_current_cold_compiler'] is False
            and worker['full_SQLite_or_AgentStore_qualification'] is False
            and type(worker['elapsed_ns']) is int
            and 0 <= worker['elapsed_ns'] <= 180000000000,
            'complete actual generation-only worker result')
        final['worker'] = wp
        final['generation'] = read_generation(q, output, worker)
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
        final['status'] = 'FINITE_PAGER_GENERATION_PASS_ONLY'
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
        if final['status'] == 'FINITE_PAGER_GENERATION_PASS_ONLY':
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
        if final['status'] == 'FINITE_PAGER_GENERATION_PASS_ONLY':
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
