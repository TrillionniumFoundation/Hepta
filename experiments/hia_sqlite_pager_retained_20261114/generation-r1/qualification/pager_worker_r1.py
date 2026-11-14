"""Two CPython author calls inside one unchanged 180+3 owner.

Only Core documents, assembly text, their original caps and roundtrips are
produced. No B3, GAS, VM, HIA entry, SQL, IPC, or original interop case runs.
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
from pager_generation_r1 import generate

ROOT = support.ROOT

def main():
    path = Path(sys.argv[1])
    pin, raw = common.read(path, 1 << 20)
    common.require(pin['sha256'] == sys.argv[2], 'exact frozen Pager request SHA')
    q = policy.validate(json.loads(raw), pin, new_output=False)
    output = Path(q['output'])
    common.require(output.is_dir(), 'launcher-created private output')
    report = {
        'schema': 'hia.sqlite-pager.retained-generation-worker.v1',
        'status': 'HOLD', 'request': pin, 'exception': None,
        'generation_started': False, 'generation_completed': False,
        'CPython_author_tooling': True,
        'native_execution_authorized': False,
        'VM_execution_authorized': False,
        'interop_qualification': False,
        'matching_current_cold_compiler': False,
        'full_SQLite_or_AgentStore_qualification': False}
    started = time.monotonic_ns()
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
        resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
        resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20, 4 << 20))
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
        common.require(time.monotonic() < deadline, 'original owner deadline before generation')
        report['generation_started'] = True
        report['programs'] = generate(q, output/'generation')
        report['generation'] = common.read(output/'generation/GENERATION.json', 4 << 20)[0]
        report['generation_completed'] = True
        common.require(time.monotonic() < deadline, 'same original owner deadline after both authors')
        report['imports'] = support.current_imports(q, source_before)
        after = support.input_records(q)
        source_after = support.source_records(q)
        system_after = support.system_records(q)
        report['inputs_after'] = common.create(output/'WORKER-INPUTS-AFTER.json', after)
        report['source_after'] = common.create(output/'WORKER-SOURCE-AFTER.json', source_after)
        report['system_after'] = common.create(output/'WORKER-SYSTEM-AFTER.json', system_after)
        common.require(before == after and source_before == source_after
                       and system_before == system_after, 'all frozen input identities unchanged')
        report['status'] = 'TWO_HIA_GENERATIONS_PASS_ONLY'
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
                          'generation_started': report['generation_started'],
                          'generation_completed': report['generation_completed'],
                          'elapsed_ns': report['elapsed_ns']}))
    return 0 if report['status'] == 'TWO_HIA_GENERATIONS_PASS_ONLY' else 1

if __name__ == '__main__':
    raise SystemExit(main())
