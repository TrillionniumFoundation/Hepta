"""Freeze existing r4c source and its unexecuted request as Git input text.

No product module, HIA author, C compiler, owner or request is executed.
The JSON transport packet is outside the source/canonical member set.
"""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import json
import os
import stat

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1')
IMPLEMENTATION = ROOT / 'implementation-r4c'
REQUEST_ROOT = Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e')
OUTPUT = Path('/tmp/hia-cli-json-r4c-plan-publication-r1-20261112-e26e')
PARENT = '564f16a2b6dcb0bd22347a13ae7b5a4574afbd4f'
PREFIX = 'experiments/hia_cli_json_graph_20261112/implementation-r4c-source-plan-r1'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError('checkpoint readback differs')


def files(root):
    def identity(item):
        return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    result = {}
    for path in sorted(root.rglob('*')):
        item = path.lstat()
        if stat.S_ISDIR(item.st_mode):
            continue
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
            raise ValueError('checkpoint source must be regular single-link')
        if '__pycache__' in path.parts:
            raise ValueError('unexpected Python cache in source snapshot')
        raw = path.read_bytes()
        if identity(path.lstat()) != identity(item):
            raise ValueError('checkpoint source metadata changed')
        result[path.relative_to(root).as_posix()] = raw
    return result


def main():
    if OUTPUT.exists():
        raise ValueError('create-only checkpoint output already exists')
    if (REQUEST_ROOT / 'actual').exists() or any((REQUEST_ROOT / 'guardian' / name).exists()
            for name in ('guardian.json', 'child.stdout.log', 'child.stderr.log')):
        raise ValueError('unexecuted request unexpectedly has actual outputs')
    implementation = files(IMPLEMENTATION)
    request = files(REQUEST_ROOT)
    config = json.loads(request['control/CONFIG.json'])
    preexec = json.loads(request['PREEXEC.json'])
    materialization = json.loads(request['MATERIALIZATION.json'])
    for name, expected in config['source_pins'].items():
        if pin(request['source/' + name]) != expected:
            raise ValueError('source request pin differs: ' + name)
    for name, expected in preexec['source_overlay_files'].items():
        if pin(implementation['inputs/' + name]) != expected:
            raise ValueError('WIP/request overlay differs: ' + name)
    parse_rows = []
    for name, raw in sorted(implementation.items()):
        if name.endswith('.py'):
            ast.parse(raw, filename=name)
            parse_rows.append({'path': name, **pin(raw)})
    worker = request['control/source_authoring_worker.py']
    ast.parse(worker, filename='source-request/control/source_authoring_worker.py')
    contents = {'implementation/' + name: raw for name, raw in implementation.items()}
    contents.update({'source-request/' + name: raw for name, raw in request.items()})
    license_raw = (ROOT / 'implementation-r4b/reference/cpython-v3.12.14/LICENSE').read_bytes()
    contents['implementation/reference/cpython-v3.12.14/LICENSE'] = license_raw
    peer = ROOT / 'peer-reviews/integer-caught-done-current-v89-r1.json'
    if peer.is_file():
        contents['related-peer-reviews/integer-caught-done-current-v89-r1.json'] = peer.read_bytes()
    source_delta = {
        'schema': 'hia.cli-json.r4c.source-delta.v1', 'status': 'STATIC_WIP_SOURCE_REQUEST_NOT_EXECUTED',
        'previous_actual': PARENT,
        'implemented': [
            'Actual executing generator stack pointer held in C TLS while real frame.stacktop is -1; original frame and handled exception links restored before Python transport.',
            'Real localsplus CALL operands: method/self rewriting, consumed PushAndInit binder, generic callable then argument release, result pushed before generic eval breaker.',
            'Original operand primitives for truth, arithmetic, iteration, dict/list operations, format, tuple/string build, STORE_FAST and STORE_DEREF.',
            'Exact copied original do_raise, stopiteration_error and unbound/name helpers with whole-body inverse derivation receipts and PSF license.',
            'HIA body selects instructions, branches, actual exception-table depth/target, reverse operand unwind, lasti/error transfer and yield/return/error state.',
            'HIA lifetime separates traceback already handled from fresh error and retains normal owned None through actual frame clearing.',
            'Three original code packets compile retained source to metadata only; every code unit has exception lookup, including cache words for monitor_handled retry.'
        ],
        'concrete_open_bindings': {
            '240': 'Known scalar, sort and JSON generator CALL routing from actual callable identity and owned stack.',
            '241': 'Nested HIA generator SEND/FOR_ITER, throw/close and foreign iterator scheduling.',
            '242': 'Existing HIA UNPACK raw owned-stack export; public tuple adapter is not equivalent.',
            '243': 'Actual entry/resume/throw and monitoring.',
            '244': 'Original eval breaker and monitor events with original failing PC.'
        },
        'other_open_semantics': [
            'Complete C driver eliminating arbitrary Python transport allocations/GC between original instruction effects.',
            'Additional _PyEval_EvalFrameDefault entry for foreign exact Python calls still changes C recursion/entry structure; not declared equivalent to original inlined call.',
            'Runtime admission must bind every packet to actual code object, globals, closure cells, constants and names.',
            'Private C source has not been parsed, compiled, linked or executed; its complete runtime header/address provenance remains a later frozen compile request.',
            'Original 17 CLI callers, all 46 traces, original compiler line gate, native, installed, cold and full qualification are unexecuted for r4c.'
        ],
        'new_request': {
            'HIA_components': config['components'], 'packet_names': config['packet_names'],
            'owner_seconds': 180, 'cleanup_seconds': 3, 'limits': config['limits'],
            'source_files': len(config['source_pins']), 'all_input_count': preexec['all_input_count'],
            'source_bytes': preexec['source_bytes'], 'default_selector_changed': False,
            'old_source_requests_replayed': False
        },
        'static_corrections_preserved': [
            'Initial private op <=99 refusal of 100-112; owned return slot rejected across frame clear; helper extraction initially matched declaration.',
            'Executing frame originally exposed its logical stack instead of -1 sentinel.',
            'monitor_handled retry used old PC and packet omitted cache-word exception lookup.'
        ],
        'AST_only': parse_rows,
        'HIA_generation_executed': False, 'C_compilation_executed': False,
        'native_executed': False, 'original_17_executed': 0, 'trace_46_executed': 0,
    }
    contents['SOURCE-DELTA.json'] = wire(source_delta)
    handoff = {
        'schema': 'hia.cli-json.r4c.source-plan.handoff.v1',
        'status': 'FROZEN_SOURCE_ONLY_REQUEST_AWAITING_ROOT_REVIEW',
        'parent_commit': PARENT, 'canonical_prefix': PREFIX,
        'local_implementation': str(IMPLEMENTATION), 'local_request': str(REQUEST_ROOT),
        'previous_actual_not_replayed': PARENT,
        'command': preexec['command'], 'cwd': preexec['cwd'], 'environment': preexec['environment'],
        'request': preexec['request'], 'preexec': pin(request['PREEXEC.json']),
        'worker': pin(worker), 'python': preexec['python'],
        'components': config['components'], 'packet_names': config['packet_names'],
        'source_files': len(config['source_pins']), 'source_bytes': preexec['source_bytes'],
        'all_input_count': preexec['all_input_count'], 'owner_seconds': 180, 'cleanup_seconds': 3,
        'limits': config['limits'], 'materialization': pin(request['MATERIALIZATION.json']),
        'source_changes': materialization['changed_source_paths'],
        'source_additions': materialization['added_source_paths'],
        'expected_actual_root': preexec['expected_actual_root'],
        'expected_guardian_root': str(REQUEST_ROOT / 'guardian'),
        'expected_worker_success': preexec['expected_worker_status'],
        'current_actual_outputs_exist': False,
        'limits_exclusions': preexec['limits_exclusions'],
        'scope': 'Only syntax/Core round trip/nine caps for two new HIA components and three fixed code metadata packets. No old request or JSON body executes; C/native/17/46 are separate.',
        'original_plan_denominators': {'CLI': len(config['original_cli_ids']), 'traces': len(config['trace_plan_ids'])},
        'files': {name: pin(raw) for name, raw in sorted(contents.items())},
        'no_ref_or_workflow_trigger_requested': True,
    }
    contents['HANDOFF.json'] = wire(handoff)
    os.mkdir(OUTPUT, 0o700)
    for name in ('HANDOFF.json', 'SOURCE-DELTA.json'):
        create(OUTPUT / name, contents[name])
    packet = {'schema': 'hia.cli-json.r4c.git-publication-packet.v1', 'parent': PARENT,
              'prefix': PREFIX, 'files': [{
                  'path': PREFIX + '/' + name, 'mode': '100644',
                  **pin(raw), 'text': raw.decode('utf-8')}
                  for name, raw in sorted(contents.items())]}
    create(OUTPUT / 'PUBLICATION-PACKET.json', wire(packet))
    print(json.dumps({'output': str(OUTPUT), 'files': len(contents),
                      'bytes': sum(map(len, contents.values())),
                      'handoff': pin(contents['HANDOFF.json']),
                      'source_delta': pin(contents['SOURCE-DELTA.json']),
                      'execution': False}, sort_keys=True))


if __name__ == '__main__':
    main()
