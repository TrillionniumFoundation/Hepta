"""New r2 read-only joins for the original eight SQLite varint source methods."""
from pathlib import Path
import importlib.util
import json
import os
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('sqlite_source8_r2_common', ROOT / 'control/common.py')
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)
PUBLIC_FLAGS = ('native_executed', 'native_compiler_executed', 'C_oracle_compiled',
                'network_used', 'database_opened', 'product_qualification_executed')

def source_map(request):
    _, raw = common.read(ROOT / request['source_map'])
    value = json.loads(raw)
    rows = value['files']
    common.require(value['commit'] == request['source_commit']
                   == '0504beb11c0dae875d8590660c42488b7bc634fb'
                   and value['tree'] == request['source_tree']
                   == '596ab07e8813e4811a8dca51800cd51eb397aeb2'
                   and value['root'] == request['source_root']
                   and len(rows) == request['source_file_count'] == 1686
                   and sum(row['bytes'] for row in rows) == request['source_total_bytes'] == 40890650
                   and len({row['path'] for row in rows}) == len(rows),
                   'complete frozen physical source map differs')
    return rows

def source_records(request):
    root = Path(request['source_root'])
    common.require(root == ROOT / 'source-base', 'new exact restored source root differs')
    records = {}
    for expected in source_map(request):
        name = expected['path']
        common.require(type(name) is str and not name.startswith('/')
                       and '..' not in Path(name).parts, 'source path is not fixed relative')
        actual, _ = common.read(root / name)
        mode = '100755' if actual['identity'][2] & 0o111 else '100644'
        common.require(mode == expected['mode']
                       and all(actual[key] == expected[key] for key in ('bytes', 'sha256', 'git_blob')),
                       'current physical source byte/mode differs: ' + name)
        records[name] = actual
    observed = set()
    for base, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            current = (Path(base) / name).lstat()
            common.require(stat.S_ISDIR(current.st_mode), 'source directory link or special type')
        for name in names:
            path = Path(base) / name
            current = path.lstat()
            common.require(stat.S_ISREG(current.st_mode), 'source member is not regular')
            observed.add(str(path.relative_to(root)))
    common.require(observed == set(records), 'restored physical source namespace differs')
    return records

def imported_sources(request):
    expected = {str(Path(request['source_root']) / r['path']): r for r in source_map(request)}
    expected.update({str(ROOT / name): pin for name, pin in request['inputs'].items()
                     if name.startswith('candidate/inputs/') and name.endswith('.py')})
    observed = []
    for name, module in sorted(sys.modules.items()):
        if not (name == 'hepta' or name.startswith('hepta.') or name == 'tools'
                or name.startswith('tools.') or name == 'tests' or name.startswith('tests.')):
            continue
        filename = getattr(module, '__file__', None)
        if filename is None:
            common.require(name == 'tools', 'unexpected project namespace without source')
            observed.append({'module': name, 'namespace_only': True})
            continue
        path = str(Path(filename).resolve())
        common.require(path in expected and path.endswith('.py'), 'project import is outside frozen sources: ' + name)
        pin, _ = common.read(path)
        common.require(all(pin[k] == expected[path][k] for k in ('bytes', 'sha256', 'git_blob')),
                       'actual imported source bytes differ: ' + name)
        observed.append({'module': name, 'source': pin})
    common.require(any(r['module'] == request['test_module'] for r in observed),
                   'actual source test module missing')
    return observed

def hex_bytes(value):
    common.require(type(value) is str, 'VM buffer must be complete canonical hex')
    raw = bytes.fromhex(value)
    common.require(raw.hex() == value, 'VM buffer encoding is not canonical')
    return raw

def inspect_vm(request, output):
    pin, raw = common.read(output / 'tests/VM-RAW.json', 16 << 20)
    value = json.loads(raw)
    common.require(value.get('schema') == 'hia.sqlite-varint.source-vm-raw.v1'
                   and value.get('native_executed') is False and value.get('compiler_executed') is False
                   and type(value.get('calls')) is list and len(value['calls']) == 1618,
                   'whole original VM return population differs')
    expected = request['expected_vm_by_id']
    counts = {name: 0 for name in request['expected_ids']}
    sequence = []
    keys = {'case', 'actual_returned', 'status', 'source_before_hex', 'source_after_hex',
            'output_before_hex', 'output_after_hex', 'workspace_before_hex', 'workspace_after_hex'}
    for row in value['calls']:
        common.require(type(row) is dict and set(row) == keys
                       and row['case'] in counts and row['actual_returned'] is True
                       and type(row['status']) is int
                       and (1 <= row['status'] <= 9 or row['status'] in (0xfffffffc, 0xfffffffd, 0xfffffffe)),
                       'VM entry shape, actual return, ID or status differs')
        source_before, source_after = (hex_bytes(row[k]) for k in ('source_before_hex', 'source_after_hex'))
        before, after = (hex_bytes(row[k]) for k in ('output_before_hex', 'output_after_hex'))
        command_before, command_after = (hex_bytes(row[k]) for k in ('workspace_before_hex', 'workspace_after_hex'))
        common.require(source_before == source_after and command_before == command_after
                       and len(before) == len(after) and len(source_before) <= 10
                       and len(before) <= 10 and len(command_before) <= 17,
                       'whole VM input/control identity or output extent differs')
        if row['status'] >= 0xfffffffc:
            common.require(before == after, 'refused VM call mutated output')
        counts[row['case']] += 1
        sequence.append(row['case'])
    ordered = [name for name in request['expected_ids'] for _ in range(expected[name])]
    common.require(counts == expected and sequence == ordered, 'complete ordered per-method VM denominator differs')
    return {'pin': pin, 'actual_return_count': len(value['calls']), 'by_id': counts,
            'full_input_output_control_buffers_reread': True, 'all_returns_marked_actual': True}

def inspect_core(output):
    assembly_pin, assembly_raw = common.read(output / 'tests/sqlite_varint.hiaasm', 1 << 20)
    text = assembly_raw.decode('utf-8')
    common.require(len(text.split('\n')) <= 16384, 'original 16384-line limit exceeded')
    core_pin, core_raw = common.read(output / 'tests/CORE.json', 16 << 20)
    document = json.loads(core_raw)
    functions = document['functions']
    blocks = [b for f in functions for b in f['blocks']]
    operations = sum(len(b['ops']) for b in blocks)
    common.require(len(functions) == 6 <= 128 and len(blocks) <= 1536 and operations <= 8192,
                   'original total compiler limits differ')
    seen_ssa = []
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('args', 'params') and isinstance(item, list):
                    common.require(len(item) <= 16, 'original 16 argument limit exceeded')
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and value.startswith('v') and value[1:].isdigit():
            seen_ssa.append(int(value[1:]))
    walk(document)
    common.require(seen_ssa and max(seen_ssa) <= 2047, 'original SSA capacity exceeded')
    for function in functions:
        common.require(len(function['blocks']) <= 256 and len(function['returns']) <= 3,
                       'original per-function block/return limit exceeded')
        for block in function['blocks']:
            for op in block['ops']:
                common.require(len(op.get('out', [])) <= 3, 'original result limit exceeded')
    return {'assembly': assembly_pin, 'core': core_pin, 'lines': len(text.split('\n')),
            'functions': len(functions), 'blocks': len(blocks), 'operations': operations,
            'maximum_ssa_index': max(seen_ssa), 'all_original_caps_preserved': True}

def natural_owner(returned, life, request, parent_request, parent_request_pin, life_pin):
    projected = dict(returned)
    supervisor = projected.pop('supervisor_returncode', None)
    sha = projected.pop('receipt_sha256', None)
    common.require(projected == life and type(supervisor) is int and sha == life_pin['sha256']
        and life.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
        and life.get('implementation_sha256') == request['inputs']['control/process_owner_impl.py']['sha256']
        and life.get('request_sha256') == parent_request_pin['sha256']
        and parent_request['command'] == request['command']
        and parent_request['cwd'] == str(ROOT) and parent_request['env'] == request['environment']
        and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3,
        'actual owner request/implementation/returned full bytes differ')
    cleanup = life.get('cleanup', {})
    closed = (life.get('subreaper_enabled') is True and life.get('event_overflow') is False
        and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
        and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
        and cleanup.get('errors') == [] and cleanup.get('deadline_exceeded') is False)
    common.require(closed, 'current owner has not proved ECHILD; child originals must remain unread')
    events = life.get('events', [])
    natural = (supervisor == 0 and life.get('status') == 'OWNED_PROCESS_COMPLETED'
        and life.get('returncode') == 0 and life.get('timed_out') is False
        and life.get('exit_observed_before_deadline') is True and life.get('owner_error') is None
        and life.get('interrupted_signals') == []
        and [e.get('kind') for e in events] == ['qualification_started', 'owned_child_observed',
                                             'qualification_exit_observed', 'owned_child_reaped']
        and all(e.get('pid') == life.get('qualification_pid') for e in events))
    return closed, natural
