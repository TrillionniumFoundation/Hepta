"""Independent, read-only audit of the one completed r4c source request.

This reader imports no repository module, reconstructs no code object and runs
no generator, HIA or C code.  Packet checks decode retained bytes only.
"""
import dis
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

BASE = Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4c-source-actual-r1')
OUT = Path('/tmp/hia-cli-r4c-actual-audit-native-r1-20261112-e26e')
COMMIT = '4787038c3a013357309c22929b268055dc91090c'
TREE = 'cfc66ec1d1ecd57dca61b42c1e5818cb1c40e4bc'
LIMITS = dict(source_bytes=1048576, functions=128, blocks_per_function=256,
              blocks_total=1536, parameters_or_arguments=16,
              ssa_names_per_function=2048, instruction_results=3,
              function_results=3, instructions=8192)
NAMES = ['_iterencode_list', '_iterencode_dict', '_iterencode']
records = {}
checks = 0


def check(value, label):
    global checks
    checks += 1
    if not value:
        raise ValueError(label)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path):
    path = Path(path)
    check(path.is_absolute() and '..' not in path.parts, 'absolute fixed file path')
    descriptors = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append((fd, None, None, identity(os.fstat(fd))))
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            s = os.fstat(child)
            check(stat.S_ISDIR(s.st_mode), 'directory descriptor type')
            descriptors.append((child, fd, name, identity(s)))
            fd = child
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        check(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular single-link file ' + str(path))
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            check(identity(os.fstat(leaf)) == identity(before), 'opened leaf identity')
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(leaf, min(remaining, 1 << 20))
                check(bool(chunk), 'unexpected short evidence file')
                remaining -= len(chunk)
                chunks.append(chunk)
            check(os.read(leaf, 1) == b'', 'evidence file grew')
            raw = b''.join(chunks)
            check(identity(os.fstat(leaf)) == identity(before) == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'leaf identity after read')
        finally:
            os.close(leaf)
        for held, parent, name, prior in descriptors:
            now = identity(os.fstat(held))
            # Other agents may create unrelated directory children. The held
            # directory inode/mode/owner must remain, not its child mtime.
            check(now[:5] == prior[:5], 'held directory identity')
            if parent is not None:
                check(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == prior[:5], 'held directory still named')
    finally:
        for held, _, _, _ in reversed(descriptors):
            os.close(held)
    row = {'path': str(path), 'identity': identity(before), **pin(raw)}
    if str(path) in records:
        check(records[str(path)] == row, 'same original read twice')
    records[str(path)] = row
    return raw


def obj(path):
    return json.loads(read(path))


def bind(row, path=None):
    actual_path = str(path or row['path'])
    raw = read(actual_path)
    actual = records[actual_path]
    for key in ('bytes', 'sha256', 'git_blob', 'identity'):
        if key in row:
            check(actual[key] == row[key], key + ' binding ' + actual_path)
    return raw


def recursive_bind(value):
    if type(value) is dict:
        if {'path', 'bytes', 'sha256'} <= value.keys() and str(value['path']).startswith('/'):
            bind(value)
        for child in value.values():
            recursive_bind(child)
    elif type(value) is list:
        for child in value:
            recursive_bind(child)


def leaves(root):
    output = []
    def walk(path):
        for child in sorted(path.iterdir()):
            s = child.lstat()
            if stat.S_ISDIR(s.st_mode):
                walk(child)
            else:
                check(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'physical namespace has only regular leaves')
                output.append(child.relative_to(root).as_posix())
    walk(root)
    return output


def measure(document, assembly):
    rows = []
    for fn in document['functions']:
        names = {x['name'] for x in fn['params']}
        params = len(fn['params'])
        args = result_count = operations = 0
        for block in fn['blocks']:
            params = max(params, len(block['params']))
            names.update(x['name'] for x in block['params'])
            for operation in block['ops']:
                operations += 1
                args = max(args, len(operation['args']))
                result_count = max(result_count, len(operation['out']))
                names.update(x['name'] for x in operation['out'])
            term = block['term']
            if term['op'] == 'branch':
                edges = [term['then']['args'], term['else']['args']]
            elif term['op'] == 'jump':
                edges = [term['args']]
            elif term['op'] == 'ret':
                edges = [term['values']]
            else:
                edges = []
            args = max([args] + [len(edge) for edge in edges])
        rows.append(dict(name=fn['name'], blocks=len(fn['blocks']), operations=operations,
                         ssa_names=len(names), parameters=params, arguments=args,
                         instruction_results=result_count, function_results=len(fn['returns'])))
    return rows, dict(source_bytes=len(assembly), functions=len(rows),
                      blocks_per_function=max(x['blocks'] for x in rows),
                      blocks_total=sum(x['blocks'] for x in rows),
                      parameters_or_arguments=max(max(x['parameters'], x['arguments']) for x in rows),
                      ssa_names_per_function=max(x['ssa_names'] for x in rows),
                      instruction_results=max(x['instruction_results'] for x in rows),
                      function_results=max(x['function_results'] for x in rows),
                      instructions=sum(x['operations'] for x in rows))


def exceptions(raw):
    position = 0
    def varint():
        nonlocal position
        check(position < len(raw), 'complete exception varint')
        byte = raw[position]
        position += 1
        value = byte & 63
        while byte & 64:
            check(position < len(raw), 'complete continued exception varint')
            byte = raw[position]
            position += 1
            value = (value << 6) | (byte & 63)
        return value
    result = []
    while position < len(raw):
        start = varint()
        length = varint()
        target = varint()
        packed = varint()
        result.append((start, start + length, target, packed))
    return result


def packet_audit(packet_name, packet_index):
    label = packet_name.removeprefix('_')
    raw = read(BASE / 'actual/packets' / (label + '.packet.bin'))
    meta = obj(BASE / 'actual/packets' / (label + '.packet.json'))
    check(meta['schema'] == 'hia.cli-json.py312-code-packet.v1' and meta['profile'] == 31214, 'packet schema/profile')
    check(meta['packet'] == pin(raw), 'metadata binds complete packet bytes')
    check(meta['runtime_code_object_admitted'] is False and meta['foreign_input_domain_restricted'] is False, 'packet limited scope')
    code = meta['code']
    check(code['name'] == packet_name, 'packet code name')
    original = bytes.fromhex(code['code_hex'])
    for key in ('code', 'exception_table', 'linetable'):
        check(pin(bytes.fromhex(code[key + '_hex'])) == code[key], 'retained code bytes ' + key)
    check(len(original) > 0 and len(original) % 2 == 0, 'wordcode exact even length')
    units = len(original) // 2
    check(len(raw) == 64 * (units + 1), 'packet total length')
    check(meta['exception_lookup_code_units'] == units, 'all code units have exception lookup')
    header = struct.unpack_from('<8Q', raw)
    rows = meta['instructions']
    check(rows and rows[0]['pc'] == 0 and len({x['pc'] for x in rows}) == len(rows), 'unique original instruction positions')
    positions = {x['pc'] for x in rows}
    generators = [x for x in rows if x['opname'] == 'RETURN_GENERATOR']
    check(len(generators) == 1, 'single generator prologue')
    check(header == (int.from_bytes(b'HCLIBC31', 'little'), 31214, units, packet_index,
                     generators[0]['pc'] + 1, len(code['localsplus_names']), code['stacksize'], 1), 'all packet header words')
    decoded = exceptions(bytes.fromhex(code['exception_table_hex']))
    valid = {x['pc']: x for x in rows}
    no_handler = (1 << 64) - 1
    extension = 0
    for index, row in enumerate(rows):
        pc, opcode = row['pc'], row['opcode']
        check(opcode == original[2 * pc] and row['opname'] == dis.opname[opcode], 'recorded opcode/name match original word')
        following = rows[index + 1]['pc'] if index + 1 < len(rows) else units
        check(row['following'] == following, 'next original instruction position')
        check(following == pc + 1 + dis._inline_cache_entries[opcode], 'complete inline-cache gap')
        argument = (original[2 * pc + 1] | extension) if opcode >= dis.HAVE_ARGUMENT else 0
        check(row['argument'] == argument, 'extended unsigned opcode argument')
        extension = argument << 8 if opcode == dis.EXTENDED_ARG else 0
        if opcode in dis.hasjrel:
            expected_target = following + (-argument if 'BACKWARD' in row['opname'] else argument)
        elif opcode in dis.hasjabs:
            expected_target = argument
        else:
            expected_target = no_handler
        check(row['target'] == expected_target, 'original jump offset including cache extent')
        check(expected_target == no_handler or expected_target in positions, 'branch target is valid original instruction')
    for pc in range(units):
        entries = [x for x in decoded if x[0] <= pc < x[1]]
        check(len(entries) <= 1, 'non-overlapping original exception entry')
        handler, packed = (entries[0][2], entries[0][3]) if entries else (no_handler, 0)
        if pc in valid:
            row = valid[pc]
            check(row['handler'] == handler and row['unwind_depth_and_lasti'] == packed, 'full exception table decode at real opcode')
            expected = (row['opcode'], row['argument'], row['following'], row['target'], handler, packed, 0, 1)
        else:
            check(original[pc * 2] == 0, 'unmarked code unit is actual CACHE')
            expected = (0, 0, 0, no_handler, handler, packed, 0, 0)
        check(struct.unpack_from('<8Q', raw, 64 * (pc + 1)) == expected, 'all eight words of each packet code unit')
    return {'name': packet_name, 'code_units': units, 'instructions': len(rows),
            'exception_entries': len(decoded), 'packet': pin(raw),
            'all_code_unit_words_read': units * 8, 'runtime_code_object_admitted': False}


def main():
    check(sys.version_info[:3] == (3, 12, 14), 'reader dis metadata exact Python profile')
    pre = obj(ROOT / 'PRETRIGGER.json')
    intent = obj(ROOT / 'INVOCATION-INTENT.json')
    returned = obj(ROOT / 'INVOCATION-RETURN.json')
    request = obj(BASE / 'guardian/REQUEST.json')
    config = obj(BASE / 'control/CONFIG.json')
    guardian = obj(BASE / 'guardian/guardian.json')
    report = obj(BASE / 'actual/REPORT.json')
    check(pre['canonical_commit'] == COMMIT and pre['canonical_tree'] == TREE, 'one frozen canonical request')
    check(returned['returncode'] == 0, 'only original launch returned zero')
    for item in (pre, returned, report):
        recursive_bind(item)
    check(guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED', 'outer terminal status')
    check(guardian['command'] == request['command'] and guardian['cwd'] == request['cwd'], 'actual owner command/cwd')
    check(guardian['external_controller_seconds'] == request['controller_seconds'] == 180, 'original 180 second owner')
    check(guardian['input_identity_preserved'] is True, 'guardian preserved inputs')
    check(guardian['source_identities_before'] == guardian['source_identities_after'] == request['source_identities'], 'guardian all input hash maps')
    check(len(request['source_identities']) == 184, '184 original bound inputs')
    for path, expected in request['source_identities'].items():
        check(pin(read(path))['sha256'] == expected, 'actual full input SHA ' + path)
    check(guardian['lifecycle_implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2', 'unchanged lifecycle owner')
    life = guardian['lifecycle']
    check(life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0, 'actual natural child status')
    check(life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3, 'unchanged original owner budgets')
    check(life['subreaper_enabled'] is True and life['exit_observed_before_deadline'] is True, 'subreaper and deadline')
    check(life['timed_out'] is False and life['event_overflow'] is False and life['interrupted_signals'] == [], 'no timeout/overflow/signal')
    events = life['events']
    check([x['kind'] for x in events] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'], 'four natural events no kill')
    check(events[2]['si_status'] == 0 and events[2]['si_code'] == 1 and events[3]['returncode'] == 0, 'natural leader exit/reap')
    check(len({x['pid'] for x in events}) == 1, 'same child PID across lifecycle')
    cleanup = life['cleanup']
    check(cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True, 'closed ECHILD custody')
    check(cleanup['remaining_direct_children'] == cleanup['errors'] == [] and cleanup['deadline_exceeded'] is False, 'no remaining ownership')
    for path, expected in guardian['logs'].items():
        check(pin(read(path))['sha256'] == expected, 'actual original child log')
    check(report['status'] == 'TWO_HIA_AND_THREE_CODE_PACKETS_PASS_PENDING_OUTER_GUARDIAN' and report['errors'] == [], 'source report status and errors')
    check(report['native_executed'] is False and report['product_callers_executed'] is False and report['counts_are_plan_only'] is True, 'no runtime/caller qualification')
    check(report['original_cli_ids'] == config['original_cli_ids'] and len(report['original_cli_ids']) == len(set(report['original_cli_ids'])) == 17, '17 exact planned original IDs')
    check(report['trace_plan_ids'] == config['trace_plan_ids'] and len(report['trace_plan_ids']) == len(set(report['trace_plan_ids'])) == 46, '46 exact planned trace IDs')
    before_raw, after_raw = read(BASE / 'actual/source.before.json'), read(BASE / 'actual/source.after.json')
    check(before_raw == after_raw, 'full source snapshot original bytes equal')
    before = json.loads(before_raw)
    check(len(before) == 177 and set(before) == set(config['source_pins']), '177 exact source members')
    namespace_before = leaves(BASE / 'source')
    check(namespace_before == sorted(before), 'complete physical source namespace')
    for name, row in before.items():
        check(row['path'] == str(BASE / 'source' / name), 'source actual path')
        bind(row)
        bind(config['source_pins'][name], BASE / 'source' / name)
    check(sum(x['bytes'] for x in before.values()) == 2750177, 'source byte denominator')
    check(len(report['actual_repository_modules']) == 35, '35 actually imported repository modules')
    for module, name in report['actual_repository_modules'].items():
        check(name in before, 'imported module within complete source pins: ' + module)
    check(config['limits'] == LIMITS, 'exact original nine structure caps')
    check([[x['name'], x['module']] for x in report['components']] == config['components'] == [['py312_body', 'tools.generate_hia_cli_json_py312_body'], ['py312_lifetime', 'tools.generate_hia_cli_json_py312_lifetime']], 'complete two-component denominator')
    measured = []
    for row in report['components']:
        check(row['status'] == 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and row['error'] is None, 'component actual status')
        assembly = bind(row['assembly'])
        doc_raw = bind(row['document'])
        check(doc_raw == bind(row['verified_document']), 'Core roundtrip full document bytes')
        caps = json.loads(bind(row['caps']))
        functions, metrics = measure(json.loads(doc_raw), assembly)
        check(functions == caps['functions'] and metrics == caps['actual'], 'all function and global caps independently recomputed')
        check(caps['limits'] == LIMITS and caps['within_limits'] is True and all(metrics[k] <= v for k, v in LIMITS.items()), 'all original nine caps')
        check(caps['compiler_line_gate_executed'] is False and caps['source_lines_diagnostic'] == len(assembly.splitlines()), 'line diagnostic is not compiler qualification')
        measured.append({'name': row['name'], 'actual': metrics, 'assembly': pin(assembly), 'document': pin(doc_raw)})
    packets = obj(BASE / 'actual/packets/REPORT.json')
    check(packets['status'] == report['packet_authoring']['status'] == 'THREE_SOURCE_PACKETS_AUTHORED' and packets['errors'] == [], 'packet authoring report')
    check(packets['exact_names'] == config['packet_names'] == NAMES == [x['name'] for x in packets['code_objects']], 'exact three packet names/order')
    check(packets['source'] == config['source_pins'][config['encoder_source']], 'retained encoder source bytes')
    check(packets['generator_bodies_executed'] is False and packets['runtime_code_objects_admitted'] is False and packets['native_executed'] is False and packets['json_values_encoded'] == 0, 'packet metadata-only scope')
    check(len(packets['outputs']) == 6 and packets['outputs'] == [y for x in packets['code_objects'] for y in x['outputs']], 'six complete original packet outputs')
    for row in packets['code_objects']:
        check(row['status'] == 'SOURCE_PACKET_AUTHORED_NOT_RUNTIME_ADMITTED' and row['error'] is None, 'packet individual source status')
    for row in packets['outputs']:
        bind(row, BASE / 'actual/packets' / row['path'])
    packet_metrics = [packet_audit(name, index) for index, name in enumerate(NAMES)]
    actual_names, guard_names = leaves(BASE / 'actual'), leaves(BASE / 'guardian')
    check(len(actual_names) == 20 and len(guard_names) == 4, 'complete original output namespaces')
    for folder, names in (('actual', actual_names), ('guardian', guard_names)):
        for name in names:
            read(BASE / folder / name)
    root_names = leaves(ROOT)
    check(root_names == ['INVOCATION-INTENT.json', 'INVOCATION-RETURN.json', 'PRETRIGGER.json', 'READBACK.json', 'launcher.stderr.log', 'launcher.stdout.log'], 'six root original receipts including independent readback')
    root_readback = obj(ROOT / 'READBACK.json')
    for name in root_names:
        read(ROOT / name)
    read(ROOT.parent / 'audit_cli_r4c_source_actual.py')
    check(root_readback['report']['sha256'] == records[str(BASE / 'actual/REPORT.json')]['sha256'], 'independent root same report')
    check(root_readback['guardian']['sha256'] == records[str(BASE / 'guardian/guardian.json')]['sha256'], 'independent root same lifecycle')
    check([x['actual'] for x in root_readback['components']] == [x['actual'] for x in measured], 'independent root same all nine measurements')
    # Re-read every evidence/input leaf after all parsing; no atime component.
    for path in list(records):
        read(path)
    check(namespace_before == leaves(BASE / 'source') and actual_names == leaves(BASE / 'actual') and guard_names == leaves(BASE / 'guardian'), 'all physical namespaces stable through audit')
    result = {'schema': 'hia.cli-json.r4c.actual-independent-audit.v1',
              'status': 'TWO_HIA_SOURCE_AND_THREE_METADATA_PACKETS_PASS',
              'request_commit': COMMIT, 'request_tree': TREE,
              'source_count': 177, 'source_bytes': 2750177, 'bound_input_count': 184,
              'actual_original_count': len(actual_names), 'guardian_original_count': len(guard_names),
              'root_original_count': len(root_names), 'root_reader_original_count': 1,
              'full_source_and_input_identity_unchanged': True, 'components': measured,
              'packets': packet_metrics, 'source_worker_elapsed_ns': report['elapsed_ns'],
              'owner_elapsed_ns': events[2]['monotonic_ns'] - events[0]['monotonic_ns'],
              'lifecycle': life, 'joins': checks, 'full_unique_files': len(records),
              'scope': {'native': False, 'c_compile': False, 'compiler_line_gate': False,
                        'original_cli_17': False, 'trace_plan_46': False,
                        'runtime_code_objects_admitted': False, 'generator_bodies_executed': False,
                        'whole_json_rewrite_qualified': False},
              'files': sorted(records.values(), key=lambda x: x['path'])}
    return result


if __name__ == '__main__':
    try:
        result = main()
    except BaseException:
        import traceback
        raw = traceback.format_exc().encode()
        with (OUT / 'READONLY-ERROR.txt').open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        raise
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    with (OUT / 'AUDIT.json').open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({k: v for k, v in result.items() if k not in ('files', 'lifecycle')}, sort_keys=True))
