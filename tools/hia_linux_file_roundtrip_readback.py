"""Independent raw-record readback for the bounded roundtrip qualifier.

These functions do not execute a payload or produce observed buffers. They
re-read the actual requests, full compile observations, kernel output files,
complete VM frames, fixed original inputs and final cold/source bindings.
A comparison boolean or a serialized fixture never substitutes for those.
"""
from pathlib import Path
import os
import struct
import sys

from tools.hia_linux_file_roundtrip_cold import (
    ROOT, PROFILE, CAPACITY, REPRESENTATION_SOURCE, SEMANTIC_SOURCE,
    require, decode, digest, wire, pin, check_bindings, retained_bytes, observation, profile_capture,
)

LIMITS = {'wall': 20, 'cleanup': 3, 'cpu': 10, 'address': 256 << 20,
          'stack': 8 << 20, 'filesize': 16 << 20, 'fds': 32, 'core': 0}
EXTENTS = {'file': 8388609, 'output': CAPACITY, 'workspace': CAPACITY}


def actual_kernel(folder, executable, argv, *, observer=False):
    folder, executable = Path(folder), Path(executable)
    actual = decode((folder / 'OBSERVATION.json').read_bytes())
    request = decode((folder / 'EXEC-REQUEST.json').read_bytes())
    expected = {'elf': str(executable.resolve()), 'elf_sha256': digest(executable.read_bytes()),
        'argv_hex': [value.hex() for value in argv],
        'environment_hex': [b'LC_ALL=C.UTF-8'.hex()],
        'exec_failure': str((folder / 'EXEC-FAILURE.json').resolve())}
    if observer:
        expected['observations'] = {name: {'fd': 29 + index, 'extent': length,
            'path': str((folder / (name + '.bin')).resolve())}
            for index, (name, length) in enumerate(EXTENTS.items())}
        module = 'hia_linux_file_roundtrip_exec.py'
    else:
        expected.update(sigpipe_ignored=False, close_fds=[])
        module = 'hia_linux_process_cases.py'
    command = [sys.executable, '-I', '-S', '-B', str((ROOT / 'tests' / module).resolve()),
               '--raw-exec', str((folder / 'EXEC-REQUEST.json').resolve())]
    require(wire(request) == wire(expected) and actual.get('command') == command
            and actual.get('payload') == expected['elf']
            and actual.get('image_sha256') == actual.get('image_after_sha256') == expected['elf_sha256']
            and actual.get('limits') == LIMITS and all(type(v) is int for v in actual['limits'].values())
            and actual.get('timed_out') is False and actual.get('reaped_ECHILD') is True
            and actual.get('preexec_python_ctypes') is True
            and actual.get('runtime_payload_python_or_ctypes') is False
            and type(actual.get('returncode')) is int and actual.get('stdin_consumed') == 0
            and type(actual.get('stdin_consumed')) is int
            and (folder / 'stdin.bin').read_bytes() == b''
            and actual.get('stdout_hex') == (folder / 'stdout.bin').read_bytes().hex()
            and actual.get('stderr_hex') == (folder / 'stderr.bin').read_bytes().hex()
            and actual.get('exec_failure') is None and not (folder / 'EXEC-FAILURE.json').exists(),
            'actual complete kernel request/output/cleanup differs: ' + str(folder))
    buffers = {}
    if observer:
        require(actual.get('native_startup_capability_from_actual_kernel') is True
                and type(actual.get('postreturn_buffers')) is dict
                and set(actual['postreturn_buffers']) == set(EXTENTS),
                'pure HIA postreturn observer metadata missing')
        for index, (name, length) in enumerate(EXTENTS.items()):
            path = folder / (name + '.bin'); bound = pin(path); raw = path.read_bytes()
            require(actual['postreturn_buffers'][name] == {
                'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
                'complete': True, 'expected_extent': length, 'descriptor': 29 + index}
                and bound['bytes'] == length, 'actual whole native buffer differs: ' + name)
            buffers[name] = raw
    return actual, buffers


def read_vm(folder, program, components, raw, path, mode, expected):
    folder = Path(folder)
    request = decode((folder / 'VM-REQUEST.json').read_bytes())
    wanted = {'schema': 'hepta.hia.roundtrip-vm-inputs.v1', 'program_sha256': program.sha256,
        'component_sha256': [digest(value) for value in components],
        'input': pin(folder / 'reference-input.bin'), 'path': str(path), 'mode': mode,
        'stat': pin(folder / 'stat-before.bin'), 'max_steps': 10000000,
        'initial_buffers': {name: {'bytes': extent, 'fill': 0} for name, extent in EXTENTS.items()},
        'actual_kernel_execution': False}
    require(wire(request) == wire(wanted) and (folder / 'reference-input.bin').read_bytes() == raw
            and wanted['stat']['bytes'] == 144, 'full original VM input binding differs')
    result = decode((folder / 'VM.json').read_bytes())
    require(result.get('schema') == 'hepta.hia.linux-file-roundtrip-execution.v1'
            and result.get('profile') == PROFILE and result.get('function') == 'f0'
            and result.get('program_sha256') == result.get('input_sha256') == program.sha256
            and result.get('status') == 'returned' and result.get('values') == [expected]
            and all(type(value) is int for value in result['values'])
            and type(result.get('steps')) is int and 0 < result['steps'] <= 10000000
            and result.get('actual_kernel_execution') is False and result.get('whole') is False
            and result.get('matching_cold') is False and result.get('default_core_authority') is False
            and result.get('explicit_effect_provider') is True
            and type(result.get('effects')) is list, 'actual bounded VM terminal differs')
    refs = result.get('complete_buffer_members')
    require(type(refs) is dict and set(refs) == set(EXTENTS), 'three full VM buffers required')
    buffers = {}
    for name, extent in EXTENTS.items():
        target = folder / (name + '.vm.bin')
        require(refs[name] == pin(target) and refs[name]['bytes'] == extent,
                'complete VM buffer identity differs: ' + name)
        buffers[name] = target.read_bytes()
    stdout, stderr = (folder / 'stdout.bin').read_bytes(), (folder / 'stderr.bin').read_bytes()
    calls = decode((folder / 'PROVIDER.json').read_bytes())
    require(type(calls) is list and all(type(row) is dict for row in calls), 'actual provider events required')
    effects = [row for row in result['effects'] if row['operation'].startswith('linux.file.')
               or row['operation'] in ('linux.stdout.write', 'linux.stderr.write')]
    projected = []
    for effect in effects:
        response = bytes.fromhex(effect.get('read_hex', ''))
        projected.append({key: effect[key] for key in ('operation', 'fd', 'offset', 'count', 'extent', 'result')})
        projected[-1].update(payload_bytes=len(response), payload_sha256=digest(response))
    require(calls == projected, 'independent original provider rows differ from actual VM effects')
    for fd, output in ((1, stdout), (2, stderr)):
        name = 'linux.stdout.write' if fd == 1 else 'linux.stderr.write'
        pieces = []
        for row in effects:
            if row['operation'] == name:
                require(type(row.get('result')) is int, 'integer effect result required')
                if row['result'] > 0:
                    written = bytes.fromhex(row['write_hex'])
                    require(row['result'] <= len(written), 'effect returned more bytes than supplied')
                    pieces.append(written[:row['result']])
        require(b''.join(pieces) == output, 'recorded provider stdout/stderr differs')
    return result, buffers, stdout, stderr, calls


def _row(folder, checks):
    row = decode((Path(folder) / 'COMPARISON.json').read_bytes())
    require(type(row) is dict and row.get('pass') is True
            and row.get('checks') == checks and all(value is True for value in checks.values()),
            'original complete comparison differs from raw readback: ' + str(folder))
    return row


def kernel(ctx, directory):
    executable = Path(ctx['production']['executable']['path']); rows = []
    for original in ctx['retained']['kernel_cases']:
        fixture, old = original['declared'], original['original_observation']
        folder = Path(directory) / original['name']; path = folder / 'input.json'
        raw = retained_bytes(original['input'])
        require(path.read_bytes() == raw, 'original kernel input changed')
        actual, _ = actual_kernel(folder / 'native', executable,
            (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)))
        stdout, stderr = bytes.fromhex(actual['stdout_hex']), bytes.fromhex(actual['stderr_hex'])
        checks = {'expected_return': actual['returncode'] == fixture['expected'] == old['native_returncode'],
            'same_complete_stdout': stdout == retained_bytes(original['stdout']),
            'same_complete_stderr': stderr == retained_bytes(original['stderr']),
            'no_timeout': not actual['timed_out'], 'reaped': actual['reaped_ECHILD'],
            'exec_succeeded': actual['exec_failure'] is None,
            'ELF_unchanged': actual['image_sha256'] == actual['image_after_sha256'] == ctx['production']['executable']['sha256']}
        if fixture['expected'] != 0:
            checks['no_failure_stdout'] = stdout == b''
        row = _row(folder, checks)
        require(row['name'] == original['name'] and row['input_sha256'] == digest(raw)
                and row['expected'] == fixture['expected'] and type(row['expected']) is int
                and row['declared_scope_exclusion'] == fixture['excluded'], 'original kernel mapping differs')
        rows.append({'name': original['name'], 'observation': pin(folder / 'native/OBSERVATION.json'),
                     'comparison': pin(folder / 'COMPARISON.json')})
    return rows


def pipeline(ctx, directory):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import verify_program
    _, captured_sources = profile_capture()
    program = assemble_program(captured_sources['examples/hia_bootstrap/native_file_roundtrip.hepta'], profile=PROFILE)
    components = tuple(captured_sources[name] for name in (REPRESENTATION_SOURCE, SEMANTIC_SOURCE))
    cases = {r['name']: r for r in ctx['retained']['kernel_cases']}
    rows = []
    for label, original_name, mode, expected, expected_calls in ctx['retained']['pipeline_rows']:
        folder = Path(directory) / label; path = folder / 'input.json'
        raw = retained_bytes(cases[original_name]['input']) if original_name else b'{}'
        require((not path.exists()) if mode == 'open-refused' else path.read_bytes() == raw,
                'original pipeline input domain differs')
        result, buffers, stdout, stderr, calls = read_vm(folder, program, components, raw, path, mode, expected)
        residents = [r for r in result['effects'] if r['operation'].startswith('linux.roundtrip.')]
        checks = {'VM_return': result['status'] == 'returned' and result['values'] == [expected],
            'all_three_buffers_retained': set(buffers) == set(EXTENTS),
            'exact_resident_call_count': len(residents) == expected_calls,
            'original_shared_fuel': result['steps'] <= 10000000, 'no_VM_exception': True}
        if mode != 'read-error-close-error':
            native, native_buffers = actual_kernel(folder / 'native', ctx['observer']['executable']['path'],
                (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)), observer=True)
            require(native['returncode'] == expected, 'actual pipeline native return differs')
            if original_name:
                original = cases[original_name]
                require(native['returncode'] == original['original_observation']['native_returncode']
                        and bytes.fromhex(native['stdout_hex']) == retained_bytes(original['stdout'])
                        and bytes.fromhex(native['stderr_hex']) == retained_bytes(original['stderr']),
                        'actual pipeline differs from original native oracle')
            checks['same_complete_stdout'] = stdout.hex() == native['stdout_hex']
            checks['same_complete_stderr'] = stderr.hex() == native['stderr_hex']
            checks.update({'same_complete_' + name: buffers[name] == native_buffers[name] for name in EXTENTS})
        else:
            require(not (folder / 'native').exists(), 'VM-only original row cannot invent a kernel observation')
        if expected == 0:
            canonical = verify_program(raw).canonical_bytes
            checks.update(original_JSON_preserved=buffers['file'][:len(raw)] == raw,
                first_canonical_exact_original_Core=buffers['file'][CAPACITY:CAPACITY + len(canonical)] == canonical,
                second_canonical_exact_original_Core=buffers['output'][:len(canonical)] == canonical,
                independent_assembly_preserved=buffers['file'][2*CAPACITY:2*CAPACITY + len(stdout)] == stdout,
                two_canonical_resident_returns=[residents[i]['result'] for i in (2, 4)] == [len(canonical)] * 2,
                five_actual_fixed_resident_calls=[r['operation'] for r in residents] == [
                    'linux.roundtrip.representation', 'linux.roundtrip.semantic', 'linux.roundtrip.representation',
                    'linux.roundtrip.representation', 'linux.roundtrip.representation'])
        if mode == 'partial-and-EINTR':
            checks['real_reference_EINTR_branch'] = any(r['operation'] == 'linux.file.read' and r['result'] == -4 for r in calls)
            checks['real_reference_partial_write_branch'] = sum(r['operation'] == 'linux.stdout.write' for r in calls) > 1
        if mode == 'open-refused':
            checks['no_close_without_acquisition'] = not any(r['operation'] == 'linux.file.close' for r in calls)
        if mode == 'read-error-close-error':
            checks['original_read_error_priority'] = len(stderr) == 32 and struct.unpack('<4Q', stderr)[1:] == (66, 1, 4)
            checks['one_revoked_close'] = sum(r['operation'] == 'linux.file.close' for r in calls) == 1
        row = _row(folder, checks)
        require(row['name'] == label and row['original_name'] == original_name and row['mode'] == mode
                and row['error'] is None and row['VM_steps'] == result['steps']
                and row['residents'] == residents, 'pipeline observation binding differs')
        rows.append({'name': label, 'VM': pin(folder / 'VM.json'), 'comparison': pin(folder / 'COMPARISON.json'),
                     'actual_kernel_full_buffers': mode != 'read-error-close-error'})
    return rows


def tail_faults(ctx, directory):
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from hepta.hia_program import verify_program
    from tests.hia_linux_file_roundtrip_cases import projected_document
    from tools.build_hia_linux_file_roundtrip_program import _frame, _elf_structure
    original = next(r for r in ctx['retained']['kernel_cases'] if r['name'] == 'exports-metadata-empty')
    raw = retained_bytes(original['input']); canonical = verify_program(raw).canonical_bytes
    _, captured_sources = profile_capture()
    components = tuple(captured_sources[name] for name in (REPRESENTATION_SOURCE, SEMANTIC_SOURCE))
    actual_components = tuple(Path(r['path']).read_bytes() for r in ctx['production']['components'][1:])
    provider = ctx['toolchain']['compiler_image']['path']
    packer = Path(ctx['observer']['executable']['path']).parent / 'observer-packer.image.bin'
    rows = []
    for side in ('C1', 'C2'):
        folder = Path(directory) / side; path = folder / 'input.json'
        document, author, statement = projected_document(side)
        source = render_assembly(document, profile=PROFILE).encode()
        require((folder / 'fault-author.py.txt').read_text() == author
                and (folder / 'fault-controller.hepta').read_bytes() == source and path.read_bytes() == raw,
                'exact last-byte fault author/source/input differs')
        program = assemble_program(source, profile=PROFILE)
        _, image, compile_receipt = observation(folder, 'fault-controller', provider, source)
        images = (image, *actual_components); frame = _frame(images)
        require((folder / 'packer-input.bin').read_bytes() == frame, 'fault packer frame differs')
        _, elf, packed = observation(folder, 'fault-packed', packer, frame, extension='.elf.bin')
        executable = folder / 'fault-observer.elf'
        require(executable.read_bytes() == elf and pin(executable)['mode'] == 0o500,
                'fault observer is not actual packed ELF')
        inspection = _elf_structure(elf, images)
        native, native_buffers = actual_kernel(folder / 'native', executable,
            (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)), observer=True)
        result, buffers, stdout, stderr, calls = read_vm(folder, program, components, raw, path, 'ordinary', 72)
        first = buffers['file'][CAPACITY:CAPACITY + len(canonical)]
        second = buffers['output'][:len(canonical)]; tampered = canonical[:-1] + bytes([canonical[-1] ^ 1])
        residents = [e for e in result['effects'] if e['operation'].startswith('linux.roundtrip.')]
        checks = {'actual_kernel_return_72': native['returncode'] == 72,
            'VM_return_72': result['status'] == 'returned' and result['values'] == [72],
            'no_stdout': stdout == b'' and native['stdout_hex'] == '',
            'same_complete_stderr': stderr.hex() == native['stderr_hex'],
            'byte_equality_phase_7': len(stderr) == 32 and struct.unpack('<4Q', stderr)[1:] == (72, 7, len(canonical)),
            'same_lengths': len(first) == len(second) == len(canonical),
            'equal_all_but_last': first[:-1] == second[:-1] == canonical[:-1],
            'last_bytes_different': first[-1] != second[-1],
            'exact_C1_injection': first == (tampered if side == 'C1' else canonical),
            'exact_C2_injection': second == (tampered if side == 'C2' else canonical),
            'original_JSON_preserved': buffers['file'][:len(raw)] == raw,
            'five_actual_residents': len(residents) == 5 and all(e['status'] == 'returned' for e in residents),
            'two_equal_canonical_returns_before_injection': [residents[i]['result'] for i in (2,4)] == [len(canonical)]*2,
            'within_original_fuel': result['steps'] <= 10000000, 'no_VM_exception': True}
        checks.update({'same_complete_' + name: buffers[name] == native_buffers[name] for name in EXTENTS})
        row = _row(folder, checks)
        require(row['name'] == side + '-last-byte' and row['compile'] == compile_receipt
                and row['packed'] == packed and row['injection'] == statement
                and row['fault_source_sha256'] == digest(source) and row['image_sha256'] == digest(image)
                and row['ELF_bytes'] == len(elf) and row['ELF_sha256'] == digest(elf)
                and row['elf_inspection'] == inspection and row['error'] is None,
                'actual fault projection/compilation/observation differs')
        rows.append({'name': row['name'], 'comparison': pin(folder / 'COMPARISON.json'), 'VM': pin(folder / 'VM.json')})
    return rows
