"""Permanent exact original130, pipeline7 and last-byte2 observations.

The reference provider is only a VM input. Real native F/O/W bytes come from
the separately compiled pure HIA postreturn observer, never host-created frames.
All original check dictionaries and the two reference/projection function
bodies are retained. The source/fixture/build owner supplies current authority.
"""
from pathlib import Path
import ast
import copy
import ctypes
import json
import os
import struct
import traceback
import types

from tools.hia_linux_file_roundtrip_cold import (
    ROOT as SOURCE, CAPACITY, digest as sha, retained, retained_bytes,
    pin, publish, guard_authority, compile_bound, profile_capture,
)


def context(fixture):
    from tools.build_hia_linux_file_roundtrip_cold import admit_toolchain, admit_program, admit_observer
    authority = fixture['authority']
    return {'authority': authority, 'retained': retained(),
            'toolchain': admit_toolchain(fixture['toolchain']['path'], authority=authority),
            'production': admit_program(fixture['production']['path'], authority=authority),
            'observer': admit_observer(fixture['observer']['path'], authority=authority)}


def save_vm(folder, observed):
    report = dict(observed)
    refs, buffers = {}, {}
    for key, name in [('source_hex', 'file'), ('output_hex', 'output'), ('workspace_hex', 'workspace')]:
        if key not in report:
            continue
        raw = bytes.fromhex(report.pop(key))
        path = folder / (name + '.vm.bin')
        with path.open('xb') as stream:
            stream.write(raw)
        assert path.read_bytes() == raw
        refs[name] = pin(path); buffers[name] = raw
    report['complete_buffer_members'] = refs
    publish(folder / 'VM.json', report)
    return buffers


def record_vm_request(folder, program, components, raw, path, mode, status_bytes):
    capture = folder / 'reference-input.bin'
    with capture.open('xb') as stream:
        stream.write(raw)
    status = folder / 'stat-before.bin'
    if status.exists():
        assert status.read_bytes() == status_bytes
    else:
        with status.open('xb') as stream:
            stream.write(status_bytes)
    publish(folder / 'VM-REQUEST.json', {
        'schema': 'hepta.hia.roundtrip-vm-inputs.v1',
        'program_sha256': program.sha256,
        'component_sha256': [sha(value) for value in components],
        'input': pin(capture), 'path': str(path), 'mode': mode,
        'stat': pin(status), 'max_steps': 10000000,
        'initial_buffers': {'file': {'bytes': 8388609, 'fill': 0},
                            'output': {'bytes': CAPACITY, 'fill': 0},
                            'workspace': {'bytes': CAPACITY, 'fill': 0}},
        'actual_kernel_execution': False,
    })


def kernel_case(ctx, output, index):
    from tests.hia_linux_process_cases import direct
    original = ctx['retained']['kernel_cases'][index]
    fixture, old_row = original['declared'], original['original_observation']
    name = fixture['name']; folder = Path(output) / name; folder.mkdir()
    data = retained_bytes(original['input'])
    old_stdout, old_stderr = retained_bytes(original['stdout']), retained_bytes(original['stderr'])
    executable = Path(ctx['production']['executable']['path'])
    ELF_SHA = ctx['production']['executable']['sha256']
    path = folder / 'input.json'; path.write_bytes(data)
    row = {'name': name, 'input_bytes': len(data), 'input_sha256': sha(data),
           'expected': fixture['expected'], 'declared_scope_exclusion': fixture['excluded'], 'pass': False}
    try:
        observed = direct(folder / 'native', executable,
            (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)), (b'LC_ALL=C.UTF-8',))
        stdout = bytes.fromhex(observed['stdout_hex'])
        stderr = bytes.fromhex(observed['stderr_hex'])
        checks = {'expected_return': observed['returncode'] == fixture['expected'] == old_row['native_returncode'],
            'same_complete_stdout': stdout == old_stdout,
            'same_complete_stderr': stderr == old_stderr,
            'no_timeout': not observed['timed_out'], 'reaped': observed['reaped_ECHILD'],
            'exec_succeeded': observed['exec_failure'] is None,
            'ELF_unchanged': observed['image_sha256'] == observed['image_after_sha256'] == ELF_SHA}
        if fixture['expected'] != 0:
            checks['no_failure_stdout'] = stdout == b''
        diagnostic = list(struct.unpack('<4Q', stderr)) if len(stderr) == 32 else None
        row.update(pass_=all(checks.values()), checks=checks, native_returncode=observed['returncode'],
            stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_hex=stderr.hex(), diagnostic=diagnostic,
            original_core_sha256=old_row.get('original_core_sha256'),
            original_canonical_roundtrip_reference=old_row.get('canonical_roundtrip'))
        row['pass'] = all(checks.values())
        assert path.read_bytes() == data
        assert row['pass'], row
    except BaseException:
        row['pass'] = False; row['error'] = traceback.format_exc(); raise
    finally:
        publish(folder / 'COMPARISON.json', row)
    return row


def pipeline_case(ctx, output, index):
    from tests.hia_linux_file_roundtrip_exec import direct
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_linux_file_roundtrip import PROFILE
    from hepta.hia_program import verify_program
    label, original_name, mode, expected, expected_calls = ctx['retained']['pipeline_rows'][index]
    original = {r['name']: r['original_observation'] for r in ctx['retained']['kernel_cases']}
    cases = {r['name']: r for r in ctx['retained']['kernel_cases']}
    executable = Path(ctx['observer']['executable']['path']); elf = executable.read_bytes()
    _, captured_sources = profile_capture()
    program = assemble_program(captured_sources['examples/hia_bootstrap/native_file_roundtrip.hepta'], profile=PROFILE)
    components = tuple(captured_sources[name] for name in (
        'examples/hia_bootstrap/core_representation_private.hepta',
        'examples/hia_bootstrap/file_render_checker_v4.hepta'))
    folder = Path(output) / label; folder.mkdir(); path = folder / 'input.json'
    raw = retained_bytes(cases[original_name]['input']) if original_name else b'{}'
    if mode != 'open-refused':
        path.write_bytes(raw)
    status = (ctypes.c_ubyte * 144)()
    lib = ctypes.CDLL(None, use_errno=True)
    lib.stat.argtypes = (ctypes.c_char_p, ctypes.c_void_p); lib.stat.restype = ctypes.c_int
    if mode != 'open-refused':
        assert lib.stat(os.fsencode(path), status) == 0
    status_bytes = bytes(status); (folder / 'stat-before.bin').write_bytes(status_bytes)
    row = {'name': label, 'original_name': original_name, 'mode': mode, 'expected': expected,
           'input_bytes': len(raw), 'input_sha256': sha(raw), 'pass': False}
    try:
        native = None
        if mode != 'read-error-close-error':
            native = direct(folder / 'native', executable,
                (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)), (b'LC_ALL=C.UTF-8',))
            assert native['returncode'] == expected and not native['timed_out']
            assert native['reaped_ECHILD'] and native['exec_failure'] is None
            assert native['image_sha256'] == native['image_after_sha256'] == sha(elf)
            assert all(item['complete'] for item in native['postreturn_buffers'].values())
            if original_name:
                oracle = original[original_name]
                assert native['returncode'] == oracle['native_returncode']
                assert sha(bytes.fromhex(native['stdout_hex'])) == oracle['stdout_sha256']
                assert native['stderr_hex'] == oracle['stderr_hex']
        record_vm_request(folder, program, components, raw, path, mode, status_bytes)
        result, stdout, stderr, calls, error = reference(program, components, raw, path, mode, status_bytes)
        buffers = save_vm(folder, result)
        (folder / 'stdout.bin').write_bytes(stdout); (folder / 'stderr.bin').write_bytes(stderr)
        publish(folder / 'PROVIDER.json', calls)
        residents = [r for r in result.get('effects', []) if r['operation'].startswith('linux.roundtrip.')]
        checks = {'VM_return': result['status'] == 'returned' and result['values'] == [expected],
            'all_three_buffers_retained': set(buffers) == {'file', 'output', 'workspace'},
            'exact_resident_call_count': len(residents) == expected_calls,
            'original_shared_fuel': result['steps'] <= 10000000,
            'no_VM_exception': error is None}
        if native is not None:
            checks['same_complete_stdout'] = stdout.hex() == native['stdout_hex']
            checks['same_complete_stderr'] = stderr.hex() == native['stderr_hex']
            for name, raw_buffer in buffers.items():
                actual = Path(native['postreturn_buffers'][name]['path']).read_bytes()
                checks['same_complete_' + name] = actual == raw_buffer
        if expected == 0:
            assert original_name
            canonical = verify_program(raw).canonical_bytes
            checks['original_JSON_preserved'] = buffers['file'][:len(raw)] == raw
            checks['first_canonical_exact_original_Core'] = buffers['file'][CAPACITY:CAPACITY + len(canonical)] == canonical
            checks['second_canonical_exact_original_Core'] = buffers['output'][:len(canonical)] == canonical
            checks['independent_assembly_preserved'] = buffers['file'][2 * CAPACITY:2 * CAPACITY + len(stdout)] == stdout
            checks['two_canonical_resident_returns'] = [residents[i]['result'] for i in (2, 4)] == [len(canonical)] * 2
            checks['five_actual_fixed_resident_calls'] = [r['operation'] for r in residents] == [
                'linux.roundtrip.representation', 'linux.roundtrip.semantic',
                'linux.roundtrip.representation', 'linux.roundtrip.representation', 'linux.roundtrip.representation']
        if mode == 'partial-and-EINTR':
            checks['real_reference_EINTR_branch'] = any(r['operation'] == 'linux.file.read' and r['result'] == -4 for r in calls)
            checks['real_reference_partial_write_branch'] = sum(r['operation'] == 'linux.stdout.write' for r in calls) > 1
        if mode == 'open-refused':
            checks['no_close_without_acquisition'] = not any(r['operation'] == 'linux.file.close' for r in calls)
        if mode == 'read-error-close-error':
            checks['original_read_error_priority'] = len(stderr) == 32 and struct.unpack('<4Q', stderr)[1:] == (66, 1, 4)
            checks['one_revoked_close'] = sum(r['operation'] == 'linux.file.close' for r in calls) == 1
        row.update(pass_=all(checks.values()), checks=checks, VM_status=result['status'], VM_steps=result['steps'],
            values=result.get('values'), residents=residents, source_bytes=len(buffers.get('file', b'')),
            native_postreturn_full_buffers=native is not None, error=error)
        row['pass'] = all(checks.values())
        assert row['pass'], row
    except BaseException:
        row['pass'] = False; row['error'] = traceback.format_exc(); raise
    finally:
        publish(folder / 'COMPARISON.json', row)
    return row


def tail_fault_case(ctx, output, index):
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from hepta.hia_linux_file_roundtrip import PROFILE
    from hepta.hia_program import verify_program
    from tools.build_hia_linux_file_roundtrip_program import _frame, _elf_structure
    from tools.build_hia_linux_file_roundtrip_cold import publish_executable
    from tests.hia_linux_file_roundtrip_exec import direct
    side = ('C1', 'C2')[index]
    folder = Path(output) / side; folder.mkdir()
    authority = ctx['authority']
    profile_compiler = Path(ctx['toolchain']['compiler_image']['path'])
    observer_folder = Path(ctx['observer']['executable']['path']).parent
    packer = observer_folder / 'observer-packer.image.bin'
    actual_components = tuple(Path(item['path']).read_bytes() for item in ctx['production']['components'][1:])
    _, captured_sources = profile_capture()
    components = tuple(captured_sources[name] for name in (
        'examples/hia_bootstrap/core_representation_private.hepta',
        'examples/hia_bootstrap/file_render_checker_v4.hepta'))
    case = next(row for row in ctx['retained']['kernel_cases'] if row['name'] == 'exports-metadata-empty')
    input_raw = retained_bytes(case['input']); canonical = verify_program(input_raw).canonical_bytes
    assert canonical and len(canonical) < CAPACITY
    row = {'name': side + '-last-byte', 'pass': False, 'production_tail_comparison_unchanged': True}
    try:
        document, author, statement = projected_document(side)
        (folder / 'fault-author.py.txt').write_text(author)
        source = render_assembly(document, profile=PROFILE).encode()
        (folder / 'fault-controller.hepta').write_bytes(source)
        program = assemble_program(source, profile=PROFILE)
        image_path, image, receipt = compile_bound(folder, 'fault-controller', profile_compiler, source, authority)
        row['compile'] = receipt
        images = (image, *actual_components); frame = _frame(images)
        (folder / 'packer-input.bin').write_bytes(frame)
        elf_path, elf, packed = compile_bound(folder, 'fault-packed', packer, frame, authority, extension='.elf.bin')
        row['packed'] = packed; inspection = _elf_structure(elf, images)
        executable = folder / 'fault-observer.elf'; publish_executable(executable, elf)
        path = folder / 'input.json'; path.write_bytes(input_raw)
        status = (ctypes.c_ubyte * 144)()
        lib = ctypes.CDLL(None, use_errno=True)
        lib.stat.argtypes = (ctypes.c_char_p, ctypes.c_void_p); lib.stat.restype = ctypes.c_int
        assert lib.stat(os.fsencode(path), status) == 0
        native = direct(folder / 'native', executable,
            (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)), (b'LC_ALL=C.UTF-8',))
        assert not native['timed_out'] and native['reaped_ECHILD'] and native['exec_failure'] is None
        assert all(v['complete'] for v in native['postreturn_buffers'].values())
        record_vm_request(folder, program, components, input_raw, path, 'ordinary', bytes(status))
        result, stdout, stderr, calls, error = reference(program, components, input_raw, path, 'ordinary', bytes(status))
        buffers = save_vm(folder, result)
        (folder / 'stdout.bin').write_bytes(stdout); (folder / 'stderr.bin').write_bytes(stderr)
        publish(folder / 'PROVIDER.json', calls)
        first = buffers['file'][CAPACITY:CAPACITY + len(canonical)]
        second = buffers['output'][:len(canonical)]
        tampered = canonical[:-1] + bytes([canonical[-1] ^ 1])
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
            'original_JSON_preserved': buffers['file'][:len(input_raw)] == input_raw,
            'five_actual_residents': len(residents) == 5 and all(e['status'] == 'returned' for e in residents),
            'two_equal_canonical_returns_before_injection': [residents[i]['result'] for i in (2, 4)] == [len(canonical)] * 2,
            'within_original_fuel': result['steps'] <= 10000000,
            'no_VM_exception': error is None}
        for name, raw in buffers.items():
            checks['same_complete_' + name] = raw == Path(native['postreturn_buffers'][name]['path']).read_bytes()
        row.update(checks=checks, VM_steps=result['steps'], injection=statement,
            fault_source_sha256=sha(source), image_sha256=sha(image), ELF_bytes=len(elf), ELF_sha256=sha(elf),
            elf_inspection=inspection, error=error, pass_=all(checks.values()))
        row['pass'] = all(checks.values())
        assert row['pass'], row
        guard_authority(authority)
    except BaseException:
        row['pass'] = False; row['error'] = traceback.format_exc(); raise
    finally:
        publish(folder / 'COMPARISON.json', row)
    return row


def reference(program, components, raw, path, mode, status_bytes):
    from hepta.hia_program_runtime import execute_program
    from hepta.hia_linux_file_roundtrip import PROFILE, LinuxStartupSnapshot
    sent, calls = {1: [], 2: []}, []
    cursor = reads = 0
    argv = (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path))
    def provider(request):
        nonlocal cursor, reads
        operation = request.operation
        row = {'operation': operation, 'fd': request.fd, 'offset': request.offset,
               'count': request.count, 'extent': request.extent}
        calls.append(row)
        if operation == 'linux.file.open':
            assert request.path == os.fsencode(path) + b'\0' and request.fd is None and request.flags == 0xa0800
            response = (-2, b'') if mode == 'open-refused' else (3, b'')
        elif operation == 'linux.file.fdflags':
            assert request.fd == 3
            response = (1, b'')
        elif operation == 'linux.file.statusflags':
            assert request.fd == 3
            response = (0x28800, b'')
        elif operation == 'linux.file.stat':
            assert request.fd == 3 and request.count == 144
            response = (0, status_bytes)
        elif operation == 'linux.file.read':
            assert request.fd == 3
            reads += 1
            if mode == 'read-error-close-error':
                response = (-5, b'')
            elif mode == 'partial-and-EINTR' and reads == 1:
                response = (-4, b'')
            else:
                count = min(request.count, 31) if mode == 'partial-and-EINTR' else request.count
                payload = raw[cursor:cursor + count]
                cursor += len(payload)
                response = (len(payload), payload)
        elif operation == 'linux.file.close':
            assert request.fd == 3
            response = (-4, b'') if mode == 'read-error-close-error' else (0, b'')
        else:
            assert operation in ('linux.stdout.write', 'linux.stderr.write') and request.fd in (1, 2)
            count = min(request.count, 7) if mode == 'partial-and-EINTR' else request.count
            sent[request.fd].append(request.write_bytes[:count])
            response = (count, b'')
        row.update(result=response[0], payload_bytes=len(response[1]), payload_sha256=sha(response[1]))
        return response
    try:
        result = execute_program(program, 'f0', (bytes(8388609), bytes(CAPACITY), bytes(CAPACITY)),
            profile=PROFILE, linux_file_provider=provider, linux_file_roundtrip_components=components,
            linux_process_startup=LinuxStartupSnapshot(argv, (b'LC_ALL=C.UTF-8',)), max_steps=10000000)
    except BaseException as exc:
        if hasattr(exc, 'report'):
            return exc.report, b''.join(sent[1]), b''.join(sent[2]), calls, traceback.format_exc()
        raise
    return result, b''.join(sent[1]), b''.join(sent[2]), calls, None


def projected_document(side):
    from tools import generate_hia_native_file_roundtrip as original
    tree = ast.parse(original.RUN)
    previous = copy.deepcopy(tree)
    run = next(node for node in tree.body if node.name == 'run')
    places = [i for i, node in enumerate(run.body) if isinstance(node, ast.If)
              and ast.unparse(node.test) == 'same_region(f, 1048576, o, 0, canonical_size) == 0']
    assert len(places) == 1
    i = places[0]
    assert ast.unparse(run.body[i - 1].test) == 'second_size != canonical_size'
    statement = ('write(f, 1048576 + canonical_size - 1, byte(f, 1048576 + canonical_size - 1) ^ 1, 1)'
                 if side == 'C1' else 'write(o, second_size - 1, byte(o, second_size - 1) ^ 1, 1)')
    inserted = ast.parse(statement).body[0]
    run.body.insert(i, inserted)
    inverse = copy.deepcopy(tree)
    del next(node for node in inverse.body if node.name == 'run').body[i]
    assert ast.dump(inverse, include_attributes=False) == ast.dump(previous, include_attributes=False)
    text = ast.unparse(ast.fix_missing_locations(tree)) + '\n'
    namespace = dict(vars(original), RUN=text)
    namespace['author_source'] = types.FunctionType(original.author_source.__code__, namespace)
    document = types.FunctionType(original.document.__code__, namespace)()
    return document, text, statement
