"""Complete retained process controls bound to a freshly admitted cold fixture."""
from pathlib import Path
import signal
import struct

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_linux_process import PROFILE
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools import hia_linux_process_cold as custody
from tools.build_hia_linux_process_program import _elf_structure
from tests.hia_linux_process_cases import direct, reference, dump, sha
from tests.hia_linux_process_buffer_observer import native as observe_buffers
from tests.hia_linux_process_startup_fault_observer import direct as fault_direct

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1048576
MAGIC = int.from_bytes(b'HIALNXE2', 'little')

def encoded(argv, env):
    return (struct.pack('<QQQ', 3546416430321002824, len(argv), len(env))
            + b''.join(struct.pack('<Q', len(x)) + x for x in argv + env))


def definitions():
    rows = []
    def add(name, prog, argv=(b'process',), env=(), data=b'', mode='ordinary', ignored=False,
            rc=0, stdout=b'', stderr=b'', vm_argv=None):
        rows.append(dict(name=name, program=prog, argv=argv, env=env, data=data, mode=mode,
            ignored=ignored, expected_rc=rc, expected_stdout=stdout, expected_stderr=stderr,
            vm_argv=argv if vm_argv is None else vm_argv))
    # Linux's actual argc==0 exec entry is checked independently using the small
    # count program; this kernel-normalized one-empty-arg is not a profile filter.
    add('kernel-empty-vector-count', 'counts', argv=(), rc=0,
        stdout=struct.pack('<QQ', 1, 0), vm_argv=(b'',))
    for name, args, env, vmargs in (
        ('empty-vectors-kernel-entry', (), (), (b'',)),
        ('explicit-empty-arg', (b'',), (), (b'',)),
        ('ordered-raw-duplicates', (b'process', b'', b'\xff\xfe\n', b'x=x'),
         (b'B=two', b'A=one', b'A=three', b'', b'NO_EQUALS', b'\xff=\x80'), None),
        ('raw-no-utf8-and-newlines', (b'\xff', b'\x01\n\x7f\x80'),
         (b'\xfe', b'=', b'X=\n\xff'), None),
        ('large-aggregate-over-1MiB', (b'process', b'x' * 64000),
         tuple(bytes([65 + i]) * 64000 for i in range(18)), None),
    ):
        exact = args if vmargs is None else vmargs
        add(name, 'inspect', argv=args, env=env, vm_argv=exact,
            stdout=encoded(exact, env), stderr=b'\xff\0\n')
    add('fd2-three-raw-bytes', 'stderr', stderr=b'\xff\0\n')
    add('fd2-closed-full-negative-EBADF', 'stderr', mode='closed-stderr', rc=93)
    add('fd2-inherited-default-SIGPIPE', 'stderr', mode='broken-stderr', rc=-signal.SIGPIPE)
    add('fd2-inherited-ignore-full-EPIPE', 'stderr', mode='broken-stderr', ignored=True, rc=94)
    add('fd2-zero-open', 'stderr-zero')
    add('fd2-zero-closed-still-EBADF', 'stderr-zero', mode='closed-stderr', rc=93)
    add('fd2-exact-1MiB', 'stderr-short', stderr=b'Z' * 1048576)
    add('fd2-nonblocking-short-write', 'stderr-short', mode='short-stderr', rc=95, stderr=None)
    for name in ('invalid-argv-index', 'invalid-env-index', 'copy-invalid-source',
                 'copy-invalid-destination', 'copy-source-overflow', 'copy-destination-overflow'):
        add(name, name, rc=-signal.SIGILL)
    add('copy-zero-at-both-ends', 'copy-zero-end', argv=(b'last',))
    data = bytes(range(256)) * 4096
    # Retain the full 12 previous fd0/fd1 kernel scenarios under the new profile;
    # original fixture bodies and checks are separately retained unchanged.
    old = [
        ('empty-input', 'bounded-copy', b'', 'ordinary', False, 0, b''),
        ('short-binary-input', 'bounded-copy', b'\0\xffshort\n', 'ordinary', False, 0, b'\0\xffshort\n'),
        ('zero-count-open', 'zero-transfer', b'unchanged', 'ordinary', False, 0, b''),
        ('zero-count-closed-read', 'zero-transfer', b'unchanged', 'closed-stdin', False, 247, b''),
        ('zero-count-closed-write', 'zero-transfer', b'unchanged', 'closed-stdout', False, 247, b''),
        ('full-signed-read-ebadf', 'read-ebadf-exact', b'untouched', 'closed-stdin', False, 93, b''),
        ('full-signed-write-ebadf', 'write-ebadf-exact', b'untouched', 'closed-stdout', False, 93, b''),
        ('SIGPIPE-default', 'bounded-copy', b'pipe payload', 'broken-stdout', False, -signal.SIGPIPE, b''),
        ('SIGPIPE-inherited-ignore-EPIPE', 'bounded-copy', b'pipe payload', 'broken-stdout', True, 224, b''),
        ('exact-1MiB', 'bounded-copy', data, 'ordinary', False, 0, data),
        ('over-1MiB-rejected-before-write', 'bounded-copy', data + b'!', 'ordinary', False, 3, b''),
        ('bounds-before-read', 'out-of-bounds', b'untouched', 'ordinary', False, -signal.SIGILL, b''),
    ]
    for name, prog, raw, mode, ignored, rc, expected in old:
        add('retained-' + name, 'retained-' + prog, data=raw, mode=mode, ignored=ignored,
            rc=rc, stdout=expected)
    return rows


def retained():
    return custody.retained_inputs()


def case_source(name):
    row = retained()['programs'][name]
    raw = row['source'].encode('utf-8')
    custody.require(type(row['bytes']) is int and len(raw) == row['bytes']
                    and custody.digest(raw) == row['sha256'], 'retained program bytes differ: ' + name)
    return raw


def program_names():
    names = tuple(dict.fromkeys(case['program'] for case in definitions())) + ('buffer-layout',)
    custody.require(len(names) == len(set(names)) == 18
                    and set(names) == set(retained()['programs']), 'complete eighteen programs required')
    return names


def checked_program(name):
    return assemble_program(case_source(name), profile=PROFILE)


def _program(fixture, name):
    row = fixture['programs'][name]
    custody.check_bindings([row['build']])
    path = Path(row['executable'])
    custody.require(custody.digest(path.read_bytes()) == row['executable_sha256'],
                    'prepared executable changed: ' + name)
    return row, path


def kernel_checks(case, actual, expected, build):
    stderr = case['expected_stderr']
    if case['mode'] == 'short-stderr':
        stderr = b'Z' * actual['pipe_capacity']
    return {
        'exec_entered': actual['exec_failure'] is None,
        'returncode': actual['returncode'] == expected['process_returncode'] == case['expected_rc'],
        'stdout': actual['stdout_hex'] == expected['expected_stdout_hex'] == case['expected_stdout'].hex(),
        'stderr': actual['stderr_hex'] == expected['expected_stderr_hex'] == stderr.hex(),
        'stdin_consumed': actual['stdin_consumed'] == expected['stdin_consumed'],
        'no_timeout': actual['timed_out'] is False, 'reaped': actual['reaped_ECHILD'] is True,
        'elf_unchanged': actual['image_sha256'] == actual['image_after_sha256'] == build['executable_sha256'],
    }


def direct_case(fixture, output, index):
    case = definitions()[index]
    build, executable = _program(fixture, case['program'])
    folder = Path(output) / case['name']
    actual = direct(folder, executable, case['argv'], case['env'], stdin=case['data'],
                    mode=case['mode'], ignored=case['ignored'])
    expected = reference(checked_program(case['program']), case['vm_argv'], case['env'],
        stdin=case['data'], mode=case['mode'], ignored=case['ignored'], short_capacity=actual['pipe_capacity'])
    dump(folder / 'VM.json', expected)
    checks = kernel_checks(case, actual, expected, build)
    row = {'name': case['name'], 'status': 'PASS' if all(checks.values()) else 'FAIL',
           'checks': checks, 'native_returncode': actual['returncode'],
           'vm_steps': expected['steps'], 'effects': len(expected['effects'])}
    dump(folder / 'CHECKS.json', row)
    return row


def pack_frame(image):
    return struct.pack('<QQQQ', MAGIC, 1, len(image), 0) + image


def packer_definitions(image):
    valid = pack_frame(image)
    invalid = 0xffffffff
    space = 0xfffffffe
    return [
        ('same-A5-full-observation', valid, CAPACITY, 8192),
        ('empty-frame', b'', CAPACITY, invalid),
        ('wrong-magic', b'x' + valid[1:], CAPACITY, invalid),
        ('wrong-version', valid[:8] + struct.pack('<Q', 2) + valid[16:], CAPACITY, invalid),
        ('reserved-field', valid[:24] + struct.pack('<Q', 1) + valid[32:], CAPACITY, invalid),
        ('zero-image', pack_frame(b''), CAPACITY, invalid),
        ('truncated-frame', valid[:-1], CAPACITY, invalid),
        ('trailing-byte', valid + b'!', CAPACITY, invalid),
        ('zero-output', valid, 0, space),
        ('short-output', valid, 8191, space),
        ('image-one-over-entry-limit', pack_frame(bytes(CAPACITY - 1024 + 1)), CAPACITY, invalid),
        ('exact-1MiB-ELF-structural-only', pack_frame(bytes(CAPACITY - 1024)), CAPACITY, CAPACITY),
        ('minimum-image-structural-only', pack_frame(b'\0'), 4096, 4096),
    ]


def packer_checks(raw, capacity, expected, values, reference, actual):
    checks = {'returned': actual['returncode'] == 0 and actual['child']['status'] == 'returned',
        'value': values == [actual['child']['result_u64']] == [expected],
        'full_source': actual['source_hex'] == reference['source_hex'] == raw.hex(),
        'full_output': actual['output_hex'] == reference['output_hex'],
        'full_workspace': actual['workspace_hex'] == reference['workspace_hex'],
        'all_canaries': all(actual['canaries']), 'no_timeout': not actual['timed_out'],
        'no_project_imports': actual['child']['forbidden_modules_loaded'] == [],
        'no_stdin_effect': actual['stdin_consumed'] == 0,
        'no_stdout_stderr': actual['stdout_hex'] == actual['stderr_hex'] == ''}
    if expected in (0xffffffff, 0xfffffffe):
        checks['refusal_before_output_mutation'] = actual['output_hex'] == (b'\xa5' * capacity).hex()
    return checks


def packer_case(fixture, output, index):
    build, _ = _program(fixture, 'counts')
    built = Path(build['build']['path']).parent
    image = (built / 'program.image.bin').read_bytes()
    packer = Path(fixture['packer_image']['path'])
    custody.check_bindings([fixture['packer_image']])
    name, raw, capacity, expected = packer_definitions(image)[index]
    roots = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'\xa5' * capacity)),
             _Owner(-3, bytearray(CAPACITY))]
    checked = assemble_program((ROOT / custody.PACKER_SOURCE).read_bytes())
    vm = _Machine(checked, 10000000, CAPACITY, None, 128)
    values = vm.invoke(vm.functions['f0'], [_View(roots[0], False),
                      _View(roots[1], True), _View(roots[2], True)])
    reference = {'values': values, 'source_hex': roots[0].data.hex(),
        'output_hex': roots[1].data.hex(), 'workspace_hex': roots[2].data.hex(),
        'steps': vm.steps, 'resources': vm.resources()}
    dump(Path(output) / (name + '.VM.json'), reference)
    actual = observe_buffers(Path(output) / name, packer, raw, b'\xa5' * capacity, bytes(CAPACITY), b'', 'ordinary')
    checks = packer_checks(raw, capacity, expected, values, reference, actual)
    if expected not in (0xffffffff, 0xfffffffe):
        elf = bytes.fromhex(actual['output_hex'])[:expected]
        inspection = _elf_structure(elf, raw[32:])
        dump(Path(output) / (name + '.ELF.json'), inspection)
        checks['W_X_and_exact_HIA_image'] = (inspection['writable_executable_segment'] is False
            and inspection['executable_stack'] is False and inspection['elf_interpreter'] is False)
    if name == 'same-A5-full-observation':
        checks['all_original_compile_output_bytes'] = actual['output_hex'] == \
            (built / 'packed.output.bin').read_bytes().hex()
    row = {'name': name, 'status': 'PASS' if all(checks.values()) else 'FAIL',
           'checks': checks, 'vm_steps': vm.steps, 'packed_synthetic_image_executed': False}
    dump(Path(output) / (name + '.CHECKS.json'), row)
    return row


def startup_case(fixture, output, index):
    mode = retained()['groups']['startup'][index]
    build, elf = _program(fixture, 'counts')
    actual = fault_direct(Path(output) / mode, elf, (b'process',), (b'A=1',),
                          stdin=b'untouched', mode='deny-' + mode)
    checks = {'ELF_entry_not_execve_failure': actual['exec_failure'] is None,
        'startup_refused': actual['returncode'] == 126,
        'no_HIA_stdout': actual['stdout_hex'] == '', 'no_stderr': actual['stderr_hex'] == '',
        'stdin_untouched': actual['stdin_consumed'] == 0,
        'no_timeout': actual['timed_out'] is False, 'child_reaped': actual['reaped_ECHILD'] is True,
        'image_unchanged': actual['image_sha256'] == actual['image_after_sha256'] == build['executable_sha256']}
    row = {'name': mode, 'checks': checks, 'status': 'PASS' if all(checks.values()) else 'FAIL'}
    dump(Path(output) / mode / 'CHECKS.json', row)
    return row


def entry_case(fixture, output, index):
    name = retained()['groups']['entry'][index]
    if index == 0:
        build, elf = _program(fixture, 'buffer-layout')
        folder = Path(output) / name
        actual = direct(folder, elf, (b'process',), ())
        expected = reference(checked_program('buffer-layout'), (b'process',), ())
        dump(folder / 'VM.json', expected)
        checks = {'native_VM_return': actual['returncode'] == expected['process_returncode'] == 0,
            'stdout_two_output_endpoints': actual['stdout_hex'] == expected['expected_stdout_hex'] == '1112',
            'stderr_two_workspace_endpoints': actual['stderr_hex'] == expected['expected_stderr_hex'] == '2122',
            'real_exec': actual['exec_failure'] is None, 'no_timeout': not actual['timed_out'],
            'reaped': actual['reaped_ECHILD']}
    elif index == 1:
        build, elf = _program(fixture, 'inspect')
        args = (b'x' * 131071,)
        folder = Path(output) / name
        actual = direct(folder, elf, args, ())
        expected = reference(checked_program('inspect'), args, ())
        dump(folder / 'VM.json', expected)
        checks = {'native_VM_return': actual['returncode'] == expected['process_returncode'] == 0,
            'all_raw_bytes': actual['stdout_hex'] == expected['expected_stdout_hex'] == encoded(args, ()).hex(),
            'stderr': actual['stderr_hex'] == expected['expected_stderr_hex'] == 'ff000a',
            'real_exec': actual['exec_failure'] is None, 'no_timeout': not actual['timed_out'],
            'reaped': actual['reaped_ECHILD']}
    else:
        build, elf = _program(fixture, 'inspect')
        args, env = ((b'x' * 131072,), ()) if index == 2 else ((b'process',), (b'x' * 65536,) * 48)
        folder = Path(output) / name
        actual = direct(folder, elf, args, env)
        checks = {'kernel_E2BIG_before_payload': actual['exec_failure'] == {
            'returncode': -1, 'errno': 7, 'payload_entered': False, 'stage': 'raw_execve'},
            'helper_failure_code_distinct': actual['returncode'] == 125,
            'no_stdout_stderr': actual['stdout_hex'] == actual['stderr_hex'] == '',
            'no_timeout': not actual['timed_out'], 'reaped': actual['reaped_ECHILD']}
    row = {'name': name, 'status': 'PASS' if all(checks.values()) else 'FAIL', 'checks': checks}
    if index >= 2:
        row.update(HIA_program_invoked=False, scope='observed kernel exec admission; not a new profile cap')
    dump(folder / 'CHECKS.json', row)
    return row


def domain_case(fixture, output, index):
    from tools.qualify_hia_selfhost import invoke, _compile_observation_size
    name = retained()['groups']['legacy'][index]
    raw = retained()['legacy_sources'][name]['source'].encode()
    folder = Path(output) / name
    folder.mkdir(mode=0o700)
    (folder / 'program.hepta').write_bytes(raw)
    old, new = Path(fixture['cold_compiler']['path']), Path(fixture['compiler_image']['path'])
    custody.check_bindings([fixture['cold_compiler'], fixture['compiler_image']])
    first, before_output = invoke(folder, 'original', old, raw)
    second, process_output = invoke(folder, 'process', new, raw)
    actual_old, observed_old = custody.probe_observation(folder, 'original', old, raw)
    actual_new, observed_new = custody.probe_observation(folder, 'process', new, raw)
    custody.require(first == actual_old and second == actual_new
                    and before_output == observed_old and process_output == observed_new,
                    'actual legacy probe receipts/output differ from independent readback')
    size = _compile_observation_size(first, before_output, image_format='flat-x86-64',
        compiler_sha256=fixture['cold_compiler']['sha256'], source_sha256=sha(raw), input_bytes=len(raw))
    checks = {'new_returns_rejection': second['status'] == 'returned'
            and second['core_u32'] == 0xffffffff and second['result_u64'] == 0xffffffff,
        'explicit_profile_domain_error': second['workspace_header']['40'] == 93,
        'no_function_emission': second['workspace_header']['64'] == 0,
        'source_unchanged': first['source_unchanged'] is True and second['source_unchanged'] is True,
        'actual_pinned_providers': first['image_sha256'] == fixture['cold_compiler']['sha256']
            and second['image_sha256'] == fixture['compiler_image']['sha256']}
    if name == 'explicit-empty-exports':
        checks['original_rejects_empty_exports_exact_68'] = (size is None and first['core_u32'] == 0xffffffff
            and first['result_u64'] == 0xffffffff and first['workspace_header']['40'] == 68)
    else:
        checks['old_original_accepts'] = size is not None
    row = {'name': name, 'checks': checks, 'status': 'PASS' if all(checks.values()) else 'FAIL',
        'old_produced_bytes': size, 'old_receipt': first, 'new_receipt': second,
        'historical_failed_all_accept_assumption_retained': True}
    dump(folder / 'CHECKS.json', row)
    return row
