"""Independent DATA-only reader for executable release-builder evidence.

This file uses only the standard library. It does not import the producer,
candidate, original VM, compiler or a test. Captured raw bytes are parsed and
hashed once, reused by every validator, then reread before the final result.
A complete finite PASS does not resolve a cold, GC, resource or whole-VM HOLD.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import struct

GROUPS = ('source-to-installed-exec', 'refusals', 'kernel-errors',
          'no-replace-and-corruption', 'copied-native-runtime')
VALID = ('assembly-echo', 'assembly-constant', 'core-json-echo')
STDIN = ('00', '49', 'ff')
REFUSALS = (
    ('empty', 2), ('bad-header', 2), ('bad-utf8', 2), ('flat-profile', 6),
    ('invalid-json', 2), ('source-digest-mismatch', 5), ('upper-digest', 64),
    ('unknown-syntax', 64), ('extra-argument', 64),
    ('assembly-input-overflow', 3), ('json-input-overflow', 3))
KERNEL = ('closed-stdin', 'full-stdout', 'mmap-failure')
CONTRACT = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
COLD_CHECKS = {
    'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero',
    'no_ancestor_git_identity', 'no_bytecode_cache_created',
    'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
    'source_export_hashes_preserved'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact(a, b):
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return a.keys() == b.keys() and all(exact(a[k], b[k]) for k in a)
    if type(a) in (list, tuple):
        return len(a) == len(b) and all(exact(x, y) for x, y in zip(a, b))
    return a == b


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, 'duplicate JSON object key')
        result[key] = value
    return result


def parsed(raw):
    def bad(value):
        raise ValueError('nonfinite JSON token: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


class Capture:
    def __init__(self):
        self.raw = {}

    def take(self, path, expected=None):
        path = Path(path)
        require(path.is_absolute() and not path.is_symlink() and path.is_file(),
                'consumed raw must be an absolute regular nonsymlink file')
        if path not in self.raw:
            self.raw[path] = path.read_bytes()
        raw = self.raw[path]
        if expected is not None:
            require(exact(pin(raw), {'bytes': expected['bytes'], 'sha256': expected['sha256']}),
                    'consumed raw pin differs: ' + str(path))
        return raw

    def record(self, value):
        return parsed(self.take(value['path'], value))

    def stable(self):
        for path, raw in self.raw.items():
            require(not path.is_symlink() and path.read_bytes() == raw,
                    'consumed raw changed at terminal: ' + str(path))


def plan():
    result = [{'id': 'original-first', 'group': 'original'},
              {'id': 'original-second', 'group': 'original'}]
    for case in VALID:
        result += [{'id': case + '-' + step, 'group': GROUPS[0]}
                   for step in ('build', 'install', 'verify', *('exec-' + x for x in STDIN))]
    result += [{'id': 'refusal-' + name, 'group': GROUPS[1]} for name, _ in REFUSALS]
    result += [{'id': 'kernel-' + name, 'group': GROUPS[2]} for name in KERNEL]
    result += [{'id': name, 'group': GROUPS[3]} for name in
               ('existing-install', 'existing-verify', 'corrupt-verify', 'restored-verify')]
    result += [{'id': name, 'group': GROUPS[4]} for name in
               ('copied-build', 'copied-install', 'copied-verify', *('copied-exec-' + x for x in STDIN))]
    return result


def elf(raw):
    require(len(raw) > 176 and raw[:16] == b'\x7fELF\x02\x01\x01' + bytes(9), 'ELF ident')
    require(struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
            == (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), 'ELF complete header')
    require(struct.unpack_from('<IIQQQQQQ', raw, 64)
            == (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), 'ELF load segment')
    require(struct.unpack_from('<IIQQQQQQ', raw, 120)
            == (0x6474e551, 6, 0, 0, 0, 0, 0, 16), 'ELF stack segment')


def package(raw):
    stream = io.BytesIO(raw)
    require(len(raw) <= 64 << 20, 'package bound')
    head = stream.read(24)
    require(len(head) == 24 and struct.unpack('<3Q', head)
            == (int.from_bytes(b'HIAREL01', 'little'), 2, 0), 'package header')
    result = []
    for wanted, wanted_mode in ((b'source.hepta', 0o400), (b'program', 0o500)):
        header = stream.read(24)
        require(len(header) == 24, 'member header')
        n, mode, extent = struct.unpack('<3Q', header)
        require(n == len(wanted) and mode == wanted_mode and extent <= len(raw), 'member fields')
        require(stream.read(n) == wanted, 'member order/name')
        content = stream.read(extent)
        require(len(content) == extent, 'member extent')
        result.append(content)
    require(stream.read() == b'', 'package exact exhaustion')
    elf(result[1])
    return result


def owner(capture, row, code):
    raw = capture.take(row['owner.json']['path'], row['owner.json'])
    actual = parsed(raw)
    request_raw = capture.take(row['owner.json.request.json']['path'], row['owner.json.request.json'])
    request = parsed(request_raw)
    observed = row['observed_owner']
    require(actual.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and request.get('schema') == actual['schema'], 'actual owner schema differs')
    require(type(actual.get('implementation_sha256')) is str
            and type(request.get('implementation_sha256')) is str
            and len(request['implementation_sha256']) == 64
            and all(c in '0123456789abcdef' for c in request['implementation_sha256'])
            and actual['implementation_sha256'] == request['implementation_sha256'],
            'actual owner receipt implementation does not bind the captured request')
    require(request['stdout_path'] == row['stdout.raw']['path']
            and request['stderr_path'] == row['stderr.raw']['path']
            and request['receipt_path'] == row['owner.json']['path'],
            'owner request does not bind the actual raw log paths')
    augmented = {**actual, 'supervisor_returncode': 0 if code == 0 else 1,
                 'receipt_sha256': sha256(raw).hexdigest()}
    require(exact(augmented, observed), 'returned owner observation differs from same raw receipt')
    require(actual.get('status') == ('OWNED_PROCESS_COMPLETED' if code == 0 else 'QUALIFICATION_FAILED')
            and type(actual.get('returncode')) is int and actual['returncode'] == code
            and actual.get('timed_out') is False and actual.get('exit_observed_before_deadline') is True
            and actual.get('subreaper_enabled') is True and actual.get('qualification_started') is True
            and actual.get('interrupted_signals') == [] and actual.get('event_overflow') is False,
            'actual owner did not complete the expected natural terminal')
    cleanup = actual.get('cleanup', {})
    require(cleanup.get('complete') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('observed_echild') is True and cleanup.get('errors') == []
            and cleanup.get('deadline_exceeded') is False, 'actual owner cleanup incomplete')
    require(type(actual.get('supervisor_pid')) is int and actual['supervisor_pid'] > 0
            and type(actual.get('qualification_pid')) is int and actual['qualification_pid'] > 0,
            'real owner/leader identities missing')
    require(actual['request_sha256'] == sha256(request_raw).hexdigest()
            and exact(request['command'], row['command'])
            and request['cwd'] == row['directory']
            and exact(request['qualification_seconds'], 120)
            and exact(request['cleanup_seconds'], 3)
            and exact(actual['qualification_seconds'], 120)
            and exact(actual['cleanup_seconds'], 3)
            and request['deadline_ns'] - request['started_ns'] == 120000000000,
            'original owner request/limits differ')
    require(type(row['started_ns']) is int and type(row['stopped_ns']) is int
            and row['started_ns'] <= request['started_ns'] <= row['stopped_ns'],
            'actual ordered owner interval differs')
    for key in ('stdout.raw', 'stderr.raw', 'owner.json.stdout.log', 'owner.json.stderr.log'):
        capture.take(row[key]['path'], row[key])
    require(capture.take(row['owner.json.stderr.log']['path']) == b'', 'owner diagnostic stderr differs')
    return capture.take(row['stdout.raw']['path']), capture.take(row['stderr.raw']['path'])


def native_command(capture, row, code, image, data, args, mode='ordinary', *, expected_image_path):
    out, err = owner(capture, row, code)
    request_raw = capture.take(row['request']['path'], row['request'])
    request = parsed(request_raw)
    require(row['image']['path'] == str(expected_image_path),
            'actual image path is not the required built/installed/copied executable')
    actual_image = capture.take(expected_image_path, row['image'])
    actual_input = capture.take(row['input']['path'], row['input'])
    require(actual_image == image and actual_input == data, 'actual child image/input differs')
    expected = {'schema': 'hepta.hia.exec-release-exec-request.v1',
        'image': row['image']['path'], 'image_sha256': sha256(image).hexdigest(),
        'input': row['input']['path'], 'input_sha256': sha256(data).hexdigest(),
        'arguments': list(args), 'mode': mode}
    require(exact(request, expected), 'actual captured exec request differs')
    require(row['command'][-4:] == ['--request', row['request']['path'],
                                  '--sha256', sha256(request_raw).hexdigest()],
            'actual child argv does not bind captured request')
    return out, err


def native_compile(capture, folder, label, compiler, source, produced):
    receipt_raw = capture.take(folder / (label + '.receipt.json'))
    receipt = parsed(receipt_raw)
    request = parsed(capture.take(folder / (label + '.request.json')))
    input_raw = capture.take(folder / (label + '.input.bin'))
    output_raw = capture.take(folder / (label + '.output.bin'))
    require(input_raw == source and capture.take(request['source']) == source
            and capture.take(request['image']) == compiler
            and request['image_sha256'] == sha256(compiler).hexdigest()
            and request['source_sha256'] == sha256(source).hexdigest()
            and exact(request['capacity'], 1 << 20)
            and exact(request['workspace_size'], 1 << 20)
            and exact(request['workspace_fill'], 0)
            and request['format'] == 'flat-x86-64'
            and request['output'] == str(folder / (label + '.output.bin')),
            'actual native request/input differs')
    size = len(produced)
    require(0 < size <= len(output_raw) == 1 << 20 and output_raw[:size] == produced,
            'actual native output prefix/extent differs')
    for field, value in (('status', 'returned'), ('abi_status', 0), ('core_u32', size),
        ('result_u64', size), ('source_unchanged', True), ('forbidden_compiler_modules_loaded', []),
        ('artifact_sha256', sha256(compiler).hexdigest()), ('image_sha256', sha256(compiler).hexdigest()),
        ('input_sha256', sha256(source).hexdigest()), ('source_sha256', sha256(source).hexdigest()),
        ('input_bytes', len(source)), ('output_sha256', sha256(output_raw).hexdigest()),
        ('format', 'flat-x86-64'), ('return_encoding', 'zero-extended-u32')):
        require(field in receipt and exact(receipt[field], value), 'native receipt field differs: ' + field)
    require(capture.take(folder / (label + '.stderr.log')) == b'', 'native compiler/packer stderr differs')
    stdout = parsed(capture.take(folder / (label + '.stdout.log')))
    for key, value in stdout.items():
        require(key in receipt and exact(receipt[key], value), 'native raw child stdout differs from receipt')
    return receipt


def build_evidence(capture, report, repo, development):
    folder = Path(report['path']).parent
    build = capture.record(report)
    require(build['schema'] == 'hepta.hia.exec-release-build.v1'
            and build['status'] == 'NATIVE_EXEC_RELEASE_BUILT'
            and exact(build['development_only'], development)
            and build['authority'] == ('EXPLICIT_DEVELOPMENT_BUILD_ONLY' if development else 'CURRENT_SOURCE_COLD'),
            'builder authority differs')
    compiler = capture.take(folder / 'captured-compiler.image.bin')
    require(sha256(compiler).hexdigest() == build['compiler_sha256'], 'captured compiler pin differs')
    images = {}
    for label, source_name in (('policy', 'exec_release_policy'), ('packer', 'exec_release_packer'),
                               ('frontend', 'core_json_frontend'), ('sha256', 'sha256_stream')):
        image = capture.take(folder / build['image_paths'][label])
        source = capture.take(repo / 'examples/hia_bootstrap' / (source_name + '.hepta'))
        receipt = native_compile(capture, folder, label, compiler, source, image)
        require(exact(receipt, build['compile_receipts'][label])
                and sha256(image).hexdigest() == build['image_sha256'][label],
                'complete original compile receipt differs')
        images[label] = image
    frame = struct.pack('<5Q', int.from_bytes(b'HIAERB01', 'little'),
        len(images['policy']), len(images['frontend']), len(compiler), len(images['sha256']))
    frame += images['policy'] + images['frontend'] + compiler + images['sha256']
    executable = capture.take(folder / build['executable_path'])
    elf(executable)
    receipt = native_compile(capture, folder, 'native-pack', images['packer'], frame, executable)
    require(exact(receipt, build['pack_receipt']) and sha256(frame).hexdigest() == build['packer_frame_sha256']
            and len(frame) == build['packer_frame_bytes']
            and sha256(executable).hexdigest() == build['executable_sha256']
            and len(executable) == build['executable_bytes'], 'actual final executable binding differs')
    for relative, digest in build['source_sha256'].items():
        require(sha256(capture.take(repo / relative)).hexdigest() == digest
                and build['source_manifest'].get(relative) == digest, 'specific builder source changed')
    if not development:
        cold_raw = capture.take(folder / 'captured-cold.json')
        cold = parsed(cold_raw)
        require(sha256(cold_raw).hexdigest() == build['cold_report_sha256']
                and cold['schema'] == 'hepta.hia.selfhost-cold-replay.v1'
                and cold['status'] == 'COLD_SELFHOST_REPLAY_PASS'
                and exact(cold['returncode'], 0)
                and set(cold['checks']) == COLD_CHECKS and all(v is True for v in cold['checks'].values())
                and cold['generation_sha256'] == [build['compiler_sha256']] * 3
                and exact(cold['source_manifest'], build['source_manifest']),
                'complete matching-cold builder admission differs')
    else:
        require(build['cold_report_sha256'] is None, 'DEV evidence cannot acquire a cold claim')
    return build, executable, compiler


def installer_evidence(capture, report, repo, development, compiler):
    folder = Path(report['path']).parent
    build = capture.record(report)
    if development:
        require(build['schema'] == 'hepta.hia.exec-release-dev-installer.v1'
                and build['development_only'] is True, 'DEV installer identity differs')
        labels = (('release_install_policy', 'release_install_policy'),
                  ('release_install_packer', 'release_install_packer'), ('sha256_stream', 'sha256_stream'))
        pack_label = 'installer-pack'
        executable = capture.take(build['executable']['path'], build['executable'])
    else:
        require(build['schema'] == 'hepta.hia.release-install-build.v1'
                and build['status'] == 'NATIVE_RELEASE_INSTALLER_BUILT', 'original installer identity differs')
        labels = (('policy', 'release_install_policy'), ('packer', 'release_install_packer'),
                  ('sha256', 'sha256_stream'))
        pack_label = 'release-pack'
        executable = capture.take(folder / build['executable_path'])
        require(sha256(executable).hexdigest() == build['executable_sha256'], 'installer executable pin differs')
    require(sha256(compiler).hexdigest() == build['compiler_sha256'], 'installer compiler pin differs')
    images = []
    for label, source_name in labels:
        image = capture.take(folder / (label + '.image.bin'))
        source = capture.take(repo / 'examples/hia_bootstrap' / (source_name + '.hepta'))
        actual = native_compile(capture, folder, label, compiler, source, image)
        require(exact(actual, build['compile_receipts'][label]), 'installer complete compile receipt differs')
        images.append(image)
    frame = struct.pack('<3Q', int.from_bytes(b'HIAINS01', 'little'), len(images[0]), len(images[2])) + images[0] + images[2]
    receipt = native_compile(capture, folder, pack_label, images[1], frame, executable)
    require(exact(receipt, build['pack_receipt']), 'installer pack receipt differs')
    elf(executable)
    return executable


def read_evidence(repo, report_path, expected_report_pin, output):
    repo, report_path, output = Path(repo).resolve(), Path(report_path).resolve(), Path(output).resolve()
    capture, errors = Capture(), []
    evidence = report_path.parent
    groups = {}
    observed = {}
    development = None
    try:
        report_raw = capture.take(report_path, expected_report_pin)
        report = parsed(report_raw)
        require(report['schema'] == 'hepta.hia.exec-release-qualification.v1', 'producer schema differs')
        development = report['development_only']
        require(type(development) is bool, 'authority choice is not an exact bool')
        require(report['status'] == ('PASS_EXPLICIT_DEVELOPMENT_FINITE_ONLY' if development else
                'PASS_CURRENT_SOURCE_NATIVE_EXEC_RELEASE_FINITE'), 'producer terminal remains HOLD')
        required = plan()
        require(exact(report['planned'], required)
                and exact(parsed(capture.take(evidence / 'planned.json')), required)
                and [{'id': r['id'], 'group': r['group']} for r in report['commands']] == required,
                'complete 44-command inventory/order differs')
        require(report['errors'] == [] and report['missing_commands'] == [], 'producer is incomplete')
        expected_groups = {GROUPS[0]: list(VALID), GROUPS[1]: [name for name, _ in REFUSALS],
            GROUPS[2]: list(KERNEL), GROUPS[3]: ['complete-no-replace-corruption'],
            GROUPS[4]: ['complete-copied-runtime']}
        require(set(report['groups']) == set(expected_groups), 'complete group inventory differs')
        for group, labels in expected_groups.items():
            require(exact(report['groups'][group], [{'id': name, 'status': 'PASS'} for name in labels]),
                    'producer group is incomplete or remains HOLD: ' + group)
        for flag in ('all_input_equivalence_proved', 'ordinary_cli_default_changed', 'public_vm_replaced',
                     'whole_native_delivery_qualified', 'cold_or_gc_or_existing_resource_holds_resolved'):
            require(report[flag] is False, 'finite evidence widened its scope')
        for key, relative in (('consumed_files', 'consumed-files.json'),
                              ('expectations', 'expectations.json'),
                              ('builder_report', 'builder/build.json'),
                              ('installer_report', 'installer-build/build.json')):
            require(type(report[key]) is dict and report[key]['path'] == str(evidence / relative),
                    'producer control path is not the required fresh evidence location: ' + key)
        ledger = capture.record(report['consumed_files'])
        paths = [row['path'] for row in ledger]
        require(len(paths) == len(set(paths)) and paths == sorted(paths), 'consumption ledger duplicates/order')
        for entry in ledger:
            capture.take(entry['path'], entry)
        source_map = report['source_manifest']
        require(type(source_map) is dict and source_map, 'complete source map is absent')
        for relative, digest in source_map.items():
            require(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts,
                    'source path escapes repository')
            require(sha256(capture.take(repo / relative)).hexdigest() == digest, 'current source pin differs')
        contract_raw = capture.take(repo / CONTRACT)
        contract = parsed(contract_raw)
        require(exact({**contract['source_identity']['files'], CONTRACT: sha256(contract_raw).hexdigest()}, source_map),
                'producer map is not the complete current contract map')
        frozen = capture.record(report['expectations'])
        require(frozen['schema'] == 'hepta.hia.exec-release-expectations.v1'
                and frozen['candidate_started'] is False and frozen['whole_native_delivery_qualified'] is False
                and exact(frozen['source_manifest'], source_map) and exact(frozen['planned'], required),
                'original-first freeze differs')
        original_raw = []
        for index in range(2):
            row = report['commands'][index]
            stdout, stderr = owner(capture, row, 0)
            require(stdout == b'' and stderr == b'', 'original child raw output differs')
            require(exact(row['original'], frozen['originals'][index]), 'original freeze raw pin differs')
            original_raw.append(capture.take(row['original']['path'], row['original']))
        require(original_raw[0] == original_raw[1], 'complete original-first and second bytes differ')
        reference = parsed(original_raw[0])
        require(reference['schema'] == 'hepta.hia.exec-release-originals.v1'
                and [r['id'] for r in reference['cases']] == list(VALID), 'original domain differs')
        expected_input_ids = list(VALID) + ['refusal-' + name for name, _ in REFUSALS]
        require(type(frozen['inputs']) is list
                and [row['id'] for row in frozen['inputs']] == expected_input_ids,
                'all fourteen original/refusal inputs must occur once in the fixed order')
        frozen_inputs = {row['id']: row for row in frozen['inputs']}
        require(len(frozen_inputs) == 14, 'complete valid/refusal input inventory differs')
        for row in frozen['inputs']:
            capture.take(row['path'], row)
        require(report['commands'][1]['stopped_ns'] <= frozen['frozen_ns']
                < report['commands'][2]['started_ns'], 'original freeze did not precede the actual candidate')
        for earlier, later in zip(report['commands'], report['commands'][1:]):
            require(earlier['stopped_ns'] <= later['started_ns'], 'child order overlaps/reverses')
        fixed_sources = tuple(repo / name for name in (
            'tools/hia_selfhost_process_owner.py', 'tools/hia_exec_release_child.py',
            'tests/hia_exec_release_controls.py'))
        python = report['commands'][0]['command'][0]
        require(type(python) is str and Path(python).is_absolute(), 'actual Python setup path is absent')
        for index, row in enumerate(report['commands']):
            require(set(row['source_pins']) == {str(path) for path in fixed_sources},
                    'complete actual owner/setup/original source inventory differs')
            for path, expected in row['source_pins'].items():
                raw = capture.take(path, expected)
                require(source_map.get(str(Path(path).relative_to(repo))) == sha256(raw).hexdigest(),
                        'actual owner/setup/original source is outside the admitted current map')
            actual_request = parsed(capture.take(row['owner.json.request.json']['path']))
            require(actual_request['implementation_sha256'] == sha256(capture.take(fixed_sources[0])).hexdigest(),
                    'owner actual implementation pin differs')
            env = actual_request['env']
            required_env = {'PATH': '/usr/bin:/bin', 'HOME': row['directory'],
                'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}
            require(type(env) is dict and set(env) in (set(required_env), set(required_env) | {'LD_LIBRARY_PATH'})
                    and all(type(value) is str for value in env.values())
                    and all(env.get(key) == value for key, value in required_env.items()),
                    'actual setup environment contains an unbound selection or differs')
            if index < 2:
                expected_command = [python, '-I', '-S', '-B', str(fixed_sources[2]),
                                    '--originals', row['original']['path']]
            else:
                request_raw = capture.take(row['request']['path'], row['request'])
                expected_command = [python, '-I', '-S', '-B', str(fixed_sources[1]),
                    '--request', row['request']['path'], '--sha256', sha256(request_raw).hexdigest()]
            require(exact(row['command'], expected_command),
                    'actual full original/setup command differs from the frozen source path')
        build, app, compiler = build_evidence(capture, report['builder_report'], repo, development)
        require(exact(build['source_manifest'], source_map), 'builder/full observation source map differs')
        release = installer_evidence(capture, report['installer_report'], repo, development, compiler)
        by_id = {row['id']: row for row in report['commands']}
        packages, programs, roots = {}, {}, {}
        for case in reference['cases']:
            identity, source = case['id'], bytes.fromhex(case['source_hex'])
            require(capture.take(frozen_inputs[identity]['path']) == source
                    and sha256(source).hexdigest() == case['source_sha256'], 'original exact source input differs')
            out, err = native_command(capture, by_id[identity + '-build'], 0, app, source,
                                     (case['syntax'], sha256(source).hexdigest()),
                                     expected_image_path=evidence / 'builder/hia-exec-release')
            source_member, program = package(out)
            require(source_member == source, 'entire raw source is not preserved in member')
            expected_receipt = {
                'schema': 'hepta.hia.exec-release.v1', 'status': 'PACKAGE_BUILT', 'syntax': case['syntax'],
                'profile': 'selfhost-exec-linux-x86_64.v1', 'source_sha256': sha256(source).hexdigest(),
                'image_sha256': sha256(program).hexdigest(), 'package_sha256': sha256(out).hexdigest(),
                'source_bytes': len(source), 'image_bytes': len(program), 'package_bytes': len(out),
                'members': 2, 'runtime_python': False, 'generated_program_executed': False,
                'installed': False, 'published': False}
            require(exact(parsed(err), expected_receipt), 'complete HIA package receipt differs')
            digest = sha256(out).hexdigest()
            root = evidence / 'releases' / identity
            for operation in ('install', 'verify'):
                stdout, stderr = native_command(capture, by_id[identity + '-' + operation], 0,
                    release, out, (operation, str(root), digest),
                    expected_image_path=evidence / 'installer-build/hia-release')
                require(stderr == b'' and exact(parsed(stdout), {
                    'schema': 'hepta.hia.release-install.v1', 'sha256': digest,
                    'files': 2, 'bytes': len(out), 'published': operation == 'install'}), 'native install/verify receipt')
            installed = root / digest
            require(installed.stat().st_mode & 0o7777 == 0o500
                    and sorted(p.name for p in installed.iterdir()) == ['program', 'source.hepta'],
                    'actual installed directory differs')
            for name, mode, raw in (('source.hepta', 0o400, source), ('program', 0o500, program)):
                target = installed / name
                require(capture.take(target) == raw and target.stat().st_mode & 0o7777 == mode,
                        'actual installed member bytes/mode differs')
            require([r['input_hex'] for r in case['executions']] == list(STDIN), 'complete original inputs differ')
            for result in case['executions']:
                original = result['result']
                require(original['status'] == 'returned' and exact(original['values'], [1, int(result['stdout_hex'], 16)])
                        and exact(original['resources']['live_owners'], 0)
                        and exact(original['resources']['live_local_loans'], 0), 'complete original VM record differs')
                stdout, stderr = native_command(capture, by_id[identity + '-exec-' + result['input_hex']],
                    0, program, bytes.fromhex(result['input_hex']), (),
                    expected_image_path=installed / 'program')
                require(stderr == b'' and stdout.hex() == result['stdout_hex'], 'actual native ET_EXEC result differs')
            packages[identity], programs[identity], roots[identity] = out, program, root
        groups[GROUPS[0]] = {'commands': 18, 'installed_program_executions': 9, 'status': 'PASS'}
        echo = bytes.fromhex(reference['cases'][0]['source_hex'])
        require(echo.count(b'v8 selfhost_exec\n') == 1, 'frozen original executable echo marker differs')
        flat = echo.replace(b'v8 selfhost_exec\n', b'v8 selfhost\n', 1)
        independent_refusals = (
            ('empty', b'', 'assembly', None, (), 2),
            ('bad-header', b'not HIA\n', 'assembly', None, (), 2),
            ('bad-utf8', b'\xff', 'assembly', None, (), 2),
            ('flat-profile', flat, 'assembly', None, (), 6),
            ('invalid-json', b'{}', 'core-json', None, (), 2),
            ('source-digest-mismatch', echo, 'assembly', '0' * 64, (), 5),
            ('upper-digest', echo, 'assembly', 'A' * 64, (), 64),
            ('unknown-syntax', echo, 'unknown', None, (), 64),
            ('extra-argument', echo, 'assembly', None, ('unexpected',), 64),
            ('assembly-input-overflow', b' ' * ((1 << 20) + 1), 'assembly', None, (), 3),
            ('json-input-overflow', b' ' * ((8 << 20) + 1), 'core-json', None, (), 3),
        )
        require([(name, code) for name, _, _, _, _, code in independent_refusals] == list(REFUSALS),
                'independent refusal inventory differs')
        for name, expected_data, syntax, wanted_digest, extra, code in independent_refusals:
            item = frozen_inputs['refusal-' + name]
            data = capture.take(item['path'], item)
            arguments = [syntax, sha256(expected_data).hexdigest() if wanted_digest is None else wanted_digest, *extra]
            require(data == expected_data and exact(item['arguments'], arguments)
                    and exact(item['expected_returncode'], code),
                    'frozen refusal bytes/arguments/class differ from the independent complete specification')
            out, err = native_command(capture, by_id['refusal-' + name], code, app, data, arguments,
                expected_image_path=evidence / 'builder/hia-exec-release')
            require(out == b'' and exact(parsed(err), {'schema': 'hepta.hia.exec-release.v1',
                'status': 'rejected', 'code': code, 'observed_stdout_bytes': 0,
                'installed': False, 'published': False}), 'complete refusal observation differs')
        groups[GROUPS[1]] = {'commands': 11, 'status': 'PASS'}
        echo = bytes.fromhex(reference['cases'][0]['source_hex'])
        for mode in KERNEL:
            out, err = native_command(capture, by_id['kernel-' + mode], 4, app, echo,
                ('assembly', sha256(echo).hexdigest()), mode,
                expected_image_path=evidence / 'builder/hia-exec-release')
            require(out == b'' and exact(parsed(err), {'schema': 'hepta.hia.exec-release.v1',
                'status': 'rejected', 'code': 4, 'observed_stdout_bytes': 0,
                'installed': False, 'published': False}), 'complete kernel refusal observation differs')
        groups[GROUPS[2]] = {'commands': 3, 'status': 'PASS'}
        package_raw, root = packages['assembly-echo'], roots['assembly-echo']
        digest = sha256(package_raw).hexdigest()
        for label, op, code in (('existing-install', 'install', 14), ('existing-verify', 'verify', 0),
                                ('corrupt-verify', 'verify', 11), ('restored-verify', 'verify', 0)):
            stdout, stderr = native_command(capture, by_id[label], code, release, package_raw,
                                           (op, str(root), digest),
                                           expected_image_path=evidence / 'installer-build/hia-release')
            if code == 0:
                require(stderr == b'' and exact(parsed(stdout), {
                    'schema': 'hepta.hia.release-install.v1', 'sha256': digest, 'files': 2,
                    'bytes': len(package_raw), 'published': False}), 'read-only verify receipt differs')
            else:
                require(stdout == b'', 'rejected installation wrote success output')
        before = capture.take(evidence / 'corruption-before.raw')
        during = capture.take(evidence / 'corruption-during.raw')
        restored = capture.take(evidence / 'corruption-restored.raw')
        mutation = parsed(capture.take(evidence / 'corruption.json'))
        require(before == echo and during == before + b'\n' and restored == before
                and exact(mutation['source_before'], pin(before))
                and exact(mutation['source_during'], pin(during))
                and exact(mutation['source_restored'], pin(restored))
                and type(mutation['inode_before']) is int
                and mutation['inode_before'] == mutation['inode_during'] == mutation['inode_restored']
                and mutation['test_owned_control'] is True, 'explicit real corruption/restoration evidence differs')
        groups[GROUPS[3]] = {'commands': 4, 'status': 'PASS'}
        out, err = native_command(capture, by_id['copied-build'], 0, app, echo,
                                 ('assembly', sha256(echo).hexdigest()),
                                 expected_image_path=evidence / 'copied/builder')
        require(out == package_raw and exact(parsed(err), parsed(capture.take(by_id['assembly-echo-build']['stderr.raw']['path']))),
                'copied runtime package/receipt differs')
        copied_root = evidence / 'copied' / 'releases'
        for op in ('install', 'verify'):
            stdout, stderr = native_command(capture, by_id['copied-' + op], 0, release, package_raw,
                (op, str(copied_root), digest), expected_image_path=evidence / 'copied/installer')
            require(stderr == b'' and exact(parsed(stdout), {'schema': 'hepta.hia.release-install.v1',
                'sha256': digest, 'files': 2, 'bytes': len(package_raw), 'published': op == 'install'}),
                'copied native installer differs')
        for result in reference['cases'][0]['executions']:
            stdout, stderr = native_command(capture, by_id['copied-exec-' + result['input_hex']], 0,
                programs['assembly-echo'], bytes.fromhex(result['input_hex']), (),
                expected_image_path=copied_root / digest / 'program')
            require(stderr == b'' and stdout.hex() == result['stdout_hex'], 'copied ET_EXEC differs')
        groups[GROUPS[4]] = {'commands': 6, 'status': 'PASS'}
        observed = {'original_complete_records': 2, 'actual_owned_commands': 44,
                    'native_installed_program_executions': 12, 'complete_case_order': required}
    except Exception as error:
        errors.append({'type': type(error).__name__, 'message': str(error)})
    try:
        capture.stable()
    except Exception as error:
        errors.append({'type': type(error).__name__, 'message': str(error)})
    status = ('PASS_READBACK_EXPLICIT_DEV_FINITE_ONLY' if development else
              'PASS_READBACK_CURRENT_SOURCE_NATIVE_EXEC_RELEASE_FINITE') if not errors else 'HOLD'
    result = {'schema': 'hepta.hia.exec-release-readback.v1', 'status': status,
        'evidence_integrity': 'PASS' if not errors else 'HOLD', 'errors': errors,
        'producer_report': {'path': str(report_path), **pin(capture.raw[report_path])}
            if report_path in capture.raw else {'path': str(report_path), **expected_report_pin},
        'development_only': development, 'groups': groups, 'observed': observed,
        'all_input_equivalence_proved': False, 'ordinary_cli_default_changed': False,
        'public_vm_replaced': False, 'whole_native_delivery_qualified': False,
        'cold_or_gc_or_existing_resource_holds_resolved': False}
    output.mkdir(mode=0o700)
    ledger = [{'path': str(path), **pin(raw)} for path, raw in sorted(capture.raw.items())]
    with (output / 'consumed-raw.json').open('x') as stream:
        json.dump(ledger, stream, sort_keys=True, indent=2); stream.write('\n')
    with (output / 'READBACK.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2); stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--report-sha256', required=True)
    parser.add_argument('--report-bytes', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{64}', args.report_sha256) is not None
            and args.report_bytes > 0, 'external producer raw pin is required')
    result = read_evidence(args.repo, args.report,
        {'bytes': args.report_bytes, 'sha256': args.report_sha256}, args.output)
    print(json.dumps({'status': result['status'], 'output': str(args.output)}))
    return 0 if result['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
