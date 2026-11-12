"""Freeze exact source/tool/header/previous-compiler inputs. No product runs.

This authoring command performs file reads, copies no external tool or prior
compiler artifacts, and creates only manifests/request/proofs in this private
plan directory. C compilation, runtime symbol admission and HIA are not run.
"""
from __future__ import annotations

import ast
from hashlib import sha256, sha1
import json
import os
from pathlib import Path
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parent
CONTROL = ROOT / 'control'
sys.path.insert(0, str(CONTROL))
from common import identity, directory_identity, require, wire

OLD = Path('/tmp/hia-core-integer-native-current-v89-r2-20261112-e26e')
ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r1-20261112-e26e')
PYTHON = Path('/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12')


def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def original(path):
    path = Path(path)
    before = identity(path.stat())
    raw = path.read_bytes()
    require(before == identity(path.stat()) and len(raw) == before['size'], 'input changed during freeze')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': blob(raw), 'mode': stat.S_IMODE(before['mode'])}, raw


def create(path, value):
    raw = wire(value)
    with open(path, 'xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)
    record, observed = original(path)
    require(observed == raw, 'authoring creation readback differs')
    return record


def c_dependencies(path):
    """Read ELF declared libraries/interpreter without executing that file."""
    raw = path.read_bytes()
    if raw[:4] != b'\x7fELF':
        return [], []
    header = struct.Struct('<16sHHIQQQIHHHHHH')
    program = struct.Struct('<IIQQQQQQ')
    fields = header.unpack_from(raw)
    require(fields[0][:7] == b'\x7fELF\x02\x01\x01', 'unsupported external tool ELF profile')
    ph_at, ph_size, ph_count = fields[5], fields[9], fields[10]
    require(ph_size == program.size, 'external ELF program table differs')
    segments = [program.unpack_from(raw, ph_at + i * ph_size) for i in range(ph_count)]
    names, interpreters, dynamics = [], [], []
    for row in segments:
        if row[0] == 3:
            interpreters.append(raw[row[2]:row[2] + row[5]].rstrip(b'\0').decode())
        if row[0] == 2:
            dynamics.extend(struct.unpack_from('<qQ', raw, at)
                            for at in range(row[2], row[2] + row[5], 16))
    strings = next((value for tag, value in dynamics if tag == 5), None)
    string_bytes = next((value for tag, value in dynamics if tag == 10), 0)
    if strings is not None:
        matches = [row[2] + strings - row[3] for row in segments
                   if row[0] == 1 and row[3] <= strings < row[3] + row[5]]
        require(len(matches) == 1, 'external ELF strings lack one actual file mapping')
        table = raw[matches[0]:matches[0] + string_bytes]
        for tag, value in dynamics:
            if tag == 1:
                end = table.find(b'\0', value)
                require(end >= value, 'external ELF library name malformed')
                names.append(table[value:end].decode())
    return names, interpreters


def system_inputs():
    roots = [Path('/usr/include'),
             Path('/usr/lib/gcc/x86_64-linux-gnu/14/include'),
             PYTHON.parents[1] / 'include/python3.12',
             PYTHON.parents[1] / 'lib/python3.12']
    tools = [Path('/usr/bin/x86_64-linux-gnu-gcc-14'),
             Path('/usr/libexec/gcc/x86_64-linux-gnu/14/cc1'),
             Path('/usr/libexec/gcc/x86_64-linux-gnu/14/collect2'),
             Path('/usr/libexec/gcc/x86_64-linux-gnu/14/lto-wrapper'),
             Path('/usr/libexec/gcc/x86_64-linux-gnu/14/liblto_plugin.so'),
             Path('/usr/bin/as'), Path('/usr/bin/ld'),
             Path('/usr/bin/x86_64-linux-gnu-as'), Path('/usr/bin/x86_64-linux-gnu-ld'),
             Path('/usr/bin/x86_64-linux-gnu-ld.bfd'), PYTHON,
             Path('/etc/ld.so.cache')]
    trees, physical, links = [], {}, {}
    pending = roots[:]
    seen_roots = set()
    def add_file(path):
        current = Path('/')
        for part in path.parts[1:]:
            current = current / part
            information = current.lstat()
            if stat.S_ISLNK(information.st_mode):
                links[str(current)] = {'path': str(current), 'identity': identity(information),
                    'target': os.readlink(current), 'resolved': str(current.resolve(strict=True))}
        resolved = path.resolve(strict=True)
        require(resolved.is_file(), 'fixed external path is not a file: ' + str(path))
        if path.is_symlink():
            links[str(path)] = {'path': str(path), 'identity': identity(path.lstat()),
                                'target': os.readlink(path), 'resolved': str(resolved)}
        physical[str(resolved)] = resolved
    while pending:
        base = pending.pop(0).resolve(strict=True)
        if str(base) in seen_roots:
            continue
        seen_roots.add(str(base))
        excluded = ['site-packages'] if base == PYTHON.parents[1] / 'lib/python3.12' else []
        entries = []
        directories = [base]
        while directories:
            directory = directories.pop()
            for path in sorted(directory.iterdir()):
                info = path.lstat()
                row = {'path': path.relative_to(base).as_posix()}
                if row['path'] in excluded:
                    require(stat.S_ISDIR(info.st_mode), 'isolated site subtree changed type')
                    row.update(kind='excluded-site-directory', identity=list(directory_identity(info)))
                    entries.append(row)
                    continue
                if stat.S_ISDIR(info.st_mode):
                    row.update(kind='directory', identity=list(directory_identity(info)))
                    directories.append(path)
                elif stat.S_ISREG(info.st_mode):
                    row.update(kind='regular', identity=identity(info))
                    add_file(path)
                elif stat.S_ISLNK(info.st_mode):
                    resolved = path.resolve(strict=True)
                    row.update(kind='symlink', identity=identity(info), target=os.readlink(path), resolved=str(resolved))
                    if resolved.is_dir():
                        pending.append(resolved)
                    else:
                        add_file(path)
                else:
                    raise ValueError('special fixed header input: ' + str(path))
                entries.append(row)
        entries.sort(key=lambda row: row['path'])
        trees.append({'root': str(base), 'entries': entries, 'excluded_subtrees': excluded})
    # Freeze ELF dependencies of all actually selected tools recursively.
    # Resolution paths and original ld.so.cache are explicit input evidence;
    # this does not claim a locked kernel or all possible system libraries.
    tool_queue = tools[:] + [path for path in physical.values()
                             if '.so' in path.name and str(path).startswith(str(PYTHON.parents[1]))]
    tool_seen, dependencies = set(), []
    search = [Path('/usr/lib/x86_64-linux-gnu'), Path('/lib/x86_64-linux-gnu'),
              Path('/usr/lib'), PYTHON.parents[1] / 'lib']
    while tool_queue:
        lexical = tool_queue.pop(0)
        add_file(lexical)
        path = lexical.resolve(strict=True)
        if str(path) in tool_seen:
            continue
        tool_seen.add(str(path))
        libraries, interpreters = c_dependencies(path)
        for name in libraries:
            matches = {str((folder / name).resolve(strict=True)): folder / name
                       for folder in search if (folder / name).is_file()}
            require(len(matches) == 1, 'ambiguous/missing fixed compiler runtime library: ' + name)
            target = next(iter(matches.values()))
            dependencies.append({'from': str(path), 'needed': name, 'path': str(target),
                                 'physical': str(target.resolve(strict=True))})
            tool_queue.append(target)
        for name in interpreters:
            dependencies.append({'from': str(path), 'interpreter': name,
                                 'physical': str(Path(name).resolve(strict=True))})
            tool_queue.append(Path(name))
    files = []
    for name, path in sorted(physical.items()):
        record, _ = original(path)
        info = identity(path.lstat())
        require(stat.S_ISREG(info['mode']), 'physical system leaf changed type')
        files.append({'physical_path': name, 'bytes': record['bytes'], 'sha256': record['sha256'],
                      'git_blob': record['git_blob'], 'identity': info})
    return {'schema': 'hia.cli-json.fixed-system-inputs.v1', 'status': 'FROZEN_NOT_EXECUTED',
            'trees': sorted(trees, key=lambda row: row['root']), 'files': files,
            'standalone_links': [links[name] for name in sorted(links)],
            'ELF_declared_dependencies': dependencies,
            'full_tool_or_product_execution': False,
            'library_resolution_is_fixed_observation_not_OS_lock': True}


def main():
    require(not ACTUAL.exists(), 'new finite actual root already exists')
    source_files, source_directories = [], []
    parsed = []
    for path in sorted((ROOT / 'source').rglob('*')):
        name = path.relative_to(ROOT / 'source').as_posix()
        if path.is_dir():
            source_directories.append(name)
        else:
            row, raw = original(path); row['path'] = name; source_files.append(row)
            if path.suffix == '.py':
                ast.parse(raw); parsed.append(str(path))
    for path in sorted(CONTROL.glob('*.py')):
        ast.parse(path.read_bytes()); parsed.append(str(path))
    ast.parse(Path(__file__).read_bytes()); parsed.append(str(Path(__file__)))
    contract_tree = ast.parse((CONTROL / 'case_contract.py').read_bytes())
    literals = {node.targets[0].id: ast.literal_eval(node.value) for node in contract_tree.body
                if isinstance(node, ast.Assign)}
    system = system_inputs()
    system_record = create(ROOT / 'SYSTEM-INPUTS.json', system)
    previous = json.loads((OLD / 'POLICY.json').read_bytes())
    external = {}
    for row in previous['current_compiler_capsule']['originals']:
        record, raw = original(OLD / row['path'])
        require(record['bytes'] == row['bytes'] and record['sha256'] == row['sha256']
                and record['git_blob'] == row['git_blob_sha1'], 'current original capsule pin differs')
        external[record['path']] = record
    for row in list(previous['current_compiler_capsule']['independent_readback'].values()) + list(previous['compiler_helpers'].values()):
        record, raw = original(OLD / row['path'])
        require(record['bytes'] == row['bytes'] and record['sha256'] == row['sha256']
                and record['git_blob'] == row['git_blob_sha1'], 'current original helper/readback pin differs')
        external[record['path']] = record
    compiler_policy_record, _ = original(OLD / 'POLICY.json')
    external[compiler_policy_record['path']] = compiler_policy_record
    python_record, _ = original(PYTHON)
    require(python_record['sha256'] == 'fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7',
            'exact interpreter source pin differs')
    controls = []
    for path in sorted(CONTROL.glob('*')):
        require(path.is_file(), 'unfrozen directory under control')
        row, _ = original(path); row['path'] = path.relative_to(ROOT).as_posix(); controls.append(row)
    for path in (ROOT / 'SYSTEM-INPUTS.json', Path(__file__)):
        row, _ = original(path); row['path'] = path.relative_to(ROOT).as_posix(); controls.append(row)
    controls.sort(key=lambda row: row['path'])
    assets = []
    for path in sorted((ROOT / 'assets').iterdir()):
        row, _ = original(path); row['path'] = path.relative_to(ROOT).as_posix(); assets.append(row)
    hia = next(row for row in assets if row['path'].endswith('.hiaasm'))
    require(hia['bytes'] == 26967 and hia['sha256'] == '43b7d82d0dd14cc44e70168127801046d17112c4e0338b453c251e575a791ec4',
            'actual source-qualified lifetime HIA differs')
    work = ACTUAL / 'work'
    includes = [str(PYTHON.parents[1] / 'include/python3.12'),
                '/usr/lib/gcc/x86_64-linux-gnu/14/include', '/usr/include/x86_64-linux-gnu', '/usr/include']
    command = ['/usr/bin/x86_64-linux-gnu-gcc-14', '-v', '-std=c11', '-O2', '-fPIC',
               '-fno-stack-protector', '-fno-common', '-shared', '-nostdlib', '-nostdinc',
               '-Werror=implicit-function-declaration', '-Wl,--build-id=none',
               '-B/usr/libexec/gcc/x86_64-linux-gnu/14/', '-B/usr/bin/']
    for path in includes:
        command.extend(['-isystem', path])
    command.extend(['-MD', '-MF', str(work / 'c-build/cli-json.d'), '-MT', str(work / 'c-build/cli-json.so'),
                    str(ROOT / 'source/hepta/hia_cli_json_cpython.c'), '-o', str(work / 'c-build/cli-json.so')])
    policy = {
        'schema': 'hia.cli-json.C-runtime-lifetime-policy.v1',
        'operation_key': 'hia-cli-json-c-runtime-lifetime-local312-r1', 'operation_root': str(ACTUAL),
        'qualification_seconds': 180, 'cleanup_seconds': 3, 'child_seconds': 5,
        'compiler_limits': {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1 << 20},
        'c_compiler_limits': {'wall_seconds': 20, 'cpu_seconds_per_compiler_process': 10,
                              'maximum_file_bytes': 1 << 20, 'new_development_frontend': True},
        'python': {**python_record, 'version': [3, 12, 14]},
        'source_actual_commit': '5f30676148b332fd8c1f01324a145e041e4582c0',
        'pump_static_commit': '5e7bd957db4f950c0c9583b08d31e16bead036f3',
        'compiler_capsule_commit': 'cf49fc44665d89f239f6cf6b63149d1fd1d61f27',
        'compiler_origin_root': str(OLD),
        'compiler': previous['compiler'], 'compiler_helpers': previous['compiler_helpers'],
        'current_compiler_capsule': previous['current_compiler_capsule'],
        'current_compiler_originals': previous['current_compiler_originals'],
        'lifetime_source': hia, 'source_files': source_files, 'source_directories': sorted(source_directories),
        'control_files': controls, 'asset_files': assets, 'external_files': [external[k] for k in sorted(external)],
        'system_manifest': {'path': 'SYSTEM-INPUTS.json', 'bytes': system_record['bytes'],
                            'sha256': system_record['sha256']},
        'c_toolchain': {'gcc': command[0], 'include_search': includes}, 'c_command': command,
        'c_required_exports': ['hia_cli_json_leaf_layout', 'hia_cli_json_leaf_init', 'hia_cli_json_leaf_views',
            'hia_cli_json_leaf', 'hia_cli_json_capture_external', 'hia_cli_json_raise_pending',
            'hia_cli_json_transfer_closed_error', 'hia_cli_json_bind_runtime_312',
            'hia_cli_json_leaf_in_generator', 'hia_cli_json_py312_lifetime_run',
            'hia_cli_json_bind_runtime_312_control'],
        'runtime_ids': list(literals['RUNTIME_IDS']), 'lifetime_ids': list(literals['LIFETIME_IDS']),
        'raw_leaf_only_ids': list(literals['RAW_LEAF_ONLY_IDS']),
        'expected_lifetime_HIA_returns': list(literals['EXPECTED_HIA_RETURNS']),
        'expected_C_pump_calls_including_refusals': list(literals['EXPECTED_C_PUMP_CALLS']),
        'expected_total_HIA_returns': sum(literals['EXPECTED_HIA_RETURNS']),
        'expected_total_C_pump_calls_including_refusals': sum(literals['EXPECTED_C_PUMP_CALLS']),
        'expected_counts_are_unexecuted': True,
        'source_scope': 'Isolated 177 source-qualified files plus r4d/r4e source overlays; not a whole product checkout',
        'qualification_scope': 'Finite CPython3.12 C/runtime/lifetime development using existing v89 B3 only',
        'current_v92_matching_claimed': False, 'fresh_cold': False,
        'activation_CALL_SEND_UNPACK_monitoring_closed': False,
        'unexecuted_scopes': list(literals['UNEXECUTED_SCOPES']),
        'preserved_original17_and46': json.loads((Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e') / 'PREEXEC.json').read_bytes())['preserved_not_run'],
    }
    policy_record = create(ROOT / 'POLICY.json', policy)
    request = {'schema': 'hia.cli-json.C-runtime-lifetime-request.v1', 'operation_key': policy['operation_key'],
        'operation_root': str(ACTUAL), 'policy_path': 'POLICY.json', 'policy_sha256': policy_record['sha256'],
        'qualification_seconds': 180, 'cleanup_seconds': 3, 'status': 'FROZEN_NOT_EXECUTED',
        'runtime_case_count': 8, 'lifetime_case_count': 10, 'expected_HIA_returns': 48,
        'expected_C_pump_calls_including_refusals': 11}
    require(policy['expected_total_HIA_returns'] == 48
            and policy['expected_total_C_pump_calls_including_refusals'] == 11,
            'fixed unexecuted finite population differs')
    request_record = create(ROOT / 'REQUEST.json', request)
    preexec = {'schema': 'hia.cli-json.C-runtime-lifetime-preexec.v1', 'status': 'FROZEN_NOT_EXECUTED',
        'command': [str(PYTHON), '-I', '-S', '-B', str(CONTROL / 'launch.py'),
                    '--request', str(ROOT / 'REQUEST.json'), '--sha256', request_record['sha256']],
        'cwd': str(ROOT), 'environment': {'PATH': '', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
        'request': request_record, 'policy': policy_record, 'source_files': len(source_files),
        'source_bytes': sum(row['bytes'] for row in source_files),
        'system_files': len(system['files']), 'system_bytes': sum(row['bytes'] for row in system['files']),
        'current_compiler_original_files': 62, 'current_compiler_other_inputs': len(external) - 62,
        'source_and_control_AST_parses_only': len(parsed), 'C_frontend_executed': False,
        'native_executed': False, 'runtime_symbol_admission_executed': False,
        'finite_case_bodies_executed': False, 'original17_executed': False, 'original46_executed': False,
        'unexecuted_scopes': policy['unexecuted_scopes'],
        'all_compilation_and_finite_children_inside_one_180_plus_3_owner': True,
        'root_review_required_before_unique_invocation': True}
    create(ROOT / 'PREEXEC.json', preexec)
    create(ROOT / 'proof/AST-ONLY.json', {'status': 'PYTHON_SYNTAX_ONLY_PASS', 'files': parsed,
        'product_imports': False, 'source_generation': False, 'C_frontend': False,
        'runtime_admission': False, 'native_execution': False})
    print(json.dumps({key: preexec[key] for key in ('status', 'source_files', 'source_bytes', 'system_files',
        'system_bytes', 'current_compiler_original_files', 'source_and_control_AST_parses_only')}))


if __name__ == '__main__':
    main()
