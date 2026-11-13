"""Frozen source-only CLI JSON authoring; no native image or CPython DSO load.

Each of seven fixed authoring modules is visited once in declared order, even
if another module fails.  Actual documents/assembly and exception originals
are retained.  This is not the 17 original CLI callers or the 46 trace plan.
The external frozen guardian supplies the new 180-second/3-second owner.
"""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import importlib
import json
import mmap
import os
from pathlib import Path
import stat
import socket
import subprocess
import sys
import time
import traceback


SCHEMA = 'hia.cli-json.call-send-source-seven.r2b.v1'
COMPONENTS = (('body', 'tools.generate_hia_cli_json_py312_body'), ('unpack', 'tools.generate_hia_cli_json_py312_unpack'), ('call_dispatch', 'tools.generate_hia_cli_json_py312_call_dispatch'), ('call', 'tools.generate_hia_cli_json_py312_call'), ('call_fast', 'tools.generate_hia_cli_json_py312_call_fast'), ('call_prologue', 'tools.generate_hia_cli_json_py312_call_prologue'), ('send', 'tools.generate_hia_cli_json_py312_send'))

LIMITS = {
    'source_bytes': 1 << 20, 'functions': 128,
    'blocks_per_function': 256, 'blocks_total': 1536,
    'parameters_or_arguments': 16, 'ssa_names_per_function': 2048,
    'instruction_results': 3, 'function_results': 3,
    'instructions': 8192,
}


def identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns]


def file_record(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('fixed source must be regular and single-linked: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('fixed source descriptor differs: ' + str(path))
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b''.join(chunks)
        if len(raw) != before.st_size or identity(os.fstat(fd)) != identity(before):
            raise ValueError('fixed source changed during read: ' + str(path))
    finally:
        os.close(fd)
    if identity(path.lstat()) != identity(before):
        raise ValueError('fixed source name changed: ' + str(path))
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': identity(before)}, raw


def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def create(path, raw):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            n = os.write(fd, raw[offset:])
            if n <= 0:
                raise OSError('short source-evidence write')
            offset += n
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        if b''.join(chunks) != raw:
            raise ValueError('source evidence readback differs')
    finally:
        os.close(fd)
    record, retained = file_record(path)
    if retained != raw:
        raise ValueError('source evidence named readback differs')
    return record


def snapshot(root, pins, fixed_identities):
    actual = sorted(path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file())
    if actual != sorted(pins):
        raise ValueError('source-only physical leaf set differs')
    answer = {}
    for name, expected in pins.items():
        current, raw = file_record(root / name)
        if (current['sha256'], current['bytes']) != (expected['sha256'], expected['bytes']):
            raise ValueError('source-only fixed bytes differ: ' + name)
        if current['identity'] != fixed_identities[name]:
            raise ValueError('source-only frozen physical identity differs: ' + name)
        answer[name] = current
    return answer


def measure(document, assembly):
    functions = document['functions']
    rows = []
    for function in functions:
        names = {entry['name'] for entry in function['params']}
        blocks = function['blocks']
        max_params = len(function['params'])
        max_args = 0
        max_out = 0
        ops = 0
        for block in blocks:
            names.update(entry['name'] for entry in block['params'])
            max_params = max(max_params, len(block['params']))
            for op in block['ops']:
                names.update(entry['name'] for entry in op['out'])
                max_args = max(max_args, len(op['args']))
                max_out = max(max_out, len(op['out']))
                ops += 1
            term = block['term']
            if term['op'] == 'jump':
                max_args = max(max_args, len(term['args']))
            elif term['op'] == 'branch':
                max_args = max(max_args, len(term['then']['args']), len(term['else']['args']))
            elif term['op'] == 'ret':
                max_args = max(max_args, len(term['values']))
        rows.append({'name': function['name'], 'blocks': len(blocks), 'operations': ops,
                     'ssa_names': len(names), 'parameters': max_params, 'arguments': max_args,
                     'instruction_results': max_out, 'function_results': len(function['returns'])})
    observed = {
        'source_bytes': len(assembly), 'functions': len(functions),
        'blocks_per_function': max(row['blocks'] for row in rows),
        'blocks_total': sum(row['blocks'] for row in rows),
        'parameters_or_arguments': max(max(row['parameters'], row['arguments']) for row in rows),
        'ssa_names_per_function': max(row['ssa_names'] for row in rows),
        'instruction_results': max(row['instruction_results'] for row in rows),
        'function_results': max(row['function_results'] for row in rows),
        'instructions': sum(row['operations'] for row in rows),
    }
    return {'actual': observed, 'limits': LIMITS, 'functions': rows,
            'source_lines_diagnostic': len(assembly.splitlines()),
            'compiler_line_gate_executed': False,
            'within_limits': all(value <= LIMITS[key] for key, value in observed.items())}


def main():
    configuration = Path(sys.argv[1]).absolute()
    output = Path(sys.argv[2]).absolute()
    configuration_record, configuration_raw = file_record(configuration)
    config = json.loads(configuration_raw)
    if config['schema'] != 'hia.cli-json.call-send-source-seven.request.r2b.v1':
        raise ValueError('source-only configuration schema differs')
    if config['components'] != [list(row) for row in COMPONENTS] or config['limits'] != LIMITS:
        raise ValueError('source-only fixed denominator or original caps differ')
    source = Path(config['source_root'])
    if not source.is_absolute() or output.exists():
        raise ValueError('new absolute source/output roots required')
    os.mkdir(output, 0o700)
    report = {'schema': SCHEMA, 'status': 'HOLD', 'configuration': configuration_record,
              'components': [], 'errors': [], 'source_before': None, 'source_after': None,
              'native_executed': None, 'product_callers_executed': None,
              'forbidden_attempts': [],
              'effect_guard': {'installed_before_project_import': False,
                               'scope_verified_without_attempts': False},
              'original_cli_ids': config['original_cli_ids'],
              'trace_plan_ids': config['trace_plan_ids'],
              'counts_are_plan_only': True,
              'started_ns': time.monotonic_ns()}
    original_sys_path = list(sys.path)
    before = None
    # The stdlib modules above are loaded before this hook, including ctypes'
    # normal Python-runtime handle. No repository module has been imported.
    # Keep every attempted forbidden entry, even if authored code catches it.
    forbidden_attempts = report['forbidden_attempts']
    record_attempt = forbidden_attempts.append

    def deny(label):
        def forbidden(*_args, **_kwargs):
            record_attempt(label)
            raise RuntimeError('source-only effect refused: ' + label)
        return forbidden

    def audit(event, _args):
        if event in {
                'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty',
                'os.posix_spawn', 'os.posix_spawnp', 'os.exec', 'pty.spawn',
                'ctypes.dlopen', 'ctypes.dlsym', 'sqlite3.connect', 'mmap.__new__'
        } or event.startswith('socket.'):
            deny('audit:' + event)()

    try:
        runtime_before, _ = file_record(Path(sys.executable).resolve())
        report['runtime_before'] = runtime_before
        if (runtime_before != config['runtime']['file']
                or list(sys.version_info[:3]) != config['runtime']['version_info']
                or sys.version != config['runtime']['version']
                or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != config['runtime']['boot_id']):
            raise ValueError('new source-only Python runtime differs')
        before = snapshot(source, config['source_pins'], config['source_identity9'])
        report['source_before'] = create(output / 'source.before.json', wire(before))
        # Syntax validation never imports a raw-object adapter or leaf DSO.
        for name in sorted(config['source_pins']):
            if name.endswith('.py'):
                ast.parse((source / name).read_bytes(), filename=name)
        # Adapted from the actual Source8 guard (239120db...), not an
        # assertion inferred from constant report flags or an empty PATH.
        sys.addaudithook(audit)
        subprocess.Popen = deny('subprocess.Popen')
        os.system = deny('os.system')
        ctypes.CDLL = deny('ctypes.CDLL')
        ctypes.PyDLL = deny('ctypes.PyDLL')
        socket.create_connection = deny('socket.create_connection')
        mmap.mmap = deny('mmap.mmap')
        report['effect_guard']['installed_before_project_import'] = True
        sys.path.insert(0, str(source))
        from hepta import hia_json_preflight_native as image_module
        image_module.NativeHiaJsonImage.__init__ = deny('NativeHiaJsonImage.__init__')
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        for label, module_name in COMPONENTS:
            row = {'name': label, 'module': module_name, 'status': 'HOLD',
                   'started_ns': time.monotonic_ns(), 'error': None}
            report['components'].append(row)
            try:
                module = importlib.import_module(module_name)
                authored = module.source_program()
                row['authoring_source'] = create(output / (label + '.authoring.py.txt'), authored.encode())
                document = module.document()
                row['document'] = create(output / (label + '.document.json'), wire(document))
                assembly = render_assembly(document).encode()
                row['assembly'] = create(output / (label + '.hiaasm'), assembly)
                verified = assemble_program(assembly)
                canonical = verified.as_dict()
                row['verified_document'] = create(output / (label + '.verified.json'), wire(canonical))
                if render_assembly(canonical).encode() != assembly:
                    raise ValueError('Core assembly round trip differs')
                measurement = measure(canonical, assembly)
                row['caps'] = create(output / (label + '.caps.json'), wire(measurement))
                if not measurement['within_limits']:
                    raise ValueError('original compiler caps exceeded')
                row['status'] = 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE'
            except BaseException as error:
                row['error'] = {'type': type(error).__name__, 'message': str(error)}
                row['traceback'] = create(output / (label + '.error.txt'), traceback.format_exc().encode())
            finally:
                row['elapsed_ns'] = time.monotonic_ns() - row['started_ns']
        actual_modules = {}
        for name, module in tuple(sys.modules.items()):
            path = getattr(module, '__file__', None)
            if type(path) is str:
                try:
                    relative = Path(path).absolute().relative_to(source).as_posix()
                except ValueError:
                    continue
                if relative not in config['source_pins']:
                    raise ValueError('unbound repository module imported: ' + relative)
                actual_modules[name] = relative
        report['actual_repository_modules'] = actual_modules
        if len(report['components']) != 7 or any(row['status'] != 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' for row in report['components']):
            raise ValueError('one or more source-only components refused')
        if (report['effect_guard']['installed_before_project_import'] is not True
                or forbidden_attempts):
            raise ValueError('source-only effect boundary was not preserved')
        report['status'] = 'SEVEN_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
        report['error_traceback'] = create(output / 'error.txt', traceback.format_exc().encode())
    finally:
        sys.path[:] = original_sys_path
        try:
            runtime_after, _ = file_record(Path(sys.executable).resolve())
            report['runtime_after'] = runtime_after
            if (runtime_after != config['runtime']['file']
                    or runtime_after != report.get('runtime_before')
                    or list(sys.version_info[:3]) != config['runtime']['version_info']
                    or sys.version != config['runtime']['version']
                    or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != config['runtime']['boot_id']):
                raise ValueError('source-only Python runtime changed')
            after = snapshot(source, config['source_pins'], config['source_identity9'])
            report['source_after'] = create(output / 'source.after.json', wire(after))
            if before != after:
                raise ValueError('source-only input identity changed')
            final_config, final_raw = file_record(configuration)
            if final_config != configuration_record or final_raw != configuration_raw:
                raise ValueError('source-only configuration changed')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['errors'].append({'phase': 'final-inputs', 'type': type(error).__name__, 'message': str(error)})
        guard_proven = (report['effect_guard']['installed_before_project_import'] is True
                        and report['forbidden_attempts'] is forbidden_attempts
                        and not forbidden_attempts)
        report['effect_guard']['scope_verified_without_attempts'] = guard_proven
        report['native_executed'] = False if guard_proven else None
        report['product_callers_executed'] = False if guard_proven else None
        if not guard_proven:
            report['status'] = 'HOLD'
            report['errors'].append({'phase': 'effect-boundary',
                                    'type': 'SourceEffectGuardUnconfirmed',
                                    'message': 'guard absent or forbidden attempts recorded'})
        report['elapsed_ns'] = time.monotonic_ns() - report['started_ns']
        create(output / 'REPORT.json', wire(report))
        print(json.dumps({'schema': SCHEMA, 'status': report['status'], 'output': str(output)}, sort_keys=True), flush=True)
    return 0 if report['status'] == 'SEVEN_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
