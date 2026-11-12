"""Materialize the frozen two-component source request; never execute it."""
from pathlib import Path
import ast
from hashlib import sha1, sha256
import json
import os
import sys

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1')
IMPLEMENTATION = ROOT / 'implementation-r4b'
OUTPUT = ROOT / 'source-authoring-r4b'
PREVIOUS = ROOT / 'source-authoring-r3'
ACTUAL = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-source4-actual-43264350911-r1/retained/source')
COMPONENTS = [('scalar', 'tools.generate_hia_cli_json_scalar'),
              ('py312_chunks', 'tools.generate_hia_cli_json_py312_chunks')]


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError('materialized source/control readback differs')


def main():
    os.mkdir(OUTPUT, 0o700)
    source = OUTPUT / 'source'
    os.mkdir(source, 0o700)
    before = {}
    old_config = json.loads((PREVIOUS / 'control/CONFIG.json').read_bytes())
    for path in sorted(ACTUAL.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(ACTUAL).as_posix()
        raw = path.read_bytes()
        expected = old_config['source_pins'][name]
        if (len(raw), sha256(raw).hexdigest()) != (expected['bytes'], expected['sha256']):
            raise ValueError('previous actual source differs: ' + name)
        before[name] = pin(raw)
        create(source / name, raw)
    if len(before) != 160 or set(before) != set(old_config['source_pins']):
        raise ValueError('previous actual source denominator differs')
    overlays = {}
    for path in sorted((IMPLEMENTATION / 'inputs').rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(IMPLEMENTATION / 'inputs').as_posix()
        raw = path.read_bytes()
        target = source / name
        if target.exists():
            target.unlink()  # only this newly created isolated copy
        create(target, raw)
        overlays[name] = pin(raw)
    if len(overlays) != 13:
        raise ValueError('frozen implementation overlay denominator differs')
    pins = {path.relative_to(source).as_posix(): pin(path.read_bytes())
            for path in sorted(source.rglob('*')) if path.is_file()}
    for name in pins:
        if name.endswith('.py'):
            ast.parse((source / name).read_bytes(), filename=name)
    controls = OUTPUT / 'control'
    os.mkdir(controls, 0o700)
    original_worker = (PREVIOUS / 'control/source_authoring_worker.py').read_text()
    worker = original_worker.replace('Each of four fixed authoring modules', 'Each of two new fixed authoring modules')
    worker = worker.replace("SCHEMA = 'hia.cli-json.source-authoring.r3.v1'", "SCHEMA = 'hia.cli-json.source-authoring.r4b.v1'")
    start = worker.index('COMPONENTS = (')
    end = worker.index('\nLIMITS =', start)
    worker = worker[:start] + 'COMPONENTS = ' + repr(tuple(COMPONENTS)) + '\n' + worker[end:]
    worker = worker.replace("'hia.cli-json.source-authoring.request.v1'", "'hia.cli-json.source-authoring.request.r4b.v1'")
    worker = worker.replace("'within_limits': all(value <= LIMITS[key] for key, value in observed.items())}",
                            "'source_lines_diagnostic': len(assembly.splitlines()),\n            'compiler_line_gate_executed': False,\n            'within_limits': all(value <= LIMITS[key] for key, value in observed.items())}")
    worker = worker.replace("len(report['components']) != 4", "len(report['components']) != 2")
    worker = worker.replace('FOUR_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN',
                            'TWO_NEW_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN')
    ast.parse(worker)
    create(controls / 'source_authoring_worker.py', worker.encode())
    for name, expected in [('guardian.py', 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'),
                           ('process_owner_impl.py', '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2')]:
        raw = (PREVIOUS / 'control' / name).read_bytes()
        if sha256(raw).hexdigest() != expected:
            raise ValueError('original owner control differs')
        create(controls / name, raw)
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        create(OUTPUT / name, (PREVIOUS / name).read_bytes())
    config = dict(old_config)
    config.update(schema='hia.cli-json.source-authoring.request.r4b.v1',
                  source_root=str(source), source_pins=pins, components=COMPONENTS,
                  source_revision='implementation-r4b', previous_four_components_rerun=False,
                  previous_four_actual_commit='ef2f5971a9032af2afc2c7c805eff10908e81ebf')
    create(controls / 'CONFIG.json', wire(config))
    python = Path(sys.executable).resolve(strict=True)
    python_pin = dict(path=str(python), version=sys.version, **pin(python.read_bytes()))
    identities = {str(python): python_pin['sha256']}
    for path in sorted(source.rglob('*')):
        if path.is_file():
            identities[str(path)] = sha256(path.read_bytes()).hexdigest()
    for path in sorted(controls.iterdir()):
        identities[str(path)] = sha256(path.read_bytes()).hexdigest()
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        identities[str(OUTPUT / name)] = sha256((OUTPUT / name).read_bytes()).hexdigest()
    guardian_root = OUTPUT / 'guardian'
    os.mkdir(guardian_root, 0o700)
    request = {'schema': 'hia-external-guardian-request.v1',
               'command': [str(python), '-I', '-S', '-B', str(controls / 'source_authoring_worker.py'),
                           str(controls / 'CONFIG.json'), str(OUTPUT / 'actual')],
               'controller_seconds': 180, 'cwd': str(source),
               'expected_qualification': None, 'source_identities': identities}
    request_raw = wire(request)
    create(guardian_root / 'REQUEST.json', request_raw)
    preexec = {'schema': 'hia.cli-json.r4b.source-only.preexec.v1', 'status': 'FROZEN_NOT_EXECUTED',
               'command': [str(python), '-I', '-S', '-B', str(controls / 'guardian.py'),
                           '--config', str(guardian_root / 'REQUEST.json'),
                           '--config-sha256', sha256(request_raw).hexdigest(),
                           '--implementation', str(controls / 'process_owner_impl.py')],
               'cwd': str(source), 'environment': {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'},
               'python': python_pin, 'request': dict(path=str(guardian_root / 'REQUEST.json'), **pin(request_raw)),
               'new_source_only_owner_seconds': 180, 'cleanup_seconds': 3,
               'components': COMPONENTS, 'source_files': len(pins),
               'source_bytes': sum(row['bytes'] for row in pins.values()),
               'source_origin': 'Exact copied Source4 actual 160-file closure plus 13 explicitly pinned r4b overlays; not a whole Git checkout.',
               'source_overlay_files': overlays, 'preserved_not_run': {
                   'original_cli_ids': config['original_cli_ids'], 'trace_plan_ids': config['trace_plan_ids']},
               'source_only': ['syntax', 'two new actual authoring modules', 'assembly', 'public Core roundtrip', 'original nine structural caps'],
               'limits_exclusions': ['Line count is diagnostic; the compiler line gate is not executed.',
                   'C is neither parsed nor compiled; private runtime admission and owned CALL/frame mechanisms are not executed.',
                   'Existing four source modules are dependency bytes only and are not re-generated.',
                   'No object input, old caller, trace, native, installation, cold or full qualification runs.'],
               'unknown_operations_touched': False, 'native_executed': False}
    create(OUTPUT / 'PREEXEC.json', wire(preexec))
    derivation = {'schema': 'hia.cli-json.r4b.source-request.materialization.v1',
                  'status': 'MATERIALIZED_AST_PARSED_NOT_EXECUTED',
                  'before_160': before, 'overlays_13': overlays, 'after': pins,
                  'original_worker': pin(original_worker.encode()), 'new_worker': pin(worker.encode()),
                  'guardian_and_owner_wholebytes_unchanged': True,
                  'configuration': pin((controls / 'CONFIG.json').read_bytes()),
                  'request': pin(request_raw), 'original_17_ids': len(config['original_cli_ids']),
                  'original_46_ids': len(config['trace_plan_ids']),
                  'actual_output_exists': (OUTPUT / 'actual').exists(),
                  'guardian_outputs_exist': any((guardian_root / name).exists() for name in ('guardian.json', 'child.stdout.log', 'child.stderr.log'))}
    create(OUTPUT / 'MATERIALIZATION.json', wire(derivation))
    print(json.dumps({'root': str(OUTPUT), 'preexec': pin((OUTPUT / 'PREEXEC.json').read_bytes()),
                      'request': pin(request_raw), 'source_files': len(pins), 'source_bytes': preexec['source_bytes'],
                      'generated': False, 'native': False}, sort_keys=True))


if __name__ == '__main__':
    main()
