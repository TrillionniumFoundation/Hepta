"""Create the bounded, reviewable source-only request without running it."""
from __future__ import annotations

import ast
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import sys


HERE = Path(__file__).absolute().parent
PROJECT = HERE.parent
REPOSITORY = PROJECT.parent / 'combined-native-v87-r1'
DESTINATION = PROJECT / 'source-authoring-r1'


def wire(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)
    if path.read_bytes() != raw:
        raise ValueError('request creation readback differs')
    return pin(raw)


def main():
    os.mkdir(DESTINATION, 0o700)
    source = DESTINATION / 'source'
    os.mkdir(source, 0o700)
    overlay = {path.relative_to(HERE / 'inputs').as_posix(): path.read_bytes()
               for path in (HERE / 'inputs').rglob('*') if path.is_file()}
    overlay['tools/generate_hia_cli_json_text.py'] = (PROJECT / 'inputs/tools/generate_hia_cli_json_text.py').read_bytes()
    selected, pending, derivation = {}, list(overlay), {}

    def module_file(name):
        parts = name.split('.')
        for candidate in ('/'.join(parts) + '.py', '/'.join(parts) + '/__init__.py'):
            if candidate in overlay or (REPOSITORY / candidate).is_file():
                return candidate
        return None

    while pending:
        name = pending.pop()
        if name in selected:
            continue
        raw = overlay.get(name)
        origin = 'isolated-r3-overlay'
        if raw is None:
            raw = (REPOSITORY / name).read_bytes()
            origin = 'actual-readonly-repository-file'
        selected[name] = raw
        derivation[name] = {'origin': origin, **pin(raw)}
        package_parts = name.split('/')[:-1]
        for count in range(1, len(package_parts) + 1):
            init = '/'.join(package_parts[:count]) + '/__init__.py'
            if init in overlay or (REPOSITORY / init).is_file():
                pending.append(init)
        if not name.endswith('.py'):
            continue
        tree = ast.parse(raw, filename=name)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [row.name for row in node.names]
            elif isinstance(node, ast.ImportFrom):
                package = package_parts[:len(package_parts) - node.level + 1] if node.level else []
                prefix = '.'.join(package + (node.module.split('.') if node.module else []))
                names = [prefix] + [prefix + '.' + row.name for row in node.names if row.name != '*']
            for imported in names:
                if imported.split('.')[0] in ('hepta', 'tools'):
                    path = module_file(imported)
                    if path is not None:
                        pending.append(path)
    source_pins = {name: create(source / name, raw) for name, raw in sorted(selected.items())}
    controls = DESTINATION / 'control'
    os.mkdir(controls, 0o700)
    worker = controls / 'source_authoring_worker.py'
    create(worker, (HERE / worker.name).read_bytes())
    reference = PROJECT.parent / 'cold-v81-source-validation-r2/controls'
    for name in ('guardian.py', 'process_owner_impl.py'):
        create(controls / name, (reference / name).read_bytes())
    source_audit = json.loads((PROJECT / 'SOURCE-AUDIT.json').read_bytes())
    trace_plan = json.loads((PROJECT / 'TRACE-PLAN.json').read_bytes())
    ids = source_audit['original_cli_test_method_ids_in_source_order']
    traces = [case['id'] for group in trace_plan['groups'] for case in group['cases']]
    if len(ids) != 17 or len(set(ids)) != 17 or len(traces) != 46 or len(set(traces)) != 46:
        raise ValueError('original caller/trace plan denominator differs')
    limits = {
        'source_bytes': 1 << 20, 'functions': 128, 'blocks_per_function': 256,
        'blocks_total': 1536, 'parameters_or_arguments': 16,
        'ssa_names_per_function': 2048, 'instruction_results': 3,
        'function_results': 3, 'instructions': 8192,
    }
    configuration = {
        'schema': 'hia.cli-json.source-authoring.request.v1',
        'source_root': str(source), 'source_pins': source_pins,
        'components': [['text', 'tools.generate_hia_cli_json_text'],
                       ['sort', 'tools.generate_hia_cli_json_sort'],
                       ['note', 'tools.generate_hia_cli_json_note'],
                       ['cgraph', 'tools.generate_hia_cli_json_cgraph']],
        'limits': limits, 'original_cli_ids': ids, 'trace_plan_ids': traces,
        'native_executed': False, 'caller_execution_requested': False,
        'trace_execution_requested': False,
    }
    config_path = controls / 'CONFIG.json'
    create(config_path, wire(configuration))
    create(DESTINATION / 'SOURCE-DERIVATION.json', wire(derivation))
    create(DESTINATION / 'ORIGINAL-CLI-ID-SOURCE.json', (PROJECT / 'SOURCE-AUDIT.json').read_bytes())
    create(DESTINATION / 'TRACE-PLAN.original.json', (PROJECT / 'TRACE-PLAN.json').read_bytes())
    python = Path(sys.executable).resolve()
    python_pin = pin(python.read_bytes())
    fixed = {str(source / name): item['sha256'] for name, item in source_pins.items()}
    fixed.update({str(path): sha256(path.read_bytes()).hexdigest() for path in controls.iterdir() if path.is_file()})
    fixed[str(python)] = python_pin['sha256']
    request = {
        'schema': 'hia-external-guardian-request.v1',
        'controller_seconds': 180, 'cwd': str(source),
        'command': [str(python), '-I', '-S', '-B', str(worker), str(config_path), str(DESTINATION / 'actual-r1')],
        'source_identities': fixed, 'expected_qualification': None,
    }
    guard = DESTINATION / 'guardian-r1'
    os.mkdir(guard, 0o700)
    request_path = guard / 'REQUEST.json'
    request_pin = create(request_path, wire(request))
    command = [str(python), '-I', '-S', '-B', str(controls / 'guardian.py'),
               '--config', str(request_path), '--config-sha256', request_pin['sha256'],
               '--implementation', str(controls / 'process_owner_impl.py')]
    preexec = {
        'schema': 'hia.cli-json.source-authoring.preexec.v1', 'status': 'FROZEN_NOT_EXECUTED',
        'command': command, 'cwd': str(source),
        'environment': {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
        'new_source_only_owner_seconds': 180, 'cleanup_seconds': 3,
        'python': {'path': str(python), 'version': sys.version, **python_pin},
        'request': {'path': str(request_path), **request_pin},
        'worker': {'path': str(worker), **pin(worker.read_bytes())},
        'source_files': len(source_pins), 'source_bytes': sum(v['bytes'] for v in source_pins.values()),
        'products_executed': False, 'C_compilation_requested': False,
        'source_only': ['syntax', 'actual authoring', 'assembly', 'public Core round trip', 'listed structural caps'],
        'preserved_not_run': {'original_cli_ids': ids, 'trace_plan_ids': traces},
        'limits_exclusions': ['No native output-size proof, actual compile or product equivalence claim.'],
        'source_origin': 'Exact per-file copied read-only repository closure plus isolated source overlays; not a Git checkout or new product head.',
        'old_unknown_operations': 'No query, reconciliation or replay.'
    }
    create(DESTINATION / 'PREEXEC.json', wire(preexec))
    print(json.dumps({'destination': str(DESTINATION), 'source_files': len(source_pins),
                      'source_bytes': preexec['source_bytes'], 'request_sha256': request_pin['sha256'],
                      'status': preexec['status']}, sort_keys=True))


if __name__ == '__main__':
    main()
