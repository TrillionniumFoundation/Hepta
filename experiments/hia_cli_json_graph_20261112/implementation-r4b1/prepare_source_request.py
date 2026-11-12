"""Copy the closed r4b inputs into a fresh two-component source-only request.

This materializer only copies, hashes and parses Python/embedded authoring AST.
It does not import a product, generate HIA, invoke an owner, or run the request.
"""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import json
import os

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1')
OLD = ROOT / 'source-authoring-r4b'
IMPLEMENTATION = ROOT / 'implementation-r4b1'
OUTPUT = ROOT / 'source-authoring-r4b1'
ACTUAL_COMMIT = '60e30e1bd5ad5a7434ea0019767e5c9210e32be7'
SCALAR = 'tools/generate_hia_cli_json_scalar.py'


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
        raise ValueError('new isolated materialization readback differs')


def main():
    old_config = json.loads((OLD / 'control/CONFIG.json').read_bytes())
    old_preexec = json.loads((OLD / 'PREEXEC.json').read_bytes())
    python = Path(old_preexec['python']['path'])
    if pin(python.read_bytes()) != {key: old_preexec['python'][key] for key in ('bytes', 'sha256', 'git_blob')}:
        raise ValueError('exact original Python bytes changed')
    if len(old_config['components']) != 2 or len(old_config['original_cli_ids']) != 17 or len(old_config['trace_plan_ids']) != 46:
        raise ValueError('original source or plan denominator differs')
    if OUTPUT.exists():
        raise ValueError('new request namespace already exists')
    physical = {path.relative_to(OLD / 'source').as_posix() for path in (OLD / 'source').rglob('*') if path.is_file()}
    if physical != set(old_config['source_pins']) or len(physical) != 167:
        raise ValueError('old source namespace differs')
    before = {}
    source = OUTPUT / 'source'
    os.mkdir(OUTPUT, 0o700)
    os.mkdir(source, 0o700)
    changed = []
    for name in sorted(physical):
        original = (OLD / 'source' / name).read_bytes()
        if pin(original) != old_config['source_pins'][name]:
            raise ValueError('old frozen source differs: ' + name)
        before[name] = pin(original)
        overlay = IMPLEMENTATION / 'inputs' / name
        raw = overlay.read_bytes() if overlay.is_file() else original
        if raw != original:
            changed.append(name)
        create(source / name, raw)
    if changed != [SCALAR]:
        raise ValueError('correction changed more than the one scalar source')
    new_pins = {path.relative_to(source).as_posix(): pin(path.read_bytes())
                for path in sorted(source.rglob('*')) if path.is_file()}
    parsed = []
    for name in sorted(new_pins):
        if name.endswith('.py'):
            ast.parse((source / name).read_bytes(), filename=name)
            parsed.append(name)
    embedded = []
    for name in (SCALAR, 'tools/generate_hia_cli_json_py312_chunks.py'):
        module = ast.parse((source / name).read_bytes(), filename=name)
        value = next(node.value.value for node in module.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'SOURCE' for target in node.targets))
        authoring = ast.parse(value, filename=name + ':SOURCE')
        unsupported = [type(node.op).__name__ for node in ast.walk(authoring)
                       if isinstance(node, ast.BinOp)
                       and not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.BitAnd,
                                                    ast.BitOr, ast.BitXor, ast.LShift, ast.RShift))]
        if unsupported:
            raise ValueError('unsupported authoring BinOp remains: ' + repr(unsupported))
        embedded.append({'name': name, 'bytes': len(value.encode()), 'function_count_before_literals': len(authoring.body),
                         'unsupported_binops': unsupported})
    controls = OUTPUT / 'control'
    os.mkdir(controls, 0o700)
    for name in ('source_authoring_worker.py', 'guardian.py', 'process_owner_impl.py'):
        create(controls / name, (OLD / 'control' / name).read_bytes())
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        create(OUTPUT / name, (OLD / name).read_bytes())
    config = dict(old_config)
    config.update(source_root=str(source), source_pins=new_pins,
                  source_revision='implementation-r4b1', previous_source_failure_commit=ACTUAL_COMMIT)
    create(controls / 'CONFIG.json', wire(config))
    identities = {str(python): old_preexec['python']['sha256']}
    for path in sorted(source.rglob('*')):
        if path.is_file():
            identities[str(path)] = sha256(path.read_bytes()).hexdigest()
    for path in sorted(controls.iterdir()):
        identities[str(path)] = sha256(path.read_bytes()).hexdigest()
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        identities[str(OUTPUT / name)] = sha256((OUTPUT / name).read_bytes()).hexdigest()
    if len(identities) != 174:
        raise ValueError('input closure denominator differs')
    guardian = OUTPUT / 'guardian'
    os.mkdir(guardian, 0o700)
    request = json.loads((OLD / 'guardian/REQUEST.json').read_bytes())
    request.update(command=[str(python), '-I', '-S', '-B', str(controls / 'source_authoring_worker.py'),
                            str(controls / 'CONFIG.json'), str(OUTPUT / 'actual')],
                   cwd=str(source), source_identities=identities)
    request_raw = wire(request)
    create(guardian / 'REQUEST.json', request_raw)
    preexec = dict(old_preexec)
    preexec.update(schema='hia.cli-json.r4b1.source-only.preexec.v1', status='FROZEN_NOT_EXECUTED',
                   command=[str(python), '-I', '-S', '-B', str(controls / 'guardian.py'),
                            '--config', str(guardian / 'REQUEST.json'), '--config-sha256', sha256(request_raw).hexdigest(),
                            '--implementation', str(controls / 'process_owner_impl.py')],
                   cwd=str(source), request=dict(path=str(guardian / 'REQUEST.json'), **pin(request_raw)),
                   source_bytes=sum(row['bytes'] for row in new_pins.values()),
                   source_origin='Exact 167 source bytes from closed r4b request with one scalar authoring correction; no whole-repository identity is claimed.',
                   previous_source_failure_commit=ACTUAL_COMMIT,
                   original_request_replayed=False,
                   source_overlay_files={path.relative_to(IMPLEMENTATION / 'inputs').as_posix(): pin(path.read_bytes())
                                         for path in sorted((IMPLEMENTATION / 'inputs').rglob('*')) if path.is_file()})
    create(OUTPUT / 'PREEXEC.json', wire(preexec))
    materialization = {'schema': 'hia.cli-json.r4b1.source-request.materialization.v1',
                       'status': 'MATERIALIZED_AST_PARSED_NOT_EXECUTED',
                       'before': before, 'after': new_pins, 'changed_source_paths': changed,
                       'python_ast_parsed': parsed, 'embedded_authoring_ast_parsed': embedded,
                       'all_three_control_bytes_unchanged': True,
                       'configuration': pin((controls / 'CONFIG.json').read_bytes()),
                       'request': pin(request_raw), 'input_denominator': len(identities),
                       'original_components': old_config['components'], 'original_17_plan_count': 17,
                       'original_46_plan_count': 46, 'owner_seconds': request['controller_seconds'],
                       'cleanup_seconds': old_preexec['cleanup_seconds'],
                       'actual_output_exists': (OUTPUT / 'actual').exists(),
                       'owner_or_generation_or_product_executed': False}
    create(OUTPUT / 'MATERIALIZATION.json', wire(materialization))
    print(json.dumps({'root': str(OUTPUT), 'source_files': len(new_pins), 'source_bytes': preexec['source_bytes'],
                      'source_changed': changed, 'request': pin(request_raw),
                      'preexec': pin((OUTPUT / 'PREEXEC.json').read_bytes()),
                      'source_or_owner_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
