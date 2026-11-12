"""Materialize a NEW source-only request; never run its worker or an owner.

The closed r4b1 source inputs are copied and the explicit r4c sources overlaid.
Two new HIA authoring components and three fixed original code metadata
packets are requested under the unchanged 180/3 owner. This command only
copies, hashes and parses source. It does not import product code, compile C,
generate HIA, construct generators, run JSON, or resume an old request.
"""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import json
import os
import stat

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1')
OLD = ROOT / 'source-authoring-r4b1'
IMPLEMENTATION = ROOT / 'implementation-r4c'
OUTPUT = Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e')
ACTUAL_COMMIT = '564f16a2b6dcb0bd22347a13ae7b5a4574afbd4f'
COMPONENTS = (('py312_body', 'tools.generate_hia_cli_json_py312_body'),
              ('py312_lifetime', 'tools.generate_hia_cli_json_py312_lifetime'))
PACKET_NAMES = ('_iterencode_list', '_iterencode_dict', '_iterencode')
ENCODER = 'reference/cpython-v3.12.14/encoder.py'


def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def identity(item):
    return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def read(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('regular single-link materialization input required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('materialization descriptor differs')
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b''.join(chunks)
        if len(raw) != before.st_size or identity(os.fstat(fd)) != identity(before):
            raise ValueError('materialization source changed')
    finally:
        os.close(fd)
    if identity(path.lstat()) != identity(before):
        raise ValueError('materialization source name changed')
    return raw


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise OSError('short materialization write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    if read(path) != raw:
        raise ValueError('new isolated materialization readback differs')


def worker_source(original):
    text = original.decode()
    before = ast.parse(text)
    old_components = "COMPONENTS = (('scalar', 'tools.generate_hia_cli_json_scalar'), ('py312_chunks', 'tools.generate_hia_cli_json_py312_chunks'))"
    if text.count(old_components) != 1:
        raise ValueError('original worker component declaration differs')
    text = text.replace(old_components, 'COMPONENTS = ' + repr(COMPONENTS) + '\nPACKET_NAMES = ' + repr(PACKET_NAMES))
    text = text.replace('source-authoring.r4b.v1', 'source-authoring.r4c.v1')
    text = text.replace('source-authoring.request.r4b.v1', 'source-authoring.request.r4c.v1')
    text = text.replace('TWO_NEW_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN',
                        'TWO_HIA_AND_THREE_CODE_PACKETS_PASS_PENDING_OUTER_GUARDIAN')
    needle = "    source = Path(config['source_root'])\n"
    addition = """    if config['packet_names'] != list(PACKET_NAMES):
        raise ValueError('three original generator code names differ')
    if config['encoder_source'] != 'reference/cpython-v3.12.14/encoder.py':
        raise ValueError('fixed original encoder source path differs')
"""
    if text.count(needle) != 1:
        raise ValueError('source path declaration differs')
    text = text.replace(needle, addition + needle)
    needle = '        actual_modules = {}\n'
    addition = """        # Source metadata authoring only: compile the retained encoder text
        # to code objects, without executing the module or a generator body.
        # Visit all three fixed code names even if one packet is refused.
        report['packet_authoring'] = {'status': 'HOLD', 'exact_names': list(PACKET_NAMES)}
        try:
            packet_module = importlib.import_module('tools.prepare_hia_cli_json_py312_packets')
            packet_output = output / 'packets'
            packet_report = packet_module.author(
                source / config['encoder_source'],
                config['source_pins'][config['encoder_source']]['sha256'], packet_output)
            packet_raw_record, packet_raw = file_record(packet_output / 'REPORT.json')
            if json.loads(packet_raw) != packet_report:
                raise ValueError('packet authoring returned/durable report differs')
            retained = {}
            for path in sorted(packet_output.iterdir()):
                retained[path.name] = file_record(path)[0]
            report['packet_authoring'].update(report=packet_raw_record, retained=retained,
                actual_names=[row['name'] for row in packet_report['code_objects']],
                source=packet_report['source'], generator_bodies_executed=False)
            if (packet_report['status'] != 'THREE_SOURCE_PACKETS_AUTHORED'
                    or packet_report['exact_names'] != list(PACKET_NAMES)
                    or [row['name'] for row in packet_report['code_objects']] != list(PACKET_NAMES)
                    or any(row['status'] != 'SOURCE_PACKET_AUTHORED_NOT_RUNTIME_ADMITTED'
                           for row in packet_report['code_objects'])
                    or len(packet_report['outputs']) != 6
                    or packet_report['source'] != config['source_pins'][config['encoder_source']]
                    or packet_report['generator_bodies_executed'] is not False
                    or packet_report['native_executed'] is not False
                    or packet_report['runtime_code_objects_admitted'] is not False
                    or packet_report['json_values_encoded'] != 0):
                raise ValueError('three source packet denominator or scope differs')
            for record in packet_report['outputs']:
                actual, raw = file_record(packet_output / record['path'])
                if (actual['sha256'], actual['bytes']) != (record['sha256'], record['bytes']):
                    raise ValueError('actual packet bytes differ')
            report['packet_authoring']['status'] = 'THREE_SOURCE_PACKETS_AUTHORED'
        except BaseException as error:
            report['packet_authoring']['error'] = {'type': type(error).__name__, 'message': str(error)}
            report['packet_authoring']['traceback'] = create(output / 'packets.error.txt', traceback.format_exc().encode())
"""
    if text.count(needle) != 1:
        raise ValueError('original module observation anchor differs')
    text = text.replace(needle, addition + needle)
    needle = "        report['status'] = 'TWO_HIA_AND_THREE_CODE_PACKETS_PASS_PENDING_OUTER_GUARDIAN'\n"
    text = text.replace(needle, "        if report['packet_authoring']['status'] != 'THREE_SOURCE_PACKETS_AUTHORED':\n            raise ValueError('one or more original source code packets refused')\n" + needle)
    text = text.replace('Each of two new fixed authoring modules is visited once in declared order, even',
                        'Two HIA modules and three original code metadata packets are authored.\nEach HIA module is visited once in declared order, even')
    after = ast.parse(text)
    unchanged = []
    for node in before.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != 'main':
            other = next(n for n in after.body if isinstance(n, type(node)) and n.name == node.name)
            if ast.dump(node, include_attributes=False) != ast.dump(other, include_attributes=False):
                raise ValueError('old worker helper changed: ' + node.name)
            unchanged.append(node.name)
    old_limits = next(n.value for n in before.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'LIMITS' for t in n.targets))
    new_limits = next(n.value for n in after.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'LIMITS' for t in n.targets))
    if ast.dump(old_limits) != ast.dump(new_limits):
        raise ValueError('original nine caps changed')
    return text.encode(), unchanged


def main():
    old_config_raw = read(OLD / 'control/CONFIG.json')
    old_config = json.loads(old_config_raw)
    old_preexec = json.loads(read(OLD / 'PREEXEC.json'))
    python = Path(old_preexec['python']['path'])
    if pin(read(python)) != {key: old_preexec['python'][key] for key in ('bytes', 'sha256', 'git_blob')}:
        raise ValueError('original source-only Python physical bytes changed')
    if len(old_config['components']) != 2 or len(old_config['original_cli_ids']) != 17 or len(old_config['trace_plan_ids']) != 46:
        raise ValueError('closed r4b1 denominators differ')
    if OUTPUT.exists():
        raise ValueError('new source request root already exists; do not replay')
    old_names = {path.relative_to(OLD / 'source').as_posix()
                 for path in (OLD / 'source').rglob('*') if path.is_file()}
    if old_names != set(old_config['source_pins']) or len(old_names) != 167:
        raise ValueError('closed source namespace differs')
    overlays = {path.relative_to(IMPLEMENTATION / 'inputs').as_posix(): read(path)
                for path in sorted((IMPLEMENTATION / 'inputs').rglob('*')) if path.is_file()}
    if len(overlays) != 12:
        raise ValueError('r4c implementation overlay count changed')
    encoder = read(ROOT / ENCODER)
    before, new_pins, changed, added = {}, {}, [], []
    os.mkdir(OUTPUT, 0o700)
    source = OUTPUT / 'source'
    os.mkdir(source, 0o700)
    for name in sorted(old_names):
        original = read(OLD / 'source' / name)
        if pin(original) != old_config['source_pins'][name]:
            raise ValueError('closed r4b1 source bytes differ: ' + name)
        before[name] = pin(original)
        raw = overlays.pop(name, original)
        if raw != original:
            changed.append(name)
        create(source / name, raw)
        new_pins[name] = pin(raw)
    for name, raw in sorted(overlays.items()):
        added.append(name)
        create(source / name, raw)
        new_pins[name] = pin(raw)
    if ENCODER in new_pins:
        raise ValueError('packet reference source already present in old namespace')
    added.append(ENCODER)
    create(source / ENCODER, encoder)
    new_pins[ENCODER] = pin(encoder)
    parsed, embedded = [], []
    for name in sorted(new_pins):
        if name.endswith('.py'):
            ast.parse(read(source / name), filename=name)
            parsed.append(name)
    for label, module in COMPONENTS:
        name = module.replace('.', '/') + '.py'
        syntax = ast.parse(read(source / name), filename=name)
        value = next(node.value.value for node in syntax.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'SOURCE' for target in node.targets))
        authored = ast.parse(value, filename=name + ':SOURCE')
        unsupported = [type(node.op).__name__ for node in ast.walk(authored)
                       if isinstance(node, ast.BinOp) and not isinstance(node.op,
                            (ast.Add, ast.Sub, ast.Mult, ast.BitAnd, ast.BitOr,
                             ast.BitXor, ast.LShift, ast.RShift))]
        if unsupported:
            raise ValueError('unsupported embedded BinOp: ' + repr(unsupported))
        embedded.append({'name': name, 'label': label, 'source': pin(value.encode()),
                         'functions_before_literals': len(authored.body), 'unsupported_binops': []})
    controls = OUTPUT / 'control'
    os.mkdir(controls, 0o700)
    old_worker = read(OLD / 'control/source_authoring_worker.py')
    new_worker, helpers = worker_source(old_worker)
    create(controls / 'source_authoring_worker.py', new_worker)
    for name in ('guardian.py', 'process_owner_impl.py'):
        create(controls / name, read(OLD / 'control' / name))
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        create(OUTPUT / name, read(OLD / name))
    config = dict(old_config)
    config.update(schema='hia.cli-json.source-authoring.request.r4c.v1',
                  components=[list(row) for row in COMPONENTS], source_root=str(source),
                  source_pins=new_pins, source_revision='implementation-r4c',
                  packet_names=list(PACKET_NAMES), encoder_source=ENCODER,
                  previous_closed_source_commit=ACTUAL_COMMIT)
    config.pop('previous_source_failure_commit', None)
    create(controls / 'CONFIG.json', wire(config))
    identities = {str(python): old_preexec['python']['sha256']}
    for path in sorted(source.rglob('*')):
        if path.is_file():
            identities[str(path)] = sha256(read(path)).hexdigest()
    for path in sorted(controls.iterdir()):
        identities[str(path)] = sha256(read(path)).hexdigest()
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        identities[str(OUTPUT / name)] = sha256(read(OUTPUT / name)).hexdigest()
    guardian = OUTPUT / 'guardian'
    os.mkdir(guardian, 0o700)
    request = json.loads(read(OLD / 'guardian/REQUEST.json'))
    request.update(command=[str(python), '-I', '-S', '-B', str(controls / 'source_authoring_worker.py'),
                            str(controls / 'CONFIG.json'), str(OUTPUT / 'actual')],
                   cwd=str(source), source_identities=identities)
    if request['controller_seconds'] != 180 or old_preexec['cleanup_seconds'] != 3:
        raise ValueError('source-only owner budget changed')
    request_raw = wire(request)
    create(guardian / 'REQUEST.json', request_raw)
    preexec = dict(old_preexec)
    preexec.update(schema='hia.cli-json.r4c.source-only.preexec.v1', status='FROZEN_NOT_EXECUTED',
                   command=[str(python), '-I', '-S', '-B', str(controls / 'guardian.py'),
                            '--config', str(guardian / 'REQUEST.json'), '--config-sha256', sha256(request_raw).hexdigest(),
                            '--implementation', str(controls / 'process_owner_impl.py')],
                   cwd=str(source), request=dict(path=str(guardian / 'REQUEST.json'), **pin(request_raw)),
                   source_files=len(new_pins), source_bytes=sum(row['bytes'] for row in new_pins.values()),
                   source_origin='Closed 167 r4b1 input files plus exact isolated r4c overlays and the retained original encoder text; not a whole-repository source identity.',
                   components=[list(row) for row in COMPONENTS],
                   packet_names=list(PACKET_NAMES), packet_count=3,
                   previous_closed_source_commit=ACTUAL_COMMIT,
                   original_request_replayed=False,
                   source_only=['syntax', 'two new HIA documents', 'Core round trip',
                                'nine original structural caps', 'three original encoder code metadata packets without module execution'],
                   source_overlay_files={p.relative_to(IMPLEMENTATION / 'inputs').as_posix(): pin(read(p))
                                         for p in sorted((IMPLEMENTATION / 'inputs').rglob('*')) if p.is_file()},
                   expected_actual_root=str(OUTPUT / 'actual'),
                   expected_worker_status='TWO_HIA_AND_THREE_CODE_PACKETS_PASS_PENDING_OUTER_GUARDIAN',
                   all_input_count=len(identities))
    preexec.pop('previous_source_failure_commit', None)
    preexec['limits_exclusions'] = [
        'Line count is diagnostic; the actual compiler line gate is not executed.',
        'No C parsing, C compilation, native image load, private runtime admission, CALL/frame behavior or 17/46 execution.',
        'Previously authored six HIA components are dependency bytes only; previous results are not re-executed or inherited.',
        'Three packet outputs contain code metadata; original modules/generator bodies do not execute and runtime code objects are not admitted.',
        'Ports 240-244, complete C driver/recursion/monitoring/SEND/raw-stack UNPACK and Python transport scheduling remain open.'
    ]
    create(OUTPUT / 'PREEXEC.json', wire(preexec))
    materialization = {'schema': 'hia.cli-json.r4c.source-request.materialization.v1',
                       'status': 'MATERIALIZED_AST_PARSED_NOT_EXECUTED',
                       'before': before, 'after': new_pins,
                       'changed_source_paths': changed, 'added_source_paths': sorted(added),
                       'python_ast_parsed': parsed, 'embedded_authoring_ast_parsed': embedded,
                       'old_worker': pin(old_worker), 'new_worker': pin(new_worker),
                       'unchanged_worker_helpers_ast': helpers, 'original_nine_caps_unchanged': True,
                       'original_two_owner_files_unchanged': True,
                       'configuration': pin(read(controls / 'CONFIG.json')), 'request': pin(request_raw),
                       'input_denominator': len(identities), 'components': [list(row) for row in COMPONENTS],
                       'packet_names': list(PACKET_NAMES), 'original_17_plan_count': 17, 'original_46_plan_count': 46,
                       'owner_seconds': 180, 'cleanup_seconds': 3,
                       'actual_output_exists': (OUTPUT / 'actual').exists(),
                       'owner_or_generation_or_product_executed': False}
    # Finally re-read every original source; this materializer cannot alter
    # any previous request or use an old result as a newly executed output.
    for name, old_pin in before.items():
        if pin(read(OLD / 'source' / name)) != old_pin:
            raise ValueError('old source changed during materialization')
    if read(OLD / 'control/CONFIG.json') != old_config_raw:
        raise ValueError('old configuration changed')
    create(OUTPUT / 'MATERIALIZATION.json', wire(materialization))
    print(json.dumps({'root': str(OUTPUT), 'source_files': len(new_pins),
                      'source_bytes': preexec['source_bytes'], 'input_count': len(identities),
                      'source_changed': changed, 'source_added': sorted(added),
                      'request': pin(request_raw), 'preexec': pin(read(OUTPUT / 'PREEXEC.json')),
                      'source_or_owner_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
