"""Freeze a new source-only request; do not import or run the candidate."""
from __future__ import annotations

import ast
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).absolute().parent
PROJECT = HERE.parent
OLD = PROJECT / 'source-authoring-r2'
NEW = PROJECT / 'source-authoring-r3'
SORT = 'tools/generate_hia_cli_json_sort.py'
CONTINUATION = 'tools/hia_cli_json_continuation.py'


def wire(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def stable(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('regular single-link input required: ' + str(path))
    def ident(st):
        return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
                st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if ident(before) != ident(os.fstat(fd)):
            raise ValueError('input changed before open')
        chunks = []
        while True:
            block = os.read(fd, 1 << 16)
            if not block:
                break
            chunks.append(block)
        raw = b''.join(chunks)
        if len(raw) != before.st_size or ident(before) != ident(os.fstat(fd)):
            raise ValueError('input changed during read')
    finally:
        os.close(fd)
    if ident(path.lstat()) != ident(before):
        raise ValueError('input name changed during read')
    return raw


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            if count <= 0:
                raise OSError('short frozen input write')
            at += count
        os.fsync(fd)
    finally:
        os.close(fd)
    if stable(path) != raw:
        raise ValueError('new input readback differs')
    return pin(raw)


def main():
    old_config = json.loads(stable(OLD / 'control/CONFIG.json'))
    old_preexec = json.loads(stable(OLD / 'PREEXEC.json'))
    old_raw = {name: stable(OLD / 'source' / name) for name in (SORT, CONTINUATION)}
    overlays = {name: stable(HERE / 'inputs' / name) for name in old_raw}
    for name, raw in overlays.items():
        ast.parse(raw, filename=name)
    helpers = """# Factored local-slot operations preserve the exact two reads and address
# arithmetic previously emitted at every use. They introduce no cached frame
# pointer, no changed workspace writes and no new foreign observation.
def frame_get(w:mutbuf, offset:u64) -> u64:
    return get(w, get(w, TS_FRAME) + offset)

def frame_put(w:mutbuf, offset:u64, value:u64) -> u64:
    return put(w, get(w, TS_FRAME) + offset, value)

"""
    substitutions = [(
        """            return ast.copy_location(ast.Call(ast.Name('get', ast.Load()),
                [ast.Name('w', ast.Load()), frame_address(self.slots[node.id])], []), node)""",
        """            return ast.copy_location(ast.Call(ast.Name('frame_get', ast.Load()),
                [ast.Name('w', ast.Load()), ast.Constant(self.slots[node.id])], []), node)"""), (
        """        return builder.expr(ast.Call(ast.Name('get', ast.Load()),
            [ast.Name('w', ast.Load()), frame_address(offset)], []))""",
        """        return builder.op('call', [builder.env['w'], builder.c(offset)],
                          'u64', function=names['frame_get'])"""), (
        """        builder.op('call', [builder.env['w'], builder.expr(frame_address(offset)), scalar(value)],
                   'u64', function=names['put'])""",
        """        builder.op('call', [builder.env['w'], builder.c(offset), scalar(value)],
                   'u64', function=names['frame_put'])""")]
    if overlays[SORT].count(helpers.encode()) != 1 or overlays[SORT].replace(helpers.encode(), b'', 1) != old_raw[SORT]:
        raise ValueError('sort helper insertion is not the exact declared delta')
    inverse = overlays[CONTINUATION]
    for before, after in substitutions:
        if inverse.count(after.encode()) != 1:
            raise ValueError('continuation substitution is not unique')
        inverse = inverse.replace(after.encode(), before.encode(), 1)
    if inverse != old_raw[CONTINUATION]:
        raise ValueError('continuation inverse differs from frozen original')
    os.mkdir(NEW, 0o700)
    source = NEW / 'source'
    os.mkdir(source, 0o700)
    source_pins, derivation = {}, {}
    for name, expected in sorted(old_config['source_pins'].items()):
        raw = stable(OLD / 'source' / name)
        if pin(raw) != expected:
            raise ValueError('frozen r2 source pin differs: ' + name)
        replacement = overlays.get(name, raw)
        source_pins[name] = create(source / name, replacement)
        derivation[name] = {'old_source_pin': expected, 'new_source_pin': source_pins[name],
                            'origin': 'isolated-r3c-frame-helpers' if name in overlays else 'exact-frozen-r2-source-copy'}
    if len(source_pins) != 160 or sum(source_pins[n] != old_config['source_pins'][n] for n in source_pins) != 2:
        raise ValueError('two-file source delta required')
    controls = NEW / 'control'
    os.mkdir(controls, 0o700)
    for name in ('source_authoring_worker.py', 'guardian.py', 'process_owner_impl.py'):
        create(controls / name, stable(OLD / 'control' / name))
    config = dict(old_config, source_root=str(source), source_pins=source_pins)
    config_path = controls / 'CONFIG.json'
    create(config_path, wire(config))
    create(NEW / 'SOURCE-DERIVATION.json', wire(derivation))
    for name in ('ORIGINAL-CLI-ID-SOURCE.json', 'TRACE-PLAN.original.json'):
        create(NEW / name, stable(OLD / name))
    python = Path(old_preexec['python']['path'])
    if pin(stable(python)) != {k: old_preexec['python'][k] for k in ('bytes', 'sha256', 'git_blob')}:
        raise ValueError('exact original Python bytes differ')
    fixed = {str(source / name): row['sha256'] for name, row in source_pins.items()}
    fixed.update({str(path): sha256(stable(path)).hexdigest() for path in controls.iterdir()})
    fixed[str(python)] = old_preexec['python']['sha256']
    worker = controls / 'source_authoring_worker.py'
    request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
               'cwd': str(source), 'command': [str(python), '-I', '-S', '-B', str(worker), str(config_path), str(NEW / 'actual-r3')],
               'source_identities': fixed, 'expected_qualification': None}
    guard = NEW / 'guardian-r3'
    os.mkdir(guard, 0o700)
    request_path = guard / 'REQUEST.json'
    request_pin = create(request_path, wire(request))
    preexec = dict(old_preexec)
    preexec.update(command=[str(python), '-I', '-S', '-B', str(controls / 'guardian.py'),
                           '--config', str(request_path), '--config-sha256', request_pin['sha256'],
                           '--implementation', str(controls / 'process_owner_impl.py')],
                   cwd=str(source), request={'path': str(request_path), **request_pin},
                   worker={'path': str(worker), **pin(stable(worker))},
                   source_bytes=sum(row['bytes'] for row in source_pins.values()),
                   previous_request_status='HOLD', previous_originals_commit='ef89a2c2012bb9849bcf07ec6352f9575dd25cdd',
                   source_revision='implementation-r3c',
                   limits_exclusions=['Only the same nine structural metrics are measured.',
                                      'The compiler 16384-line gate is not measured by this unchanged source-only worker.',
                                      'No native output-size proof, actual compilation or product equivalence claim.'])
    create(NEW / 'PREEXEC.json', wire(preexec))
    delta = {'schema': 'hia.cli-json.sort-frame-helper-delta.v1', 'status': 'STATIC_FROZEN_NOT_EXECUTED',
             'old_source_commit': '76c13dc2152c6daa31841f1622f92f3972b20004',
             'old_originals_commit': 'ef89a2c2012bb9849bcf07ec6352f9575dd25cdd',
             'source_files': {name: {'old_pin': pin(old_raw[name]), 'new_pin': pin(overlays[name])} for name in overlays},
             'exact_inverse_patch_restores_all_old_bytes': True,
             'observed_previous_cap_failure': {'instructions': 8381, 'original_limit': 8192},
             'new_cap_count': None,
             'helper_semantics': {'frame_get': 'get(w, get(w, 3264) + offset)',
                                  'frame_put': 'put(w, get(w, 3264) + offset, value)'},
             'preserved': ['Every frame-base read remains; no caching.',
                           'Each original frame target read/write and wrapping address addition remains.',
                           'Original value expression is evaluated before the frame_put operation.',
                           'Original algorithm/comparison/error propagation source is byte-identical.',
                           'Prior borrow.read/copy_range/loan.end source fix is byte-identical.',
                           'No native comparator callback order, frame layout or external permission changes.'],
             'unchanged_other_source_files': 158, 'unchanged_execution_controls': 3,
             'component_population': config['components'], 'structural_limits': config['limits'],
             'original_cli_ids': config['original_cli_ids'], 'planned_trace_ids': config['trace_plan_ids'],
             'native_or_product_requested': False, 'public_selection_changed': False,
             'no_claim_of_core_or_native_acceptance_before_actual_new_request': True}
    create(HERE / 'FRAME-HELPER-DELTA.json', wire(delta))
    create(HERE / 'STATUS.json', wire({'status': 'STATIC_FROZEN_NOT_EXECUTED',
                                     'new_request': str(NEW / 'PREEXEC.json'),
                                     'original_four_component_request_status': 'HOLD',
                                     'actual_new_source_generation': False,
                                     'separate_incomplete_r4_transport_not_included': True}))
    print(json.dumps({'status': 'FROZEN_NOT_EXECUTED', 'source_files': len(source_pins),
                      'source_bytes': preexec['source_bytes'], 'request_sha256': request_pin['sha256'],
                      'preexec_sha256': pin(stable(NEW / 'PREEXEC.json'))['sha256'],
                      'new_source_pins': {name: pin(raw) for name, raw in overlays.items()}}, sort_keys=True))


if __name__ == '__main__':
    main()
