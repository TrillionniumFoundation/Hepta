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
OLD = PROJECT / 'source-authoring-r1'
NEW = PROJECT / 'source-authoring-r2'
SORT = 'tools/generate_hia_cli_json_sort.py'


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
    old_raw = stable(OLD / 'source' / SORT)
    new_raw = stable(HERE / 'inputs' / SORT)
    ast.parse(new_raw, filename=SORT)
    before = """                return self.op('buffer.copy_range', [args[0], args[2], self.cast(args[1], 'usize'),
                               self.cast(args[3], 'usize'), self.cast(args[4], 'usize')])"""
    after = """                # A cross-buffer source remains a mutbuf parameter.  Borrow an
                # actual readbuf for this one copy, then end its local loan
                # before any later source mutation or call.  The same-buffer
                # path above uses move_within and creates no loan.
                destination_at = self.cast(args[1], 'usize')
                source_at = self.cast(args[3], 'usize')
                count = self.cast(args[4], 'usize')
                source_view = self.op('borrow.read', [args[2]], 'readbuf')
                result = self.op('buffer.copy_range', [args[0], source_view,
                                 destination_at, source_at, count])
                self.op('loan.end', [source_view])
                return result"""
    if new_raw.count(after.encode()) != 1 or new_raw.replace(after.encode(), before.encode()) != old_raw:
        raise ValueError('exact inverse of isolated source patch failed')
    program = next(ast.literal_eval(node.value) for node in ast.parse(new_raw).body
                   if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in node.targets))
    calls = [node for node in ast.walk(ast.parse(program)) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == 'copy_span']
    same = sum(ast.dump(node.args[0]) == ast.dump(node.args[2]) for node in calls)
    if len(calls) != 9 or same != 3:
        raise ValueError('source routing population differs')
    os.mkdir(NEW, 0o700)
    source = NEW / 'source'
    os.mkdir(source, 0o700)
    source_pins, derivation = {}, {}
    for name, expected in sorted(old_config['source_pins'].items()):
        raw = stable(OLD / 'source' / name)
        if pin(raw) != expected:
            raise ValueError('frozen r1 source pin differs: ' + name)
        replacement = new_raw if name == SORT else raw
        source_pins[name] = create(source / name, replacement)
        derivation[name] = {'old_source_pin': expected, 'new_source_pin': source_pins[name],
                            'origin': 'isolated-r3b-borrow-fix' if name == SORT else 'exact-frozen-r1-source-copy'}
    if len(source_pins) != 160 or sum(source_pins[n] != old_config['source_pins'][n] for n in source_pins) != 1:
        raise ValueError('one-file source delta required')
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
               'cwd': str(source), 'command': [str(python), '-I', '-S', '-B', str(worker), str(config_path), str(NEW / 'actual-r2')],
               'source_identities': fixed, 'expected_qualification': None}
    guard = NEW / 'guardian-r2'
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
                   previous_request_status='HOLD', previous_originals_commit='606b9a9e185b96908d782435c594f40ce2b97cde',
                   source_revision='implementation-r3b',
                   limits_exclusions=['Only the same nine structural metrics are measured.',
                                      'The compiler 16384-line gate is not measured by this unchanged source-only worker.',
                                      'No native output-size proof, actual compilation or product equivalence claim.'])
    create(NEW / 'PREEXEC.json', wire(preexec))
    delta = {'schema': 'hia.cli-json.sort-borrow-source-delta.v1', 'status': 'STATIC_FROZEN_NOT_EXECUTED',
             'old_source_commit': '2620fc07a169b3e15cf6a9615b20d27fb9d59db8',
             'old_originals_commit': '606b9a9e185b96908d782435c594f40ce2b97cde',
             'source_file': SORT, 'old_pin': pin(old_raw), 'new_pin': pin(new_raw),
             'exact_inverse_patch_restores_all_old_bytes': True,
             'same_buffer_routes': 3, 'cross_buffer_routes': 6,
             'same_buffer': 'unchanged buffer.move_within; no borrow',
             'cross_buffer': 'Evaluate original operands and three scalar casts, then borrow.read the source mutbuf, copy_range using its readbuf, and loan.end in the same block before subsequent source use.',
             'operand_type_definition': {'path': 'hepta/hia_opcodes.py', 'pin': source_pins['hepta/hia_opcodes.py']},
             'builder_definition': {'path': 'tools/generate_hia_selfhost.py', 'pin': source_pins['tools/generate_hia_selfhost.py']},
             'unchanged_other_source_files': 159, 'unchanged_execution_controls': 3,
             'component_population': config['components'], 'structural_limits': config['limits'],
             'original_cli_ids': config['original_cli_ids'], 'planned_trace_ids': config['trace_plan_ids'],
             'native_or_product_requested': False, 'public_selection_changed': False,
             'no_claim_of_core_or_native_acceptance_before_actual_new_request': True}
    create(HERE / 'BORROW-DELTA.json', wire(delta))
    create(HERE / 'STATUS.json', wire({'status': 'STATIC_FROZEN_NOT_EXECUTED',
                                     'new_request': str(NEW / 'PREEXEC.json'),
                                     'original_four_component_request_status': 'HOLD',
                                     'actual_new_source_generation': False,
                                     'separate_incomplete_r4_transport_not_included': True}))
    print(json.dumps({'status': 'FROZEN_NOT_EXECUTED', 'source_files': len(source_pins),
                      'source_bytes': preexec['source_bytes'], 'request_sha256': request_pin['sha256'],
                      'preexec_sha256': pin(stable(NEW / 'PREEXEC.json'))['sha256'],
                      'new_sort_sha256': pin(new_raw)['sha256']}, sort_keys=True))


if __name__ == '__main__':
    main()
