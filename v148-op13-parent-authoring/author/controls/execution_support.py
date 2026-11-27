"""Explicit op13 development gate: static bindings, no import-time products."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback
import zlib

from run_control_child import (FIELDS, LIMITS, require, pin, seven, decode, fixed,
                               metadata, source_guard, publish)
import inspect_exec_support as observer

SCHEMA = 'hepta.hia.op13.post-reset.execution.v1'
CAPACITY = 1048576
MINIMUM_FREE = 1073741824
COMPONENTS = ('control', 'format', 'discovery', 'routing', 'parser_context',
              'verified_report', 'inspect', 'patch')
FRAME_KEYS = ('source_before', 'output_before', 'workspace_before',
              'source_after', 'output_after', 'workspace_after')
SOURCE_TREE = '821bb0ac9c4ce7a7648c1c34ef91406e3a45fbcb'
B3_PIN = {'bytes': 673413, 'mode': '100644',
    'git_blob': '315c6b5f36a1ec679deb68abdca24bd4d1bef9f8',
    'sha256': 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def capture(path, *, maximum=16 << 20):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute fixed path required')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= maximum,
            'unique bounded regular input required: ' + str(path))
    raw = observer.read_regular(path, maximum=maximum)
    require(seven(info) == seven(path.lstat()), 'input changed around capture')
    row = {'path': str(path), 'pin': pin(raw, '100755' if info.st_mode & 0o111 else '100644'),
           'stat': seven(info)}
    require(fixed(row) == raw, 'complete capture readback differs')
    return row


def checked(row):
    raw = fixed(row)
    require(row['stat']['st_nlink'] == 1 and
            ('100755' if row['stat']['st_mode'] & 0o111 else '100644') == row['pin']['mode'],
            'captured POSIX/Git mode or link count differs')
    return raw


def floor(path):
    value = os.statvfs(path)
    available = value.f_bavail * value.f_frsize
    require(available >= MINIMUM_FREE, 'original actual-filesystem 1GiB floor not met')
    return available


def directory_binding(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute directory authority required')
    rows = []
    for node in reversed([path, *path.parents]):
        info = node.lstat()
        require(stat.S_ISDIR(info.st_mode), 'directory ancestor must not be a link')
        rows.append({'path': str(node), 'dev': info.st_dev, 'ino': info.st_ino,
                     'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid})
    return rows


def guard_directories(rows):
    for row in rows:
        info = Path(row['path']).lstat()
        require({'path': row['path'], 'dev': info.st_dev, 'ino': info.st_ino,
                 'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid} == row
                and stat.S_ISDIR(info.st_mode), 'held path authority changed')


def control_guard(plan):
    for name, row in plan['controls'].items():
        checked(row)
    for row in plan['provenance'].values():
        checked(row)
    require(plan['compiler']['pin'] == B3_PIN and len(checked(plan['compiler'])) == 673413,
            'exact ordinary B3 required; no compiler substitution')
    require(plan['limits'] == LIMITS and plan['storage_floor'] == MINIMUM_FREE,
            'original limits changed')
    guard_directories(plan['scope_ancestors'])
    guard_directories(plan['author_ancestors'])


def runtime_files_guard(plan):
    value = decode(checked(plan['runtime_map']))
    root = Path(value['root'])
    wanted = {row['path']: row for row in value['files']}
    before = metadata(root)
    require({name for name, st in before.items() if stat.S_ISREG(st['st_mode'])} == set(wanted)
            and len(wanted) == 2496
            and {name for name, st in before.items() if stat.S_ISDIR(st['st_mode'])}
                == {'.', *value['new_directories']}, 'complete restored runtime pathset differs')
    for name, row in wanted.items():
        old = row['new_file_seven_stat']
        expected_stat = dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),old))
        wanted_pin = {**row['pin'], 'mode': '100755' if row['mode'] & 0o111 else '100644'}
        require(stat.S_IMODE(before[name]['st_mode']) == row['mode'], 'runtime file mode differs')
        checked({'path': str(root / name), 'pin': wanted_pin, 'stat': expected_stat})
    require(metadata(root) == before, 'restored runtime metadata changed during full read')
    return {'files': len(wanted), 'map': plan['runtime_map']['pin'], 'all_bytes_read': True}


def all_guards(plan, runtime_guard=None):
    control_guard(plan)
    value = source_guard(plan, observer)
    expected = decode(checked(plan['source_map']))
    require(observer.tree_digest(expected) == SOURCE_TREE, 'complete new source tree differs')
    runtime_files_guard(plan)
    if runtime_guard is not None:
        runtime_guard(plan['runtime'])
    return value


def import_runtime(plan):
    sys.path.insert(0, plan['source'])
    from tools import hia_linux_file_roundtrip_cold as runtime
    from tools import hia_selfhost_process_owner as owner
    for module, name in ((runtime, 'tools/hia_linux_file_roundtrip_cold.py'),
                         (owner, 'tools/hia_selfhost_process_owner.py')):
        require(Path(module.__file__).absolute() == Path(plan['source']) / name,
                'runtime/owner module imported outside complete source view')
    return runtime, owner


def environment(plan):
    runtime, _ = import_runtime(plan)
    base = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': plan['attempt'],
        'TMPDIR': str(Path(plan['attempt']) / 'tmp'), 'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}
    return runtime.runtime_child_environment(base, plan['runtime'])


def admit_owner(returned, directory, command, env, plan):
    raw = observer.complete_receipt(returned, directory / 'OWNER.json')
    request_raw = checked(capture(directory / 'OWNER.json.request.json'))
    request = decode(request_raw)
    owner_pin = decode(checked(plan['source_map']))['tools/hia_selfhost_process_owner.py']['sha256']
    require(request['command'] == command and request['cwd'] == plan['source']
            and request['env'] == env and request['qualification_seconds'] == 180
            and request['cleanup_seconds'] == 3 and request['deadline_ns'] - request['started_ns'] == 180000000000
            and request['implementation_sha256'] == raw['implementation_sha256'] == owner_pin
            and raw['request_sha256'] == hashlib.sha256(request_raw).hexdigest(),
            'actual original owner request/budget/source binding differs')
    cleanup = raw['cleanup']
    require(not cleanup.get('remaining') and not cleanup.get('errors')
            and not cleanup.get('remaining_pids') and cleanup.get('remaining_direct_children') == []
            and not cleanup.get('deadline_exceeded') and cleanup.get('leader_reaped') is True
            and not raw.get('owner_error') and not raw.get('event_overflow') and cleanup['complete'] is True
            and cleanup['observed_echild'] is True, 'owner cleanup incomplete')
    return raw


def admit_tests(value, ids):
    require(value['status'] == 'PASS' and value['declared_ids'] == value['loaded_ids'] == ids
            and value['tests_run'] == len(ids) and not value.get('loader_errors')
            and value['events'] == [e for name in ids for e in (['start',name],['stop',name])]
            and not any(value.get(k) for k in ('failures','errors','skipped','expected_failures','unexpected_successes'))
            and all(r['status'] == 'PASS' for r in value['subtests']),
            'exact methods/events/subtests failed or are incomplete')


def audit_frames(directory):
    """Read every actual reference anew, including unfinalized journal files.

    This is parent evidence verification after the original owner. It does
    not execute/retire/ACK frames, infer absent buffers, or extend that owner.
    """
    result = {'journals': [], 'complete_calls': 0, 'started_calls': 0,
              'buffer_reference_reads': 0, 'all_frames_retired': False}
    for frames in sorted(Path(directory).rglob('frames')):
        require(frames.is_dir() and not frames.is_symlink(), 'frame directory type differs')
        journal = frames.parent
        rows = []; indices = set(); missing = []
        files = sorted(frames.iterdir())
        require(all(re.fullmatch(r'[0-9]{8}-(?:BEFORE|AFTER)\.json', x.name) for x in files),
                'unexpected frame evidence filename')
        for path in files:
            value = decode(checked(capture(path)))
            index = int(path.name[:8]); require(value['index'] == index, 'frame index differs')
            for key in FRAME_KEYS:
                if key not in value:
                    if path.name.endswith('-AFTER.json'): missing.append([index,key])
                    continue
                reference = value[key]
                require(re.fullmatch(r'[0-9a-f]{64}\.zlib', reference['file']) is not None
                        and reference['file'] == reference['sha256'] + '.zlib', 'bad CAS member')
                compressed = checked(capture(journal / 'buffers' / reference['file']))
                decoder = zlib.decompressobj(); full = decoder.decompress(compressed, reference['bytes'] + 1)
                require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                        and {k:v for k,v in pin(full).items() if k in reference} ==
                            {k:reference[k] for k in ('bytes','sha256','git_blob') + (('mode',) if 'mode' in reference else ())},
                        'complete actual buffer differs')
                result['buffer_reference_reads'] += 1
            if path.name.endswith('-BEFORE.json'):
                indices.add(index)
            else:
                before_path = frames / ('%08d-BEFORE.json' % index)
                before = decode(checked(capture(before_path)))
                require(all(value[k] == before[k] for k in ('source_before','output_before','workspace_before')),
                        'after frame changed its actual before bindings')
                rows.append(value)
        index_path = journal / 'INDEX.json'
        if index_path.exists():
            final = decode(checked(capture(index_path)))
            require(final['frames'] == rows and final['started_calls'] == len(indices)
                    and final['complete_calls'] == len(rows), 'final journal differs from actual frames')
        else: final = None
        require(indices == set(range(len(indices))), 'actual started call sequence has gaps')
        complete = not missing and len(rows) == len(indices)
        result['started_calls'] += len(indices); result['complete_calls'] += len(rows)
        result['journals'].append({'path':str(journal),'started':len(indices),'after':len(rows),
            'missing_fields':missing,'has_final_index': final is not None,'complete':complete})
    result['all_observed_frames_complete'] = all(r['complete'] for r in result['journals'])
    return result


def component_binding(manifest_path, expected_source, compiler, build_root):
    path = Path(manifest_path)
    require(path.is_absolute() and path.is_relative_to(build_root), 'manifest outside actual stage')
    row = capture(path); value = decode(checked(row))
    image_name = value['image_path']
    require(type(image_name) is str and Path(image_name).name == image_name and image_name not in ('','.', '..'),
            'actual image path must be one local member')
    image = capture(path.parent / image_name, maximum=CAPACITY)
    source = capture(expected_source, maximum=CAPACITY)
    require(value['source_sha256'] == source['pin']['sha256']
            and value['image_sha256'] == image['pin']['sha256']
            and value['compiler_sha256'] == compiler['pin']['sha256']
            and 0 < image['pin']['bytes'] <= CAPACITY, 'actual source/image/compiler mismatched')
    return {'manifest':row,'source':source,'image':image}
