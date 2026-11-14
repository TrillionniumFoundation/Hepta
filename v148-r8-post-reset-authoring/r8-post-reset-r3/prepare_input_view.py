"""Post-reset path binding only: no project import, binary, owner, or product.

The later original 136-oracle owner remains mandatory.  This preparer copies
only the 808 other, already independently recovered input files into a new
directory layout consumed by the unchanged retained control bodies.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import stat
import sys
import time
import traceback

STAT_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size',
             'st_mtime_ns', 'st_ctime_ns')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def stamp(value):
    return [getattr(value, key) for key in STAT_KEYS]


def read_regular(path):
    path = Path(path)
    named = path.lstat()
    require(stat.S_ISREG(named.st_mode), 'not a regular file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(stamp(os.fstat(fd)) == stamp(named), 'named/opened file differs: ' + str(path))
        pieces, remaining = [], named.st_size + 1
        while remaining:
            part = os.read(fd, min(1 << 20, remaining))
            if not part:
                break
            pieces.append(part)
            remaining -= len(part)
        raw = b''.join(pieces)
        require(len(raw) == named.st_size, 'file extent changed: ' + str(path))
        require(stamp(os.fstat(fd)) == stamp(named) == stamp(path.lstat()),
                'file changed during full read: ' + str(path))
        return raw, stat.S_IMODE(named.st_mode), stamp(named)
    finally:
        os.close(fd)


def match(raw, mode, identity):
    actual = pin(raw)
    actual.update(mode=mode, git_mode='100755' if mode & 0o111 else '100644')
    require(set(identity) <= set(actual), 'unknown identity field')
    require(all(actual[key] == value for key, value in identity.items()),
            'full input bytes or required mode differs')
    return actual


def fixed(descriptor):
    raw, mode, observed = read_regular(descriptor['path'])
    match(raw, mode, descriptor['identity'])
    require(observed == descriptor['new_seven_stats'], 'fixed post-reset stat changed')
    return raw


def relative(value):
    p = PurePosixPath(value)
    require(p.as_posix() == value and not p.is_absolute()
            and all(part not in ('', '.', '..') for part in p.parts), 'unsafe relative path')
    return p


def file_paths(root):
    root = Path(root)
    require(stat.S_ISDIR(root.lstat().st_mode), 'root is not an actual directory')
    result = set()
    for base, directories, files in os.walk(root, followlinks=False):
        base = Path(base)
        for name in directories:
            require(stat.S_ISDIR((base / name).lstat().st_mode), 'non-directory in fixed tree')
        for name in files:
            path = base / name
            require(stat.S_ISREG(path.lstat().st_mode), 'non-regular fixed tree member')
            result.add(path.relative_to(root).as_posix())
    return result


def source_snapshot(plan):
    rows = json.loads(fixed(plan['source_map']))
    require(len(rows) == 3180 and file_paths(plan['source']) == set(rows), 'complete 3180 pathset differs')
    observed = {}
    for name, row in rows.items():
        raw, mode, current = read_regular(Path(plan['source']) / relative(name))
        match(raw, mode, row['identity'])
        require(current == row['seven_stats'] and current[3] == 1,
                'fresh restored source identity changed')
        observed[name] = current
    require(file_paths(plan['source']) == set(rows), 'source pathset changed while reading')
    require(all(stamp((Path(plan['source']) / name).lstat()) == value
                for name, value in observed.items()), 'source final stats changed')
    return observed


def runtime_snapshot(plan):
    value = json.loads(fixed(plan['runtime_map']))
    rows = value['files']
    require(value['root'] == plan['runtime_root'] and len(rows) == 2496, 'runtime map root/count differs')
    names = {row['path'] for row in rows}
    require(len(names) == 2496 and file_paths(plan['runtime_root']) == names, 'runtime pathset differs')
    observed = {}
    for row in rows:
        raw, mode, current = read_regular(Path(plan['runtime_root']) / relative(row['path']))
        match(raw, mode, {**row['pin'], 'mode': row['mode']})
        require(current == row['new_file_seven_stat'] and current[3] == 1, 'runtime new stat changed')
        observed[row['path']] = current
    require(file_paths(plan['runtime_root']) == names, 'runtime final pathset changed')
    require(all(stamp((Path(plan['runtime_root']) / name).lstat()) == value
                for name, value in observed.items()), 'runtime final stats changed')
    return observed


def reference_snapshot(plan):
    rows = plan['references']
    require(len(rows) == 948 and [row['ordinal'] for row in rows] == list(range(948)),
            'original reference order/count differs')
    result, unique, bytes_read = {}, {}, 0
    for row in rows:
        raw, mode, current = read_regular(row['recovered_path'])
        match(raw, mode, row['identity'])
        require(current == row['recovered_new_seven_stats'] and current[3] == 1,
                'recovered input stat changed')
        require(not Path(row['original_path']).exists(), 'lost historical path was recreated')
        result[row['role']] = {'path': row['recovered_path'], 'new_seven_stats': current}
        previous = unique.setdefault(row['original_path'], (row['recovered_path'], current))
        require(previous == (row['recovered_path'], current), 'duplicate reference identity differs')
        bytes_read += len(raw)
    require(len(result) == 948 and len(unique) == 944 and bytes_read == 717016014,
            'complete original reference totals differ')
    require(len({tuple(value[1][:2]) for value in unique.values()}) == 944,
            'distinct recovered original paths share an inode')
    require(all(stamp(Path(value[0]).lstat()) == value[1] for value in unique.values()),
            'recovered final input stats changed')
    return result


def controlled_snapshot(plan):
    observed = {}
    for name, descriptor in plan['controlled_files'].items():
        fixed(descriptor)
        observed[name] = descriptor['new_seven_stats']
    for name, descriptor in plan['authority_files'].items():
        fixed(descriptor)
        observed['authority/' + name] = descriptor['new_seven_stats']
    return observed


def storage(plan):
    parent = Path(plan['input_view']).parent
    fs = os.statvfs(parent)
    require(not (fs.f_flag & getattr(os, 'ST_NOEXEC', 8)), 'future executable filesystem is noexec')
    block = fs.f_frsize
    copied = sum(((row['identity']['bytes'] + block - 1) // block) * block for row in plan['copy_files'])
    restored = sum(((row['identity']['bytes'] + block - 1) // block) * block
                   for row in plan['future_oracle_files'])
    required = copied + restored + plan['product_floor_bytes'] + plan['reserve_bytes'] + plan['metadata_allowance_bytes']
    available = fs.f_bavail * block
    require(plan['product_floor_bytes'] == 3221225472 and available >= required,
            'actual filesystem cannot retain original 3GiB floor after both input stages')
    return {'filesystem': str(parent), 'device': parent.stat().st_dev, 'free_bytes': available,
            'copy_allocated_bound': copied, 'oracle_allocated_bound': restored,
            'product_floor_bytes': plan['product_floor_bytes'], 'reserve_bytes': plan['reserve_bytes'],
            'metadata_allowance_bytes': plan['metadata_allowance_bytes'], 'required_bytes': required}


def write_new(path, raw, mode):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        position = 0
        while position < len(raw):
            written = os.write(fd, raw[position:])
            require(written > 0, 'short destination write')
            position += written
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def dump(path, value):
    write_new(path, encoded(value), 0o600)


def prepare(plan, plan_raw):
    start = time.monotonic_ns()
    view = Path(plan['input_view'])
    require(all(not Path(path).exists() for path in plan['must_be_absent']), 'new stage root already exists')
    require(str(view) in plan['must_be_absent'], 'input view not in exact absent roots')
    require(len(plan['copy_files']) == 808
            and sum(row['identity']['bytes'] for row in plan['copy_files']) == 132337387,
            'exact 808 input-copy denominator differs')
    require(len(plan['future_oracle_files']) == 136
            and sum(row['identity']['bytes'] for row in plan['future_oracle_files']) == 578353224,
            'mandatory future oracle denominator differs')
    before = {'controls': controlled_snapshot(plan), 'source': source_snapshot(plan),
              'runtime': runtime_snapshot(plan), 'references': reference_snapshot(plan)}
    free = storage(plan)
    require(all(not Path(path).exists() for path in plan['must_be_absent']), 'stage root appeared during admission')
    view.mkdir(mode=0o700)
    (view / 'records').mkdir(mode=0o700)
    (view / 'inputs').mkdir(mode=0o700)
    records = view / 'records'
    result = {'schema': 'hepta.r8.post-reset.input-view-preparation.v1', 'status': 'FAIL',
              'plan': pin(plan_raw), 'source_trees_copied': 0, 'input_files_copied': 0,
              'input_bytes_copied': 0, 'original_136_owner_executed': False,
              'binary_executions': 0, 'products': 0, 'automatic_retry': False,
              'old_paths_recreated': False, 'old_stats_inherited': False, 'partial_files_preserved': True}
    destination_inodes = set()
    protected_inodes = {tuple(value[:2]) for value in before['source'].values()}
    protected_inodes.update(tuple(value[:2]) for value in before['runtime'].values())
    protected_inodes.update(tuple(value['new_seven_stats'][:2]) for value in before['references'].values())
    copied = {}
    try:
        dump(records / 'INTENT.json', {'plan': pin(plan_raw), 'storage': free,
            'copy_files': plan['copy_files'], 'no_products_or_oracle_restore_in_this_preparation': True})
        dump(records / 'BEFORE.json', before)
        with (records / 'COPY.jsonl').open('x', encoding='utf-8') as journal:
            for row in plan['copy_files']:
                raw, mode, current = read_regular(row['recovered_path'])
                match(raw, mode, row['identity'])
                require(current == row['recovered_new_seven_stats'], 'copy source changed')
                destination = view / relative(row['destination_relative'])
                require(destination.is_relative_to(view / 'inputs'), 'copy outside input view')
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                for parent in (destination.parent, *destination.parent.parents):
                    if parent == view.parent:
                        break
                    require(stat.S_ISDIR(parent.lstat().st_mode), 'copy parent is not a held independent directory')
                write_new(destination, raw, mode)
                again, after_mode, after = read_regular(destination)
                match(again, after_mode, row['identity'])
                inode = tuple(after[:2])
                require(again == raw and after[3] == 1 and inode not in protected_inodes
                        and inode not in destination_inodes, 'new copy is not independent')
                require(stamp(Path(row['recovered_path']).lstat()) == current, 'copy source final stat changed')
                destination_inodes.add(inode)
                saved = {'original_path': row['original_path'], 'recovered_path': row['recovered_path'],
                         'destination': str(destination), 'identity': row['identity'],
                         'recovered_new_seven_stats': current, 'destination_new_seven_stats': after}
                copied[row['destination_relative']] = saved
                journal.write(json.dumps(saved, sort_keys=True, separators=(',', ':')) + '\n')
                journal.flush()
                result['input_files_copied'] += 1
                result['input_bytes_copied'] += len(raw)
        expected = {str(PurePosixPath(name).relative_to('inputs')) for name in copied}
        require(file_paths(view / 'inputs') == expected, 'complete copy pathset differs')
        for name, row in copied.items():
            raw, mode, current = read_regular(view / name)
            match(raw, mode, row['identity'])
            require(current == row['destination_new_seven_stats'], 'new copy changed during complete readback')
        after = {'controls': controlled_snapshot(plan), 'source': source_snapshot(plan),
                 'runtime': runtime_snapshot(plan), 'references': reference_snapshot(plan)}
        dump(records / 'AFTER.json', after)
        require(after == before, 'complete original inputs/source/runtime/controls changed')
        require(all(stamp((view / name).lstat()) == row['destination_new_seven_stats']
                    for name, row in copied.items()), 'copied final stats changed')
        require(all(not Path(path).exists() for path in plan['must_be_absent'] if path != str(view)),
                'another stage was started during binding')
        dump(records / 'CURRENT-INPUT-VIEW.json', copied)
        result.update(status='PASS_808_INPUT_VIEW_ONLY', original_948_references_guarded=True,
                      all_new_inodes_independent=True, complete_source_runtime_and_input_guards_equal=True,
                      current_input_view=pin((records / 'CURRENT-INPUT-VIEW.json').read_bytes()),
                      original_136_owner_still_required=True, storage_before=free)
        return 0
    except BaseException:
        result['error'] = traceback.format_exc()
        raise
    finally:
        result['elapsed_ns'] = time.monotonic_ns() - start
        dump(records / 'RESULT.json', result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    raw, mode, _ = read_regular(args.plan)
    require(hashlib.sha256(raw).hexdigest() == args.plan_sha256 and mode == 0o644, 'preparation plan differs')
    plan = json.loads(raw)
    require(plan['schema'] == 'hepta.r8.post-reset.input-view-preparation-plan.v1', 'unknown preparation schema')
    require(str(Path(__file__).resolve()) == plan['runner']['path'], 'wrong preparer path')
    fixed(plan['runner'])
    return prepare(plan, raw)


if __name__ == '__main__':
    raise SystemExit(main())
