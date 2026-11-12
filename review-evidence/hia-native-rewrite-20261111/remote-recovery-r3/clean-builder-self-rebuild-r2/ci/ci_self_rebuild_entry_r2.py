"""Explicit opt-in route to the full self-build CI, with no reader-sized wrapper.

The shared source-entry router binds the push SHA, selector and carrier job.
This entry additionally binds the complete target and source index before and
after runpy.  All group budgets remain owned by the exact target below.
"""
from pathlib import Path
import hashlib
import json
import operator
import os
import runpy
import stat
import sys
import traceback

TARGET = {'name': 'ci_self_rebuild_r4.py', 'bytes': 33938, 'sha256': '81663f8fc8398d2fc2902ce93932ea1eae3de7d9ae1d03acbf2b064b716f9326', 'gitsha': 'fed8c50796a4b9b5f4a0de9195bfdffda70ebe2d'}
INDEX = {'name': 'source-index-r2.json', 'bytes': 9224, 'sha256': '2fda495e899352c5a3ee81011b4f20b7bcf5e01cf6ce3c124288f108175b2cd8', 'gitsha': 'b9b54267541ea4a02643caafe041ddab4977b75c'}


def record(path):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode)
    raw = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mode) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mode)
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'gitsha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': stat.S_IMODE(before.st_mode)}


def checked(path, expected):
    pin = record(path)
    assert pin['mode'] == 0o644
    for key in ('bytes', 'sha256', 'gitsha'):
        assert pin[key] == expected[key], (str(path), key)
    return pin


def main():
    here = Path(__file__).resolve()
    target, index = here.with_name(TARGET['name']), here.with_name(INDEX['name'])
    repo = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    output_base = Path(os.environ['HIA_CI_OUTPUT']).resolve()
    output = output_base / 'true-self-rebuild-r1'
    assert repo.is_dir() and output_base != repo and not output_base.is_relative_to(repo)
    assert not output.exists()
    before = {str(here): record(here), str(target): checked(target, TARGET), str(index): checked(index, INDEX)}
    previous_argv, previous_bytecode = list(sys.argv), sys.dont_write_bytecode
    primary = None
    secondary = []
    target_returned = False
    try:
        sys.dont_write_bytecode = True
        sys.argv = [str(target), '--repo', str(repo), '--out', str(output), '--index', str(index)]
        try:
            runpy.run_path(str(target), run_name='__main__')
        except SystemExit as exc:
            if not (exc.code is None or isinstance(exc.code, int) and operator.index(exc.code) == 0):
                raise
        target_returned = True
        result = json.loads((output / 'summary.json').read_bytes())
        assert result['status'] == 'PASS' and result['primary'] is None and result['secondary'] == []
        assert result['complete_fresh_archive_afterchecked'] is True
        assert result['fresh_runtime_and_source_stages'] == 12 and result['completed_process_stages'] == 14
    except BaseException as exc:
        primary = (exc, exc.__traceback__)
    finally:
        sys.argv = previous_argv
        sys.dont_write_bytecode = previous_bytecode
        for path, expected in before.items():
            try:
                assert record(path) == expected, path
            except BaseException as exc:
                if primary is None:
                    primary = (exc, exc.__traceback__)
                else:
                    secondary.append({'phase': 'source-after', 'path': path, 'class': type(exc).__name__, 'message': str(exc)})
        receipt = {'schema': 'hia-self-rebuild-exact-opt-in-entry-r1',
                   'status': 'PASS' if primary is None and target_returned else 'FAIL',
                   'target': TARGET, 'index': INDEX, 'before': before,
                   'target_returned_zero': target_returned, 'output': str(output),
                   'reader_180_second_wrapper_used': False,
                   'original_group_budgets_owned_by_exact_target': True,
                   'primary': None if primary is None else {
                       'class': type(primary[0]).__name__, 'message': str(primary[0]),
                       'traceback': ''.join(traceback.format_exception(type(primary[0]), primary[0], primary[1]))},
                   'secondary': secondary}
        try:
            output_base.mkdir(parents=True, exist_ok=True)
            path = output_base / 'true-self-rebuild-entry-r1.json'
            raw = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
            path.write_bytes(raw)
            assert path.read_bytes() == raw
        except BaseException as exc:
            if primary is None:
                primary = (exc, exc.__traceback__)
            else:
                primary[0].add_note('entry receipt: ' + repr(exc))
    if primary is not None:
        raise primary[0].with_traceback(primary[1])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
