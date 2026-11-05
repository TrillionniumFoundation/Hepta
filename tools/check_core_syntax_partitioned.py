"""Exact eleven-stage partition protocol; no partial mode or fallback.

Only all eleven successful same-run stages can check the narrow connection.
Every wider obligation remains unproved and all production authority stays DENY.
"""
import json
import os
from pathlib import Path
import stat

from tools import check_core_syntax_staged as base
from tools import core_syntax_partition_sources as sources
from tools.check_guarded_slice_lean import require

ROOT = base.ROOT
PROTOCOL = 'contiguous-transport-certificate-partitions-v1'
STAGES = ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02', 'CertPart03',
          'CertPart04', 'CertPart05', 'CertPart06', 'Connections', 'TransportRejections', 'WrongArm')
DIAGNOSTIC_FILES = ('RUN.json', 'RESULT.json') + tuple(
    name + suffix for name in STAGES for suffix in ('.started.json', '.stdout', '.stderr', '.finished.json'))


def execute_partitioned(executable, output_directory, prepared, identity, support,
                        source_reader, support_reader, expected_binary_sha,
                        run_process=base.capture_result):
    """Reject legacy/unknown layouts before entering the shared safe executor."""
    require(prepared['manifest'].get('protocol') == PROTOCOL == sources.PROTOCOL,
            'exact versioned partition protocol required')
    require(type(prepared['stages']) is tuple and tuple(stage.name for stage in prepared['stages']) == STAGES,
            'exact eleven partition stages required')
    return base.execute_plan(executable, output_directory, prepared, identity, support,
                             source_reader, support_reader, expected_binary_sha,
                             run_process=run_process, stage_limit=base.MAX_INVOCATIONS)


def source_identity():
    result = base.source_identity()
    for relative in ('tools/check_core_syntax_partitioned.py', 'tools/core_syntax_partition_sources.py'):
        result[relative] = base.digest((ROOT / relative).read_bytes())
    return result


def qualify(lean, output_directory):
    from tools.check_core_syntax_lean import fixed_input
    from tools.qualify_hia_selected_formal import _support_identity
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT / 'formal/toolchain-lock.json').read_text())
    pinned = lock['lean_binary_sha256']
    require(base.digest(executable.read_bytes()) == pinned, 'pinned Lean binary required')
    identity, support = source_identity(), _support_identity(executable)
    prepared = sources.build_inputs()
    require(source_identity() == identity, 'sources changed during partition preparation')
    require(fixed_input()['bytes'] == prepared['canonical_bytes'], 'Core bytes changed')
    return execute_partitioned(executable, output_directory, prepared, identity, support,
                               source_identity, _support_identity, pinned)


def print_diagnostics(directory):
    """Read only this protocol's fixed report/log names, never directory entries."""
    path = Path(directory).absolute()
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'diagnostic ancestor is a symlink')
    if not path.exists():
        print('No proof output directory was created.')
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        captured = {}
        for name in (*DIAGNOSTIC_FILES, 'manifest.json'):
            try:
                handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except FileNotFoundError:
                continue
            try:
                before = os.fstat(handle)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                        before.st_size <= base.MAX_DIAGNOSTIC, 'unsafe diagnostic file')
                raw = os.read(handle, base.MAX_DIAGNOSTIC + 1)
                require(len(raw) <= base.MAX_DIAGNOSTIC, 'diagnostic exceeded limit')
                require(len(raw) == before.st_size, 'diagnostic short read')
                after = os.fstat(handle)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
                require(fields(before) == fields(after) == fields(current) and stat.S_ISREG(current.st_mode),
                        'diagnostic changed')
                captured[name] = raw
            finally:
                os.close(handle)
        if 'RESULT.json' not in captured:
            print('Incomplete diagnostic output: final RESULT.json is missing; evidence is not verified.')
            return
        result = json.loads(captured['RESULT.json'])
        require(result.get('protocol') == PROTOCOL and result.get('status') in ('passed', 'failed'),
                'invalid partition result')
        frozen = result.get('frozen_receipt_sha256')
        require(type(frozen) is dict and set(frozen) == set(captured) - {'RESULT.json'},
                'diagnostic frozen file set mismatch')
        require('manifest.json' in frozen and 'RUN.json' in frozen,
                'diagnostic manifest or RUN receipt missing')
        for name, expected in frozen.items():
            require(type(expected) is str and base.digest(captured[name]) == expected,
                    'diagnostic frozen file hash mismatch')
        if result['status'] == 'passed':
            require(set(captured) == set(DIAGNOSTIC_FILES) | {'manifest.json'},
                    'successful diagnostic file set incomplete')
        # No evidence is displayed until every candidate file has been safely read
        # and checked against the final container. RESULT itself is not self-hashed.
        for name in DIAGNOSTIC_FILES:
            if name in captured:
                print(name)
                print(captured[name].decode('utf-8', errors='replace'))
    finally:
        os.close(fd)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', type=Path)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--print-diagnostics', action='store_true')
    args = parser.parse_args(argv)
    if args.print_diagnostics:
        print_diagnostics(args.output_directory)
        return 0
    require(args.lean is not None, '--lean required for checking')
    result = qualify(args.lean, args.output_directory)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
