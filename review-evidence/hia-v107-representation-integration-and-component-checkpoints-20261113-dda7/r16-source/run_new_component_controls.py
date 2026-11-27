"""Check the three new generator entry points twice and the four new controls.

This is a local component integration check, not the complete Source gate.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
OUT = ROOT / 'new-component-controls-r1'
RUNTIME = ROOT.parent / 'v94-cli-parser-context-r11-r2/graph-probe-r2/interpreter'


def put(name, value):
    with (OUT / name).open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')


def manifest():
    out = {}
    for path in sorted(SOURCE.rglob('*')):
        if path.is_file():
            assert not path.is_symlink()
            raw = path.read_bytes()
            out[path.relative_to(SOURCE).as_posix()] = {
                'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'mode': path.stat().st_mode & 0o777}
    return out


def main():
    OUT.mkdir()
    before = manifest()
    put('SOURCE-BEFORE.json', before)
    env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_')}
    env.update(LD_LIBRARY_PATH=str(RUNTIME / 'lib'), PYTHONDONTWRITEBYTECODE='1',
        HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE=str(OUT / 'buffers'))
    python = str(RUNTIME / 'bin/python3.14')
    commands = [[python, '-B', '-c', 'import sys; print(sys.version)']]
    for pass_ in range(2):
        commands += [[python, '-B', '-m', 'tools.generate_hia_' + name] for name in (
            'assembly_reparse', 'core_representation_internal', 'core_representation_private')]
    commands.append([python, '-B', '-m', 'unittest', '-v',
        'tests.test_hia_core_representation_source.CoreRepresentationSourceTests'])
    put('INTENT.json', {'commands': commands, 'cwd': str(SOURCE), 'owner_seconds': 180,
        'cleanup_seconds': 3, 'VM_step_limit': 10000000, 'new_generators': 3, 'generation_passes': 2,
        'expected_new_Source_controls': 4, 'full_Source1357_executed': False,
        'all134_generators_executed': False, 'native_compiles': 0, 'whole_native': False})
    started = time.monotonic()
    rows = []
    try:
        for i, argv in enumerate(commands):
            limit = 180 - (time.monotonic() - started)
            if limit <= 0:
                raise RuntimeError('original local owner deadline exhausted')
            tick = time.monotonic()
            timed_out = False
            with (OUT / f'{i:02d}.stdout.raw').open('xb') as out, (OUT / f'{i:02d}.stderr.raw').open('xb') as err:
                process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdout=out, stderr=err, start_new_session=True)
                try:
                    code = process.wait(timeout=limit)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        code = process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        code = process.wait()
            row = {'index': i, 'argv': argv, 'returncode': code, 'timed_out': timed_out,
                'owner_remaining_seconds_at_start': limit, 'wall_seconds': time.monotonic() - tick}
            rows.append(row)
            put(f'{i:02d}.RESULT.json', row)
            if timed_out or code:
                raise RuntimeError('command failed: ' + str(i))
        status, error = 'PASS', None
    except BaseException as exc:
        status, error = 'FAIL', {'type': type(exc).__name__, 'message': str(exc)}
    after = manifest()
    put('SOURCE-AFTER.json', after)
    if before != after:
        status = 'FAIL'
    result = {'status': status, 'error': error, 'commands': rows, 'wall_seconds': time.monotonic() - started,
        'source_unchanged': before == after, 'source_files': len(after),
        'new_generators': 3, 'two_real_default_generation_passes': status == 'PASS',
        'new_Source_controls': 4 if status == 'PASS' else None, 'owner_seconds': 180, 'cleanup_seconds': 3,
        'VM_step_limit': 10000000, 'all134_generators_executed': False, 'full_Source1357_executed': False,
        'native_compiles': 0, 'whole_native': False}
    put('OUTER.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'commands'}), flush=True)
    return 0 if status == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
