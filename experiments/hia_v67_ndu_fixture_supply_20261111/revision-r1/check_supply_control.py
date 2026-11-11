"""Fast local controls for the supply's natural-completion acceptance.

Uses the unchanged real guardian twice, with a normal child and an exiting
leader that leaves a live setsid child. Does not build Rust or access desktop.
"""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

from common import FIXED_HELPERS, create, natural_guardian, stable_file, wire


def main():
    here = Path(__file__).resolve().parent
    out = here / 'local-controls-r1'
    out.mkdir(mode=0o700, exist_ok=False)
    rows = []
    cases = {
        'normal': ('import sys\nprint("normal natural exit", flush=True)\n', True),
        'live_setsid_descendant': (
            'import os,time\n'
            'r,w=os.pipe()\npid=os.fork()\n'
            'if pid==0:\n'
            ' os.close(r);os.setsid();os.write(w,b"1");os.close(w);time.sleep(30);os._exit(0)\n'
            'os.close(w);os.read(r,1);os.close(r);print("leader exits with live setsid child",pid,flush=True)\n', False),
    }
    for label, (program, expected) in cases.items():
        directory = out / label
        directory.mkdir(mode=0o700)
        identities = {str(here / name): digest for name, digest in FIXED_HELPERS.items()}
        request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 3,
                   'command': [sys.executable, '-I', '-S', '-B', '-c', program],
                   'cwd': str(directory), 'source_identities': identities}
        raw = wire(request)
        create(directory / 'request.json', raw)
        with (directory / 'wrapper.stdout').open('xb') as stdout, (directory / 'wrapper.stderr').open('xb') as stderr:
            process = subprocess.run([sys.executable, '-B', str(here / 'guardian.py'),
                '--config', str(directory / 'request.json'), '--config-sha256', sha256(raw).hexdigest(),
                '--implementation', str(here / 'process_owner_impl.py')],
                stdout=stdout, stderr=stderr, timeout=10, check=False)
        original = (directory / 'guardian.json').read_bytes()
        value = json.loads(original)
        got = natural_guardian(value)
        assert got is expected
        assert value['lifecycle']['cleanup']['complete'] is True
        assert value['lifecycle']['cleanup']['observed_echild'] is True
        assert value['lifecycle']['cleanup']['remaining_direct_children'] == []
        kinds = [e['kind'] for e in value['lifecycle']['events']]
        assert ('owned_child_sigkill' in kinds) is (not expected)
        rows.append({'name': label, 'actual_guardian_executed': True,
                     'wrapper_returncode': process.returncode, 'guardian_status': value['status'],
                     'natural_completion_accepted': got, 'expected': expected,
                     'receipt_sha256': sha256(original).hexdigest(), 'events': kinds,
                     'receipt': str(directory / 'guardian.json')})
        if expected:
            normal = value
    for label, mutate in [
        ('overflow', lambda r: r['lifecycle'].__setitem__('event_overflow', True)),
        ('missing_echild', lambda r: r['lifecycle']['cleanup'].pop('observed_echild')),
        ('remaining_child', lambda r: r['lifecycle']['cleanup'].__setitem__('remaining_direct_children', [12345])),
        ('owner_exception', lambda r: r['lifecycle'].__setitem__('owner_error', 'synthetic control')),
        ('signal', lambda r: r['lifecycle'].__setitem__('interrupted_signals', [15])),
    ]:
        candidate = copy.deepcopy(normal)
        mutate(candidate)
        assert natural_guardian(candidate) is False
        rows.append({'name': label, 'actual_guardian_executed': False,
                     'receipt_mutation_control': True, 'natural_completion_accepted': False})
    leaf = out / 'create-only.bin'
    create(leaf, b'original')
    for label, operation in [
        ('existing_destination_refused', lambda: create(leaf, b'replacement')),
        ('wrong_digest_refused', lambda: stable_file(leaf, '0' * 64)),
    ]:
        try:
            operation()
        except (RuntimeError, FileExistsError):
            pass
        else:
            raise AssertionError(label)
        assert leaf.read_bytes() == b'original'
        rows.append({'name': label, 'original_bytes_preserved': True})
    report = {'schema': 'hia.v67.ndu-supply-control-observations.v1', 'status': 'PASS',
              'controls': rows, 'tests_run': len(rows), 'real_guardian_runs': 2,
              'rust_built': False, 'desktop_accessed': False, 'product_qualification_claimed': False,
              'source_sha256': {p.name: sha256(p.read_bytes()).hexdigest()
                                for p in sorted(here.glob('*.py'))}}
    create(out / 'OBSERVATIONS.json', wire(report))
    print(json.dumps({'status': report['status'], 'controls': len(rows), 'actual_guardian_runs': 2}))


if __name__ == '__main__':
    main()
