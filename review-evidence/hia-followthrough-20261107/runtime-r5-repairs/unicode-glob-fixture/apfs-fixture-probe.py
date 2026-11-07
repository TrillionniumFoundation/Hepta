import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9/mac-unicode-glob-fixture-r1')
root.mkdir(mode=0o700)
original = root / 'original'
revised = root / 'revised'
original_paths = ['unicode/Å.txt', 'unicode/å.txt', 'unicode/中.txt']
revised_paths = ['unicode/upper/Å.txt', 'unicode/lower/å.txt', 'unicode/cjk/中.txt']
for name in original_paths:
    p = original / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'needle')
for name in revised_paths:
    p = revised / name
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('xb') as f:
        f.write(b'needle')
observed_original = sorted(str(p.relative_to(original)) for p in original.rglob('*') if p.is_file())
observed_revised = sorted(str(p.relative_to(revised)) for p in revised.rglob('*') if p.is_file())
assert observed_revised == sorted(revised_paths), observed_revised
assert not os.path.samefile(revised / revised_paths[0], revised / revised_paths[1])
rg = shutil.which('rg')
assert rg is not None
cases = []
for insensitive in (False, True):
    for pattern, expected in [
        ('unicode/*/Å.txt', ['unicode/upper/Å.txt']),
        ('unicode/*/å.txt', ['unicode/lower/å.txt']),
        ('unicode/*/?.txt', []),
        ('unicode/*/??.txt', ['unicode/lower/å.txt', 'unicode/upper/Å.txt']),
        ('unicode/*/???.txt', ['unicode/cjk/中.txt']),
    ]:
        argv = [rg, '--files', '--hidden', '--no-ignore', '--no-config', '--null', '--iglob' if insensitive else '--glob', pattern, '.']
        p = subprocess.run(argv, cwd=revised, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        names = sorted(name.decode().removeprefix('./') for name in p.stdout.split(b'\x00') if name)
        row = {'pattern':pattern, 'ignore_case':insensitive, 'argv':argv, 'exit_code':p.returncode, 'stdout_hex':p.stdout.hex(), 'stderr_hex':p.stderr.hex(), 'names':names, 'expected':sorted(expected)}
        cases.append(row)
        assert p.returncode in (0, 1) and names == sorted(expected), row
report = {'schema':'hia-apfs-unicode-glob-fixture-v1', 'platform':sys.platform,
          'original_paths':original_paths, 'original_observed':observed_original,
          'original_unicode_case_same_inode':os.path.samefile(original / original_paths[0], original / original_paths[1]),
          'revised_paths':revised_paths, 'revised_observed':observed_revised,
          'revised_unicode_case_same_inode':False, 'rust_tests_executed':False,
          'production_code_modified':False, 'cases':cases, 'all_assertions_passed':True}
destination = root / 'report.json'
with destination.open('x') as f:
    json.dump(report,f,indent=2,ensure_ascii=False)
    f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'report':str(destination), 'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(), 'original_observed':observed_original, 'original_same_inode':report['original_unicode_case_same_inode'], 'revised_observed':observed_revised, 'case_count':len(cases), 'all_assertions_passed':True}),flush=True)
