"""Record an independently executed VLA migration counterexample."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/4bc91e0ee48c/hepta-vla-original-type')
sys.path.insert(0, str(ROOT))
from hepta.c_migrate import migrate_c_project

OUT = Path('/tmp/hepta-vla-original-type-20261027/before')
OUT.mkdir()
CLANG = '/usr/lib/llvm-20/bin/clang'
RUSTC = '/tmp/hepta-toolchains/rust-1.90.0/bin/rustc'
source = 'unsigned int probe(unsigned int n, const unsigned int data[++n]) { return n; }\n'
(OUT / 'input.c').write_text(source)
database = OUT / 'compile_commands.json'
database.write_text(json.dumps([{'directory': str(OUT), 'file': 'input.c',
    'arguments': ['clang', '-std=c11', '-O0', '-c', 'input.c', '-o', 'input.o']}]))
contracts = {'schema': 'hepta.c-contracts.v1',
    'functions': {'probe': {'slices': {'data': {'length': 'n', 'access': 'read'}}}}}
(OUT / 'contracts.json').write_text(json.dumps(contracts, indent=2)+'\n')
report = {'schema': 'hepta.audit.vla-differential.v1',
          'git_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
          'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
          'defined_input': {'n': 7, 'initialized_array_elements': 8},
          'commands': [], 'outputs': {}, 'native_differential_executed': False}
for name, path in (('clang',CLANG),('rustc',RUSTC)):
    report[name] = {'path': path, 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        'version': subprocess.check_output([path,'--version'],text=True).strip()}
command = [CLANG, '-std=c11', '-O0', '-shared', '-fPIC', 'input.c', '-o', 'original.so']
run = subprocess.run(command,cwd=OUT,capture_output=True,text=True,timeout=60)
report['commands'].append({'argv': command, 'cwd': str(OUT), 'returncode': run.returncode,
                          'stdout': run.stdout, 'stderr': run.stderr})
run.check_returncode()
migration = migrate_c_project(database, OUT / 'translated', contracts=contracts,
    clang=CLANG, rustc=RUSTC, verify_native=True)
(OUT / 'migration.json').write_text(json.dumps(migration,indent=2,sort_keys=True)+'\n')
report['migration_ok'] = migration['ok']
report['migration_diagnostics'] = migration['diagnostics']
report['capture_sha256'] = migration.get('build',{}).get('sha256')
if migration['ok']:
    for name, artifact in (('original', OUT/'original.so'),
                           ('translated', OUT/'translated/libtranslated.so')):
        library = ctypes.CDLL(str(artifact))
        library.probe.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
        library.probe.restype = ctypes.c_uint
        data = (ctypes.c_uint * 8)(*range(8))
        report['outputs'][name] = int(library.probe(7,data))
    report['native_differential_executed'] = True
    report['equivalent'] = report['outputs']['original'] == report['outputs']['translated']
report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
(OUT/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:report[k] for k in ('git_commit','migration_ok','migration_diagnostics','outputs','native_differential_executed')}))
