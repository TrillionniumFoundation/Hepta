#!/usr/bin/env python3
"""Small defined-input C parameter probes; no benchmark or repository writes."""
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path('/workspace/scratch/4bc91e0ee48c/hepta-vla-original-type')
ROOT = Path(__file__).parent
CLANG = '/usr/lib/llvm-20/bin/clang'
sys.path.insert(0, str(REPO))
from hepta.c_migrate import migrate_c_project

CASES = {
    'ordinary_pointer': 'const unsigned *data',
    'ordinary_fixed': 'const unsigned data[8]',
    'direct_vla': 'const unsigned data[++n]',
    'sizeof_vla': 'const unsigned data[sizeof(unsigned[++n])]',
    'typeof_vla': '__typeof__(const unsigned[++n]) data',
    'typeof_deref_vla': '__typeof__(*(const unsigned (*)[++n])0) data',
    'typeof_index_vla': '__typeof__(((const unsigned (*)[++n])0)[0]) data',
    'comma_bound': 'const unsigned data[(++n, 8)]',
    'zero_times_effect': 'const unsigned data[8 + 0 * ++n]',
    'sizeof_vm_pointer': 'const unsigned data[sizeof(unsigned (*)[++n])]',
    'sizeof_vm_pointer_nested': 'const unsigned data[sizeof(unsigned (*)[sizeof(unsigned[++n])])]',
    'typeof_sizeof_vm_pointer_array': '__typeof__(const unsigned[sizeof(unsigned (*)[++n])]) data',
    'typeof_sizeof_vla_scalar': '__typeof__(sizeof(unsigned[++n])) value',
    'typeof_comma_sizeof_vla_scalar': '__typeof__((sizeof(unsigned[++n]), 0u)) value',
    'typeof_fixed_pointer_from_vm_sizeof': '__typeof__(((void)sizeof(unsigned[++n]), (const unsigned *)0)) data',
    'typeof_fixed_pointer_from_vm_deref': '__typeof__((0 ? *(const unsigned (*)[++n])0 : (const unsigned *)0)) data',
    'typeof_conditional_compatible_arrays': '__typeof__(*(0 ? (const unsigned (*)[++n])0 : (const unsigned (*)[8])0)) data',
    'typeof_conditional_reverse_arrays': '__typeof__(*(0 ? (const unsigned (*)[8])0 : (const unsigned (*)[++n])0)) data',
}

rows = []
for name, param in CASES.items():
    directory = ROOT / name
    directory.mkdir()
    source = 'unsigned probe(unsigned n, ' + param + ') { return n; }\n'
    (directory / 'input.c').write_text(source)
    argv = [CLANG, '-std=c11', '-O0', '-Werror', '-shared', '-fPIC', 'input.c', '-o', 'original.so']
    compiled = subprocess.run(argv, cwd=directory, text=True, capture_output=True, timeout=15)
    (directory / 'compile.stdout').write_text(compiled.stdout)
    (directory / 'compile.stderr').write_text(compiled.stderr)
    row = {'case': name, 'source': source, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
           'compile_argv': argv, 'compile_returncode': compiled.returncode}
    if compiled.returncode == 0:
        library = ctypes.CDLL(str(directory / 'original.so'))
        library.probe.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        library.probe.restype = ctypes.c_uint
        data = (ctypes.c_uint * 64)(*range(64))
        row['original_result_n7'] = int(library.probe(7, ctypes.cast(data, ctypes.c_void_p)))
        if row['original_result_n7'] != 7 or name in {'ordinary_pointer', 'ordinary_fixed'}:
            database = directory / 'compile_commands.json'
            database.write_text(json.dumps([{'directory':str(directory),'file':'input.c',
                'arguments':[CLANG, '-std=c11', '-O0', '-c', 'input.c', '-o', 'input.o']}]))
            contracts = {'schema':'hepta.c-contracts.v1','functions':{'probe':{'slices':{
                'data':{'length':'n','access':'read'}}}}}
            report = migrate_c_project(database, directory / 'migrated', contracts=contracts, clang=CLANG)
            (directory / 'migration.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
            row['migration_ok'] = report['ok']
            row['diagnostics'] = report['diagnostics']
            row['original_type_states'] = [item for receipt in report.get('source_type_admission', [])
                for function in receipt['functions'] for item in function['parameters']]
    rows.append(row)
    print(json.dumps({k:v for k,v in row.items() if k not in {'compile_argv','source_sha256','original_type_states'}}, ensure_ascii=False),flush=True)
(ROOT / 'candidate-results.json').write_text(json.dumps({'schema':'hepta.audit.vla-independent-candidates.v1',
    'git_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
    'cases':rows,'no_performance_measurement':True},indent=2,sort_keys=True)+'\n')
