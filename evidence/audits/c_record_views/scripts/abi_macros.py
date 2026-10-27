"""Replay native-char ABI spoof controls against one exact source checkout."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', required=True)
parser.add_argument('--clang', required=True)
parser.add_argument('--rustc', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
root = Path(args.repo).resolve()
output = Path(args.output)
if output.exists():
    parser.error('Refusing to overwrite existing evidence')
sys.path.insert(0, str(root))
from hepta.c_migrate import migrate_c_project

source = 'int probe(const char *value) { return value[0]; }\n'
base = Path(tempfile.mkdtemp(prefix='hepta-c-native-abi-macros-'))
rows = []
for name, flags, expected in [
    ('spoof_unsigned_macro_on_signed_target', ['-D__CHAR_UNSIGNED__=1'], -1),
    ('hide_unsigned_macro_on_unsigned_target', ['-funsigned-char', '-U__CHAR_UNSIGNED__'], 255),
    ('flag_like_include_path_is_not_a_compiler_option', ['-I', '-funsigned-char'], -1),
]:
    # A flag-like include-directory operand must not change the ABI model.
    work = base / name
    work.mkdir()
    (work / '-funsigned-char').mkdir()
    (work / 'input.c').write_text(source)
    database = work / 'compile_commands.json'
    database.write_text(json.dumps([{'directory': str(work), 'file': 'input.c',
        'arguments': ['clang', '-std=c11', *flags, '-c', 'input.c']}]))
    migration = migrate_c_project(database, work / 'translated',
        contracts={'schema': 'hepta.c-contracts.v1', 'functions': {'probe': {'slices': {'value': {'access': 'read', 'length': 1}}}}},
        clang=args.clang, rustc=args.rustc, verify_native=True)
    row = {'case': name, 'flags': flags, 'migration_ok': migration['ok'],
           'diagnostics': migration['diagnostics'], 'expected_native_result': expected,
           'configuration': [{key: c.get(key) for key in ('model', 'abi_model_arguments', 'predefined_macros_sha256', 'abi_predefined_macros_sha256')}
                             for c in migration.get('build', {}).get('configurations', [])]}
    if migration['ok']:
        built = subprocess.run(['gcc', '-std=c11', *flags, '-shared', '-fPIC', str(work / 'input.c'), '-o', str(work / 'original.so')], capture_output=True, text=True, cwd=work)
        if built.returncode:
            row['original_compile'] = {'returncode': built.returncode, 'stderr': built.stderr}
        else:
            values = {}
            for label, path in [('C', work / 'original.so'), ('Hepta', work / 'translated/libtranslated.so')]:
                library = ctypes.CDLL(str(path))
                call = library.probe
                call.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
                call.restype = ctypes.c_int
                byte = ctypes.c_ubyte(255)
                values[label] = call(ctypes.byref(byte))
            row['values'] = values
            row['matches_original'] = values['C'] == values['Hepta'] == expected
    rows.append(row)
report = {'schema': 'hepta.c-record-view-native-model-audit.v1',
          'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
          'source': source, 'artifacts': str(base), 'rows': rows,
          'implementation_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                   for name in ('hepta/c_project.py', 'hepta/c_translation.py', 'hepta/c_record_views.py')}}
output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, indent=2, sort_keys=True))
