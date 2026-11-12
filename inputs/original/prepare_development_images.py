"""Fresh development compilation; no current-cold authority is inferred."""
from pathlib import Path
from hashlib import sha256
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def main():
    output = ROOT / 'development-images-r2'
    output.mkdir()
    before_raw = (ROOT.parent / 'v78-byte-abi-development-r1/inputs/retained-development-compiler.bin').read_bytes()
    if len(before_raw) != 669494 or sha256(before_raw).hexdigest() != COMPILER_SHA:
        raise ValueError('exact retained B3 compiler differs')
    compiler = output / 'retained-development-compiler.bin'
    compiler.write_bytes(before_raw)
    compiler.chmod(0o444)
    sys.path.insert(0, str(SOURCE))
    spec = importlib.util.spec_from_file_location('exact_source_restore', ROOT.parent / 'v80-global-resolution-development-r1/restore_source.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    before = helper.manifest(SOURCE)
    write(output / 'SOURCE-BEFORE-GENERATION.json', before)
    commands = [
        ['tests/test_hia_selfhost_language_coverage.py', '--generate-inventory'],
        ['tools/generate_hia_selfhost_contract.py'],
        ['tools/generate_hia_selfhost_contract.py', '--check'],
        ['tools/check_hia_core_only.py']]
    generators = []
    for index, command in enumerate(commands):
        start = time.monotonic()
        result = subprocess.run([sys.executable, '-B', *command], cwd=SOURCE,
                                capture_output=True, timeout=1800)
        (output / ('generate-%d.stdout' % index)).write_bytes(result.stdout)
        (output / ('generate-%d.stderr' % index)).write_bytes(result.stderr)
        row = {'argv': [sys.executable, '-B', *command], 'seconds': time.monotonic() - start,
               'returncode': result.returncode, 'wall_limit_seconds': 1800}
        generators.append(row)
        write(output / ('generate-%d.PROCESS.json' % index), row)
        if result.returncode:
            raise ValueError('actual development generation failed: ' + command[0])
    frozen = helper.manifest(SOURCE)
    write(output / 'GENERATION.json', {'commands': generators,
        'changed_paths': [name for name in sorted(before.keys() | frozen.keys()) if before.get(name) != frozen.get(name)],
        'source_tree': helper.tree_hash(frozen), 'source_files': len(frozen),
        'current_source_cold': False})
    write(output / 'SOURCE-BEFORE.json', frozen)
    from tools.qualify_hia_selfhost import compile_stage
    labels = ('machine_encoding', 'machine_state', 'machine_instructions',
              'machine_elf', 'machine_plan', 'core_lowering')
    records = []
    for label in labels:
        module = importlib.import_module('hepta.hia_' + label + '_native')
        path = SOURCE / ('examples/hia_bootstrap/' + label + '.hiaasm')
        if module.SOURCE.resolve() != path.resolve():
            raise ValueError('source resource does not point at the actual new export')
        source = path.read_bytes()
        folder = output / label
        folder.mkdir(mode=0o700)
        image, receipt = compile_stage(folder, label, compiler, source)
        manifest = {'schema': module.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': COMPILER_SHA}
        write(folder / 'manifest.json', manifest)
        if path.read_bytes() != source or compiler.read_bytes() != before_raw:
            raise ValueError('compilation input drift')
        records.append({'label': label, 'manifest': manifest, 'receipt': receipt})
        print(json.dumps({'compiled': label, 'image_sha256': manifest['image_sha256']}, sort_keys=True), flush=True)
    after = helper.manifest(SOURCE)
    if after != frozen:
        raise ValueError('source changed during actual compilation')
    write(output / 'composition-manifests.json', {name: str(output / name / 'manifest.json') for name in labels[:-1]})
    write(output / 'SOURCE-AFTER.json', after)
    write(output / 'REPORT.json', {'schema': 'hia.global-import.fresh-development-build.v80.r2',
        'python': sys.version, 'compiler_sha256': COMPILER_SHA, 'compiled': records,
        'source_tree': helper.tree_hash(after), 'source_files': len(after),
        'all_source_bytes_modes_unchanged_during_compile': True,
        'current_source_cold': False, 'whole_native': False})
    print(json.dumps({'status': 'DEVELOPMENT_COMPILED', 'images': len(records),
                      'source_files': len(after), 'current_source_cold': False}, sort_keys=True))


if __name__ == '__main__':
    main()
