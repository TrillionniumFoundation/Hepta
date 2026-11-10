"""Build explicitly selected native HIA linker artifacts from qualified B3.

The build/custody driver remains Python. Actual ELF linking and the standalone
stdin/stdout linker entry are HIA-generated; there is no native runtime linker
subprocess or Python ELF transformation in the delivered executable.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.generate_hia_elf_linker import SOURCE
from tools.build_hia_source_lexer import _checked_compile_receipt

SCHEMA = 'hepta.hia.elf-linker-native.v1'
ROOT = Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    from tools.qualify_hia_selfhost_cli import inspect_executable
    compiler_bytes, cold = compiler.read_bytes(), cold_report.read_bytes()
    qualification = json.loads(cold)
    checks = {'export_manifest_matches_qualification', 'isolated_python_without_site',
        'nested_full_qualification_pass', 'nested_process_exit_zero', 'no_ancestor_git_identity',
        'no_bytecode_cache_created', 'no_inherited_home_or_python_cache',
        'no_inherited_seed_or_successor_images', 'origin_hashes_preserved',
        'owned_process_tree_cleanup_confirmed', 'source_export_hashes_preserved'}
    compiler_sha = sha256(compiler_bytes).hexdigest()
    if (type(qualification) is not dict
            or qualification.get('schema') != 'hepta.hia.selfhost-cold-replay.v1'
            or qualification.get('status') != 'COLD_SELFHOST_REPLAY_PASS'
            or qualification.get('returncode') != 0
            or type(qualification.get('checks')) is not dict
            or set(qualification['checks']) != checks
            or any(value is not True for value in qualification['checks'].values())
            or qualification.get('generation_sha256') != [compiler_sha] * 3):
        raise ValueError('a completed matching native cold qualification is required')
    identity_files = ['examples/hia_bootstrap/elf_linker.hiaasm',
        'tools/generate_hia_elf_linker.py', 'tools/build_hia_elf_linker.py', 'tools/link_hia_elf.py']
    captured = {name: (ROOT / name).read_bytes() for name in identity_files}
    source = captured['examples/hia_bootstrap/elf_linker.hiaasm']
    source_manifest = qualification.get('source_manifest')
    if (type(source_manifest) is not dict
            or any(source_manifest.get(name) != sha256(raw).hexdigest() for name, raw in captured.items())):
        raise ValueError('native linker build requires the matching qualified source inventory')
    output.mkdir(mode=0o700)
    flat, flat_receipt = compile_stage(output, 'elf-linker', compiler, source)
    flat_bytes = flat.read_bytes()
    identity = _checked_compile_receipt(flat_receipt, compiler_bytes, source, flat_bytes)
    cli_source = source.replace(b'hepta.hia.program.v8 elf_linker\n', b'hepta.hia.program.v8 selfhost_exec\n', 1)
    if cli_source == source:
        raise ValueError('native linker source module contract differs')
    cli, cli_receipt = compile_stage(output, 'hia-link', compiler, cli_source, output_extension='.elf')
    cli_bytes = cli.read_bytes()
    cli_identity = _checked_compile_receipt(cli_receipt, compiler_bytes, cli_source, cli_bytes)
    executable_inspection = inspect_executable(cli_bytes)
    if (compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or flat.read_bytes() != flat_bytes or cli.read_bytes() != cli_bytes):
        raise ValueError('native linker build inputs changed')
    cli.chmod(0o700)
    manifest = {'schema': SCHEMA, **identity, 'image_path': flat.name,
        'executable_path': cli.name, 'executable_sha256': cli_identity['image_sha256'],
        'executable_source_sha256': cli_identity['source_sha256'],
        'source_files': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'profile': 'selfhost-ELF64-x86_64-to-shared-libc-calloc-free-v1',
        'objects_max': 16, 'exports_max': 128, 'input_bytes_max': 1 << 20,
        'output_bytes_max': 1 << 20, 'external_allocator_ABI': ['libc.so.6:calloc', 'libc.so.6:free']}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({'schema': 'hepta.hia.elf-linker-build.v1',
        'status': 'NATIVE_LINKER_BUILT', 'manifest': manifest,
        'cold_report_sha256': sha256(cold).hexdigest(),
        'flat_compile_receipt': flat_receipt, 'executable_compile_receipt': cli_receipt,
        'executable_inspection': executable_inspection,
        'production_activated': False, 'host_build_and_artifact_custody_driver': True,
        'general_ELF_linker_implemented': False, 'whole_stack_rewritten_in_hia': False}, indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
