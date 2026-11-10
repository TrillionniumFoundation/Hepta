"""Explicit host driver: native HIA JSON Core representation -> native HIA image.

No host JSON payload decoding, Core verification or assembly translation occurs
in this path. Python still handles trusted manifests, allocations, filesystem and
child execution/receipt metadata. Not a source-only whole-toolchain bootstrap.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_core_json_frontend_native import installed_frontend, MAX_BYTES
from hepta.hia_json_preflight_native import _unique_manifest_pairs
from tools.qualify_hia_selfhost import compile_stage


def compile_core(wire: bytes, manifest: Path, compiler: Path, output: Path,
                 *, output_profile: str = 'flat') -> Path:
    if type(wire) is not bytes or len(wire) > MAX_BYTES:
        raise ValueError('outside HIA Core JSON wire profile')
    with manifest.open('rb') as stream:
        manifest_raw = stream.read(16385)
    if len(manifest_raw) > 16384:
        raise ValueError('oversized HIA frontend manifest')
    metadata = json.loads(manifest_raw, object_pairs_hook=_unique_manifest_pairs)
    compiler_raw = compiler.read_bytes()
    if type(metadata) is not dict or metadata.get('compiler_sha256') != sha256(compiler_raw).hexdigest():
        raise ValueError('native compiler differs from frontend build compiler')
    frontend = installed_frontend(str(manifest))
    rendered = frontend.render(wire, output_profile=output_profile)
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'core-json-program', compiler, rendered,
        output_extension={'elf':'.o', 'exec':'.elf', 'flat':'.image.bin'}[output_profile])
    if output_profile == 'exec':
        from tools.qualify_hia_selfhost_cli import inspect_executable
        inspect_executable(image.read_bytes())
        image.chmod(0o700)
    if compiler.read_bytes() != compiler_raw or manifest.read_bytes() != manifest_raw:
        raise ValueError('native JSON Core compilation inputs changed')
    (output/'frontend.receipt.json').write_text(json.dumps({
        'schema': 'hepta.hia.core-json-compilation.v1', 'status': 'NATIVE_CORE_JSON_COMPILED',
        'wire_sha256': sha256(wire).hexdigest(), 'wire_bytes': len(wire),
        'manifest_sha256': sha256(manifest_raw).hexdigest(),
        'rendered_assembly_sha256': sha256(rendered).hexdigest(),
        'rendered_assembly_bytes': len(rendered), 'native_compile_receipt': receipt,
        'output_profile': output_profile,
        'Python_payload_decoder_or_Core_verifier_used': False,
        'host_manifest_loader_and_process_driver': True,
        'production_activated': False, 'whole_stack_rewritten_in_hia': False},
        indent=2, sort_keys=True)+'\n')
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--output-profile', choices=('flat', 'elf', 'exec'), default='flat')
    args = parser.parse_args()
    with args.source.open('rb') as stream:
        wire = stream.read(MAX_BYTES + 1)
    print(compile_core(wire, args.manifest.resolve(), args.compiler.resolve(), args.output.resolve(),
                       output_profile=args.output_profile))


if __name__ == '__main__':
    main()
