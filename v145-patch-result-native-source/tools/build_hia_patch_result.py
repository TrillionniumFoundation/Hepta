"""Explicit development build of the new patch policy component.

The compiler is a caller-pinned input. This entry grants no current-cold,
optional-profile installation or default-dispatch authority.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))


def _publish(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw)
    if Path(path).read_bytes() != raw:
        raise ValueError('patch development report readback differs')


def build_development(output, compiler, *, compiler_sha256):
    from hepta.hia_optional_profiles import _read_bound_file
    from hepta.hia_patch_result_native import (CAPACITY, IMAGE_NAME, SCHEMA,
                                             SOURCE_NAME, _capture_host_sources)
    from hepta.hia_patch_result_data import SOURCE_BYTES, SOURCE_SHA256
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_cli_discovery_custody import admit_compilation
    output, compiler = Path(output), Path(compiler)
    if (not output.is_absolute() or not compiler.is_absolute()
            or '..' in output.parts or '..' in compiler.parts
            or type(compiler_sha256) is not str or len(compiler_sha256) != 64
            or any(c not in '0123456789abcdef' for c in compiler_sha256)):
        raise ValueError('absolute output/compiler and exact compiler SHA256 required')
    compiler_raw = _read_bound_file(compiler.parent, compiler.name, limit=CAPACITY,
                                    expected_sha256=compiler_sha256)
    source_root = ROOT / 'examples/hia_bootstrap'
    source = _read_bound_file(source_root, SOURCE_NAME, limit=CAPACITY,
                             expected_length=SOURCE_BYTES, expected_sha256=SOURCE_SHA256)
    hosts = _capture_host_sources()
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.patch-result-development-build.v1', 'status': 'FAIL',
              'scope': 'CALLER_PINNED_COMPILER_NOT_CURRENT_COLD',
              'compiler': str(compiler), 'compiler_sha256': compiler_sha256,
              'source_sha256': SOURCE_SHA256, 'source_bytes': len(source),
              'host_sources': hosts, 'compile_seconds': 20, 'cpu_seconds': 10,
              'output_capacity': CAPACITY, 'workspace_capacity': CAPACITY,
              'default_activated': False, 'matching_current_cold': False,
              'whole_runtime': False, 'full_compile_workspace_observed': False}
    try:
        with (output / SOURCE_NAME).open('xb') as stream:
            stream.write(source)
        image, returned = compile_stage(output, 'patch-result', compiler, source)
        if image != output / IMAGE_NAME:
            raise ValueError('patch compiler produced a different path')
        receipt, observations = admit_compilation(output, 'patch-result', compiler, source, image)
        if receipt != returned:
            raise ValueError('patch actual/returned compiler receipt differs')
        image_raw = _read_bound_file(output, IMAGE_NAME, limit=CAPACITY)
        manifest = {'schema': SCHEMA, 'source_path': SOURCE_NAME,
                    'source_sha256': SOURCE_SHA256, 'image_path': IMAGE_NAME,
                    'image_sha256': sha256(image_raw).hexdigest(),
                    'compiler_sha256': compiler_sha256, 'host_sources': hosts}
        if (_read_bound_file(compiler.parent, compiler.name, limit=CAPACITY,
                            expected_sha256=compiler_sha256) != compiler_raw
                or _read_bound_file(source_root, SOURCE_NAME, limit=CAPACITY,
                                    expected_length=SOURCE_BYTES, expected_sha256=SOURCE_SHA256) != source
                or _capture_host_sources() != hosts):
            raise ValueError('patch development input changed')
        _publish(output / 'manifest.json', manifest)
        report.update(status='BUILT_AND_READ_BACK', image_bytes=len(image_raw),
                      image_sha256=manifest['image_sha256'],
                      actual_compile_receipt=receipt, observation_bindings=observations,
                      manifest=str(output / 'manifest.json'))
        return output / 'manifest.json'
    except BaseException:
        report['traceback'] = traceback.format_exc()
        raise
    finally:
        # An outer owner additionally retains failures to write this report.
        # Neither an image file nor a manifest alone is a successful gate.
        _publish(output / 'BUILD.json', report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--compiler-sha256', required=True)
    args = parser.parse_args()
    print(build_development(args.output, args.compiler, compiler_sha256=args.compiler_sha256))
