"""Compile one pinned reconstructed HIA source using the unchanged B3 child.

No current cold qualification is asserted. This controller retains original
20-second child wall, 10-second CPU and original buffers/address-space limits.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback
from common import (SOURCE, COMPILER_SHA, GENERATED, OVERLAYS, create,
                    load_exact, require, stable_file, wire)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--generator', type=Path)
    parser.add_argument('--generator-sha256')
    args = parser.parse_args()
    require(not args.output.exists(), 'create-only development build required')
    args.output.mkdir(mode=0o700)
    report = {'schema':'hepta.hia.machine-elf.reconstructed-development-build.v2',
              'status':'HOLD', 'scope':'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD',
              'variant':'before_filter_key_fix' if args.generator else 'filter_key_fixed',
              'compiler_sha256':COMPILER_SHA, 'source_before':None, 'source_after':None,
              'host_successor_compiler_calls':[], 'whole_writer_qualified':False,
              'whole_native_delivery_qualified':False, 'compiler_limits_changed':False}
    error = None
    try:
        sys.path.insert(0, str(SOURCE))
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools import qualify_hia_selfhost as qualify
        require(qualify.ROOT == SOURCE and qualify.CAPACITY == 1 << 20
                and qualify.NATIVE_OBSERVER is None
                and qualify.NATIVE_LINKED_OBSERVER is None,
                'original compile path or resource constants differ')
        def forbidden(*unused, **ignored):
            report['host_successor_compiler_calls'].append('build_seed')
            raise AssertionError('host successor compilation is forbidden')
        qualify.build_seed = forbidden
        compiler_before, _ = stable_file(args.compiler, COMPILER_SHA)
        before = {name:stable_file(SOURCE / name)[0] for name in (*OVERLAYS, GENERATED)}
        report['source_before'] = before
        if args.generator:
            require(args.generator_sha256 == '8bcda88d89db86c43d970e052e77cfcf5a98ef1b063356f6aad9c75b490ec87e',
                    'frozen pre-fix reconstructed generator required')
            generator = load_exact('reconstructed_elf_prefilter_generator',
                                   args.generator, args.generator_sha256)
            document = generator.document()
            source = render_assembly(document).encode()
            require(assemble_program(source).as_dict() == document,
                    'baseline generated Core roundtrip differs')
        else:
            _, source = stable_file(SOURCE / GENERATED,
                'af122cb4340ca351a07e3148e699730e4ed652f3c3c4deebdc5837dee693c6e3', collect=True)
            document = assemble_program(source).as_dict()
        require(len(source) <= 1 << 20 and len(document['functions']) == 41,
                'unchanged input and function denominator gate failed')
        source_pin = create(args.output / 'source.hiaasm', source)
        report['actual_source'] = source_pin
        image, receipt = qualify.compile_stage(args.output, 'machine-elf', args.compiler, source)
        report['native_compile_receipt'] = receipt
        require(receipt.get('limits') == {
            'cpu_seconds':10, 'address_bytes':256 << 20, 'core_dumpable':False,
            'stack_bytes':8 << 20, 'output_capacity':1 << 20,
            'workspace_bytes':1 << 20}, 'original native child limits differ')
        after = {name:stable_file(SOURCE / name)[0] for name in (*OVERLAYS, GENERATED)}
        report['source_after'] = after
        require(before == after and compiler_before == stable_file(args.compiler, COMPILER_SHA)[0]
                and not report['host_successor_compiler_calls'], 'compile source/compiler changed')
        image_info, _ = stable_file(image)
        manifest = {'schema':'hepta.hia.machine-elf-native.v1',
                    'source_sha256':sha256(source).hexdigest(), 'image_path':image.name,
                    'image_sha256':image_info['sha256'], 'compiler_sha256':COMPILER_SHA}
        manifest_info = create(args.output / 'manifest.json', wire(manifest))
        report.update(status='NATIVE_DEVELOPMENT_IMAGE_BUILT', source_stable=True,
                      image=image_info, manifest=manifest, manifest_file=manifest_info)
    except BaseException as exc:
        error = exc
        report['failure'] = {'type':type(exc).__name__, 'text':str(exc),
                             'traceback':traceback.format_exc()}
    finally:
        create(args.output / 'build.json', wire(report))
    print(json.dumps({'stage':'native_elf_compile', 'status':report['status'],
                      'variant':report['variant']}), flush=True)
    if error is not None:
        raise error

if __name__ == '__main__':
    main()
