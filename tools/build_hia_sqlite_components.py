"""Build the source-bound Linux x86-64 SQLite component subprocesses."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_pager import (
    DRIVER, EMBED_SOURCE, ROOT, STATIC_LINKER, digest, embed, link, load_static_object, verify_executable, write_new,
)
from tools.qualify_hia_selfhost import compile_stage


UNITS = (
    'sqlite-rowid-lookup', 'sqlite-table-walk', 'sqlite-record-layout', 'sqlite-agent-row-import',
    'sqlite-agent-catalog', 'sqlite-agent-import-batch', 'sqlite-agent-cost-sequence',
    'sqlite-agent-artifact-catalog', 'sqlite-migration-plan',
)
START = 'tools/hia_sqlite_component_start.S'
INPUT = 'tools/hia_sqlite_component_input.S'
CAPTURE_ADAPTERS = ('tools/hia_agent_artifact_capture_start.S', 'tools/hia_agent_artifact_capture_read.S')
COMPONENT_DRIVER = 'tools/build_hia_sqlite_components.py'
PROJECTION = 'sqlite-migration-projection'
PROJECTION_ROLES = ('sqlite-agent-catalog', 'sqlite-table-walk', 'sqlite-rowid-lookup',
                    'sqlite-record-layout', 'sqlite-agent-row-import', 'sqlite-migration-plan',
                    'sqlite-migration-stage', 'sqlite-agent-import-batch',
                    'sqlite-agent-artifact-catalog', 'sqlite-agent-cost-sequence')
PROJECTION_ADAPTER = 'tools/hia_sqlite_migration_projection.S'
COMPONENT_TEMPLATES = 'examples/hia_bootstrap/sqlite_component_adapters.hepta'
ADAPTER_ROLES = {name: role for role, name in enumerate((START, INPUT, *CAPTURE_ADAPTERS, PROJECTION_ADAPTER))}


def compiled_images(directory, compiler, sources):
    captured = {}
    for role, source in sources.items():
        image, receipt = compile_stage(directory, role, compiler, source)
        raw = image.read_bytes()
        if digest(raw) != receipt['produced_sha256']:
            raise ValueError('SQLite build image changed: ' + role)
        captured[role] = (image, raw)
    return captured


def native_image(raw):
    return NativeHiaJsonImage(raw, digest(raw))


def build_executables(output, compiler, cold_report, units, adapters, drivers):
    compiler_bytes = compiler.read_bytes()
    cold_bytes = cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    units = {name: 'examples/hia_bootstrap/' + name.replace('-', '_') + '.hepta'
             for name in units}
    sources = {name: (ROOT / name).read_bytes()
               for name in (STATIC_LINKER, EMBED_SOURCE, COMPONENT_TEMPLATES, DRIVER, COMPONENT_DRIVER,
                            *drivers, *adapters, *units.values())}
    source_hashes = {name: digest(data) for name, data in sources.items()}
    if any(admitted.get(name) != value for name, value in source_hashes.items()):
        raise ValueError('native component source differs from admitted cold source')
    output.mkdir(mode=0o700)
    tools = compiled_images(output, compiler, {role: sources[name] for role, name in (
        ('linker', STATIC_LINKER), ('embedder', EMBED_SOURCE), ('adapter-templates', COMPONENT_TEMPLATES))})
    linker = tools['linker'][1]
    embedder = native_image(tools['embedder'][1])
    templates = native_image(tools['adapter-templates'][1])
    objects = tuple(load_static_object(templates, ADAPTER_ROLES[name], sources[name]) for name in adapters)

    products = {}
    for name, source in units.items():
        directory = output / name
        directory.mkdir(mode=0o700)
        path, receipt = compile_stage(directory, name, compiler, sources[source])
        image = path.read_bytes()
        if digest(image) != receipt['produced_sha256']:
            raise ValueError('native component image identity changed')
        component = embed(directory, 'component_image', name, image, embedder)
        binary, _ = link(directory, linker, image, (*objects, component), wire_magic=b'HIALNK01')
        if path.read_bytes() != image:
            raise ValueError('native component changed during executable link')
        products[name] = binary

    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes
            or any(path.read_bytes() != raw for path, raw in tools.values())
            or any((ROOT / name).read_bytes() != data for name, data in sources.items())):
        raise ValueError('native component build inputs changed before publication')

    manifest = {}
    for name, binary in products.items():
        executable = output / ('hia-' + name)
        with executable.open('xb') as stream:
            stream.write(binary)
            os.fchmod(stream.fileno(), 0o500)
        manifest[name] = {'name': executable.name, 'sha256': digest(binary), 'bytes': len(binary)}
    return {
        'source_sha256': source_hashes,
        'compiler_sha256': digest(compiler_bytes),
        'cold_report_sha256': digest(cold_bytes),
        'executable_manifest': manifest,
        'runtime_python_or_libc': False,
        'agent_store_replaced': False,
    }, admitted


def build_projection(output, compiler, cold_report, admitted):
    """Use the generic native linker for the projection and its intact peer bodies."""
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    names = (PROJECTION, *PROJECTION_ROLES)
    units = {name: 'examples/hia_bootstrap/' + name.replace('-', '_') + '.hepta' for name in names}
    inputs = {**units, 'linker': STATIC_LINKER, 'embedder': EMBED_SOURCE, 'adapter-templates': COMPONENT_TEMPLATES}
    sources = {name: (ROOT / name).read_bytes() for name in (*inputs.values(), PROJECTION_ADAPTER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('projection build source differs from admitted cold source')
    folder = output / PROJECTION
    folder.mkdir(mode=0o700)
    captured = compiled_images(folder, compiler, {name: sources[path] for name, path in inputs.items()})
    images = {role: raw for role, (_, raw) in captured.items()}
    embedder, templates = (native_image(images[role]) for role in ('embedder', 'adapter-templates'))
    adapter = load_static_object(templates, ADAPTER_ROLES[PROJECTION_ADAPTER], sources[PROJECTION_ADAPTER])
    objects = [embed(folder, name.removeprefix('sqlite-').replace('-', '_'), name, images[name], embedder)
               for name in names]
    binary, link_receipt = link(folder, images['linker'], images[PROJECTION], (adapter, *objects), wire_magic=b'HIALNK01')
    for name in names:
        verify_executable(binary, images[name])
    if (admit_cold_build(compiler_bytes, cold_bytes) != admitted
            or current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in sources.items())
            or any(path.read_bytes() != raw for path, raw in captured.values())):
        raise ValueError('projection inputs or linked images changed before publication')
    executable = output / ('hia-' + PROJECTION)
    with executable.open('xb') as stream:
        stream.write(binary)
        os.fchmod(stream.fileno(), 0o500)
    return {'name': executable.name, 'sha256': digest(binary), 'bytes': len(binary),
            'source_sha256': {name: digest(raw) for name, raw in sources.items()},
            'image_sha256': {name: digest(raw) for name, raw in images.items()},
            'link_receipt': link_receipt}


def build(output, compiler, cold_report, *, projection_only=False):
    if projection_only:
        compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
        admitted = admit_cold_build(compiler_bytes, report_bytes)
        output.mkdir(mode=0o700)
        report = {'compiler_sha256': digest(compiler_bytes), 'cold_report_sha256': digest(report_bytes),
                  'executable_manifest': {}, 'runtime_python_or_libc': False, 'agent_store_replaced': False}
    else:
        report, admitted = build_executables(output, compiler, cold_report, UNITS, (START, INPUT), ())
    projection = build_projection(output, compiler, cold_report, admitted)
    if projection_only:
        report['source_sha256'] = projection['source_sha256']
        if compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes:
            raise ValueError('SQLite projection cold inputs changed before publication')
    report['executable_manifest'][PROJECTION] = projection
    report.update(schema='hepta.hia.sqlite-component-process-build.v1',
                  status='NATIVE_SQLITE_COMPONENT_PROCESSES_BUILT')
    write_new(output / 'build.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + arg, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
