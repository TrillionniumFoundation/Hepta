"""Build the source-bound Linux x86-64 SQLite component subprocesses."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_pager import DRIVER, LINKER, ROOT, assemble, digest, link, write_new
from tools.qualify_hia_selfhost import compile_stage


UNITS = (
    'sqlite-rowid-lookup', 'sqlite-table-walk', 'sqlite-record-layout', 'sqlite-agent-row-import',
    'sqlite-agent-catalog', 'sqlite-agent-import-batch', 'sqlite-agent-cost-sequence',
    'sqlite-agent-artifact-catalog', 'sqlite-migration-plan',
)
START = 'tools/hia_sqlite_component_start.S'
INPUT = 'tools/hia_sqlite_component_input.S'
WRAPPER = 'tools/hia_sqlite_pager_image.S'
COMPONENT_DRIVER = 'tools/build_hia_sqlite_components.py'


def build_executables(output, compiler, cold_report, units, adapters, drivers):
    compiler_bytes = compiler.read_bytes()
    cold_bytes = cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    units = {name: 'examples/hia_bootstrap/' + name.replace('-', '_') + '.hepta'
             for name in units}
    sources = {name: (ROOT / name).read_bytes()
               for name in (LINKER, WRAPPER, DRIVER, COMPONENT_DRIVER,
                            *drivers, *adapters, *units.values())}
    source_hashes = {name: digest(data) for name, data in sources.items()}
    if any(admitted.get(name) != value for name, value in source_hashes.items()):
        raise ValueError('native component source differs from admitted cold source')
    output.mkdir(mode=0o700)
    linker_path, linker_receipt = compile_stage(output, 'linker', compiler, sources[LINKER])
    linker = linker_path.read_bytes()
    if digest(linker) != linker_receipt['produced_sha256']:
        raise ValueError('native component linker identity changed')
    adapters = tuple(assemble(output, name, sources[name]) for name in adapters)

    products = {}
    for name, source in units.items():
        directory = output / name
        directory.mkdir(mode=0o700)
        path, receipt = compile_stage(directory, name, compiler, sources[source])
        image = path.read_bytes()
        if digest(image) != receipt['produced_sha256']:
            raise ValueError('native component image identity changed')
        included = directory / 'pager_read_owner.image.bin'
        write_new(included, image)
        component = assemble(directory, WRAPPER, sources[WRAPPER])
        binary, _ = link(directory, linker, image, (*adapters, component))
        if path.read_bytes() != image or included.read_bytes() != image:
            raise ValueError('native component changed during executable link')
        products[name] = binary

    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or linker_path.read_bytes() != linker
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


def build(output, compiler, cold_report):
    report, _ = build_executables(output, compiler, cold_report, UNITS, (START, INPUT), ())
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
