"""Build the source-bound native publisher for a prepared SQLite migration."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_pager import ROOT, assemble, digest, link, write_new
from tools.qualify_hia_selfhost import compile_stage


UNITS = {
    'sqlite-migration-publish': 'examples/hia_bootstrap/sqlite_migration_publish.hepta',
    'sqlite-agent-artifact-catalog': 'examples/hia_bootstrap/sqlite_agent_artifact_catalog.hepta',
    'linker': 'examples/hia_bootstrap/elf_static_linker.hepta',
}
ADAPTER = 'tools/hia_sqlite_migration_publish.S'
DRIVER = 'tools/build_hia_sqlite_migration_publish.py'


def read_dependency(root, program, schema, compiler_pin, cold_pin, sources):
    executable = root / program
    report = root / 'build.json'
    raw, receipt = executable.read_bytes(), report.read_bytes()
    build = json.loads(receipt)
    if (build['schema'] != schema or build['executable_path'] != program
            or build['compiler_sha256'] != compiler_pin or build['cold_report_sha256'] != cold_pin
            or build['executable_sha256'] != digest(raw) or build['executable']['sha256'] != digest(raw)
            or not build['source_sha256']
            or any(sources.get(path) != sha for path, sha in build['source_sha256'].items())):
        raise ValueError('invalid migration dependency: ' + program)
    return raw, (executable, raw), (report, receipt)


def build(output, compiler, cold_report, artifact, writer):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    sources = {path: (ROOT / path).read_bytes() for path in (*UNITS.values(), ADAPTER, DRIVER)}
    if any(admitted.get(path) != digest(raw) for path, raw in sources.items()):
        raise ValueError('publisher build source differs from admitted cold source')
    dependencies = {}
    checks = [(compiler, compiler_bytes), (cold_report, cold_bytes)]
    for folder, program, schema in (
        (artifact, 'hia-artifact', 'hepta.hia.artifact-publication-build.v1'),
        (writer, 'hia-agent-batch-commit', 'hepta.hia.agent-batch-commit-build.v1'),
    ):
        raw, executable, receipt = read_dependency(folder, program, schema, digest(compiler_bytes),
                                                     digest(cold_bytes), admitted)
        dependencies[program] = raw
        checks.extend((executable, receipt))

    output.mkdir(mode=0o700)
    images = {}
    for name, path in UNITS.items():
        image, receipt = compile_stage(output, name, compiler, sources[path])
        body = image.read_bytes()
        if digest(body) != receipt['produced_sha256']:
            raise ValueError('publisher image changed during assembly')
        images[name] = body
        checks.append((image, body))
    for name, raw in dependencies.items():
        path = output / (name + '.embedded.elf')
        write_new(path, raw)
        checks.append((path, raw))
    adapter = assemble(output, ADAPTER, sources[ADAPTER])
    owner = images['sqlite-migration-publish']
    binary, receipt = link(output, images['linker'], owner, (adapter,), wire_magic=b'HIALNK01')
    if (current_sources() != admitted or any(path.read_bytes() != raw for path, raw in checks)
            or any((ROOT / path).read_bytes() != raw for path, raw in sources.items())
            or any(binary.count(raw) != 1 for raw in dependencies.values())
            or binary.count(images['sqlite-agent-artifact-catalog']) != 1):
        raise ValueError('publication build changed a bound source or dependency')
    result = output / 'hia-sqlite-migration-publish'
    with result.open('xb') as stream:
        stream.write(binary)
        os.fchmod(stream.fileno(), 0o500)
    report = dict(schema='hepta.hia.sqlite-migration-publish-build.v1',
                  executable_sha256=digest(binary), compiler_sha256=digest(compiler_bytes),
                  cold_report_sha256=digest(cold_bytes), link_receipt=receipt,
                  dependency_sha256={name: digest(raw) for name, raw in dependencies.items()},
                  source_sha256={name: digest(raw) for name, raw in sources.items()})
    write_new(output / 'build.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report', 'artifact', 'writer'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                args.artifact.resolve(), args.writer.resolve()))


if __name__ == '__main__':
    main()
