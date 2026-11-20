"""Build the source-bound native publisher for a prepared SQLite migration."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_components import compiled_images, native_image
from tools.build_hia_sqlite_pager import (
    EMBED_SOURCE, ROOT, STATIC_LINKER, digest, embed, link, load_static_object, verify_executable, write_new,
)


UNITS = {
    'sqlite-migration-publish': 'examples/hia_bootstrap/sqlite_migration_publish.hepta',
    'sqlite-agent-artifact-catalog': 'examples/hia_bootstrap/sqlite_agent_artifact_catalog.hepta',
    'linker': STATIC_LINKER,
    'embedder': EMBED_SOURCE,
}
ADAPTER = 'tools/hia_sqlite_migration_publish.S'
MIGRATION_TEMPLATES = 'examples/hia_bootstrap/sqlite_migration_adapters.hepta'
PUBLISH_ROLE = 0
MIGRATE_ROLE = 1
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
    sources = {path: (ROOT / path).read_bytes() for path in (*UNITS.values(), MIGRATION_TEMPLATES, ADAPTER, DRIVER)}
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
    inputs = {**UNITS, 'templates': MIGRATION_TEMPLATES}
    captured = compiled_images(output, compiler, {name: sources[path] for name, path in inputs.items()})
    checks.extend(captured.values())
    images = {name: raw for name, (_, raw) in captured.items()}
    adapter = load_static_object(native_image(images['templates']), PUBLISH_ROLE, sources[ADAPTER])
    owner = images['sqlite-migration-publish']
    embedded = {'migration_publish': owner, 'migration_artifact_catalog': images['sqlite-agent-artifact-catalog'],
                'migration_artifact': dependencies['hia-artifact'],
                'migration_writer': dependencies['hia-agent-batch-commit']}
    embedder = native_image(images['embedder'])
    objects = [embed(output, name, name, raw, embedder) for name, raw in embedded.items()]
    binary, receipt = link(output, images['linker'], owner, (adapter, *objects), wire_magic=b'HIALNK01')
    for raw in embedded.values():
        verify_executable(binary, raw)
    if (current_sources() != admitted or any(path.read_bytes() != raw for path, raw in checks)
            or any((ROOT / path).read_bytes() != raw for path, raw in sources.items())):
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
