"""Build the native, lock-holding Agent migration coordinator."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_pager import (
    EMBED_SOURCE, ROOT, assemble, build_embedder, digest, embed, link, write_new,
)
from tools.qualify_hia_selfhost import compile_stage


COORDINATOR = 'examples/hia_bootstrap/sqlite_migrate.hepta'
LINKER = 'examples/hia_bootstrap/elf_static_linker.hepta'
ADAPTER = 'tools/hia_sqlite_migrate.S'
DRIVER = 'tools/build_hia_sqlite_migrate.py'
COMPONENTS = (
    ('pager', 'hia-sqlite-pager', 'hepta.hia.sqlite-pager-build.v1'),
    ('staging', 'hia-sqlite-migration-projection', 'hepta.hia.sqlite-component-process-build.v1'),
    ('initializer', 'hia-agent-store-init', 'hepta.hia.agent-store-init-build.v1'),
    ('publisher', 'hia-sqlite-migration-publish', 'hepta.hia.sqlite-migration-publish-build.v1'),
)


def read_component(folder, label, name, schema, compiler_pin, cold_pin, admitted):
    executable, receipt = folder / name, folder / 'build.json'
    raw, metadata = executable.read_bytes(), receipt.read_bytes()
    build = json.loads(metadata)
    sources = build['source_sha256']
    if label == 'staging':
        selected = build['executable_manifest']['sqlite-migration-projection']
        executable_pin = selected['sha256']
        if selected['name'] != name:
            raise ValueError('unexpected staged migration executable')
        sources = selected['source_sha256']
    else:
        executable_pin = build['executable_sha256']
    if (build['schema'] != schema or executable_pin != digest(raw)
            or build['compiler_sha256'] != compiler_pin or build['cold_report_sha256'] != cold_pin
            or not sources or any(admitted.get(path) != pin for path, pin in sources.items())):
        raise ValueError('invalid migration component: ' + name)
    return raw, ((executable, raw), (receipt, metadata))


def build(output, compiler, cold, folders):
    compiler_body, cold_body = compiler.read_bytes(), cold.read_bytes()
    admitted = admit_cold_build(compiler_body, cold_body)
    sources = {name: (ROOT / name).read_bytes() for name in
               (COORDINATOR, LINKER, EMBED_SOURCE, ADAPTER, DRIVER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('migration coordinator source differs from admitted cold source')

    inputs = [(compiler, compiler_body), (cold, cold_body)]
    bodies = {}
    for label, name, schema in COMPONENTS:
        raw, paths = read_component(folders[label], label, name, schema, digest(compiler_body),
                                    digest(cold_body), admitted)
        bodies[label] = raw
        inputs.extend(paths)

    output.mkdir(mode=0o700)
    images = {}
    for label, source in (('sqlite-migrate', COORDINATOR), ('linker', LINKER)):
        image, report = compile_stage(output, label, compiler, sources[source])
        body = image.read_bytes()
        if digest(body) != report['produced_sha256']:
            raise ValueError('migration controller image changed')
        images[label] = body
        inputs.append((image, body))
    embedder = build_embedder(output, compiler, sources[EMBED_SOURCE])
    adapters = [assemble(output, ADAPTER, sources[ADAPTER])]
    for label, name, _ in COMPONENTS:
        raw = bodies[label]
        adapters.append(embed(output, label, name, raw, embedder))
        inputs.append((output / (name + '.embedded.elf'), raw))
    binary, receipt = link(output, images['linker'], images['sqlite-migrate'], adapters, wire_magic=b'HIALNK01')
    if (current_sources() != admitted or any(path.read_bytes() != raw for path, raw in inputs)
            or any((ROOT / path).read_bytes() != raw for path, raw in sources.items())
            or any(binary.count(raw) != 1 for raw in bodies.values())):
        raise ValueError('migration link changed a source or sealed executable')
    executable = output / 'hia-sqlite-migrate'
    with executable.open('xb') as stream:
        stream.write(binary)
        os.fchmod(stream.fileno(), 0o500)
    report = dict(schema='hepta.hia.sqlite-migrate-build.v1', executable_sha256=digest(binary),
                  compiler_sha256=digest(compiler_body), cold_report_sha256=digest(cold_body),
                  source_sha256={name: digest(raw) for name, raw in sources.items()},
                  component_sha256={label: digest(raw) for label, raw in bodies.items()}, link_receipt=receipt)
    write_new(output / 'build.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report', *(label for label, _, _ in COMPONENTS)):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                {label: getattr(args, label).resolve() for label, _, _ in COMPONENTS}))


if __name__ == '__main__':
    main()
