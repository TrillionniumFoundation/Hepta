"""Check the source and publication closure of the registered native release DAGs.

This is a development check. The installed release owner consumes the checked-in
HIASTD01 data directly and does not import Python. Catalog closure does not claim
a cold build, installed reconstruction, or whole release qualification.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import struct

from tools.hia_native_worker_source_authority import checked_paths, load_native_source_authority

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = 'examples/hia_bootstrap/'
OWNER = 'tools/generate_hia_release_owner.py'
TABLE = PROGRAMS + 'release_stage_sources.tsv'
AUTHORITY = 'docs/HIA_NATIVE_SOURCE_AUTHORITY.json'
COLD_FILES = 'docs/HIA_COLD_NATIVE_SOURCE_FILES.json'
CAPTURE_TAGS = {int.from_bytes(x, 'little') for x in (b'HIANAM01', b'HIARAW01', b'HIAKOBJ1')}


def registered_dags(root):
    """Read the explicit registration without importing its development author."""
    module = ast.parse((Path(root) / OWNER).read_text('utf-8'))
    assignments = [node.value for node in module.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'RELEASE_DAGS'
                           for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError('release owner must have one explicit RELEASE_DAGS registration')
    names = ast.literal_eval(assignments[0])
    if (type(names) not in (tuple, list) or not 1 <= len(names) <= 512
            or any(type(name) is not str or not re.fullmatch('[a-z][a-z0-9_]*', name) for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('invalid native release DAG registration')
    return tuple(names)


def source_path(raw):
    try:
        path = raw.decode('ascii') if isinstance(raw, bytes) else raw
        return checked_paths([path])[0]
    except (ValueError, UnicodeError) as exc:
        raise ValueError('invalid captured native source path') from exc


def product_name(raw):
    try:
        name = raw.decode('ascii') if isinstance(raw, bytes) else raw
    except UnicodeError as exc:
        raise ValueError('non-ASCII release publication') from exc
    if (not isinstance(name, str) or not 1 <= len(name) <= 255
            or name in ('.', '..') or '/' in name or '\\' in name
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in name)):
        raise ValueError('invalid native release publication name')
    return name


def capture_paths(raw):
    if len(raw) < 8:
        raise ValueError('truncated native source capture')
    count, = struct.unpack_from('<Q', raw)
    if not 1 <= count <= 128:
        raise ValueError('invalid native source capture count')
    cursor = 8
    paths = []
    aliases = set()
    for _ in range(count):
        if len(raw) - cursor < 16:
            raise ValueError('truncated native source capture row')
        alias_size, path_size = struct.unpack_from('<2Q', raw, cursor)
        cursor += 16
        if (not 1 <= alias_size <= 127 or not 1 <= path_size <= 4095
                or alias_size + path_size > len(raw) - cursor):
            raise ValueError('invalid native source capture extent')
        alias = raw[cursor:cursor + alias_size]
        if alias in aliases or any(ch < 33 or ch > 126 for ch in alias):
            raise ValueError('invalid or duplicate native capture alias')
        aliases.add(alias)
        paths.append(source_path(raw[cursor + alias_size:cursor + alias_size + path_size]))
        cursor += alias_size + path_size
    if cursor != len(raw):
        raise ValueError('trailing native source capture bytes')
    return tuple(paths)


def read_recipe(raw):
    """Decode actual retained HIASTD01 data, including every capture/publication."""
    if not 24 <= len(raw) <= 1048576:
        raise ValueError('invalid native release recipe extent')
    magic, nodes, count = struct.unpack_from('<8s2Q', raw)
    if magic != b'HIASTD01' or not 1 <= nodes <= 8192 or count > 512:
        raise ValueError('invalid native release recipe header')
    cursor = 24
    sources, publications, identities = set(), [], set()
    for _ in range(nodes):
        if len(raw) - cursor < 32:
            raise ValueError('truncated native release node')
        op, identity, argc, size = struct.unpack_from('<4Q', raw, cursor)
        cursor += 32
        if (not 1 <= op <= 19 or argc > 132 or size > 1048576
                or argc * 8 + size > len(raw) - cursor):
            raise ValueError('invalid native release node extent')
        if 7 <= op <= 10:
            if identity != 0:
                raise ValueError('native release effect has an identity')
        else:
            if not 1 <= identity <= 2048 or identity in identities:
                raise ValueError('invalid or repeated native release identity')
            identities.add(identity)
        args = struct.unpack_from('<' + 'Q' * argc, raw, cursor)
        cursor += argc * 8
        payload = raw[cursor:cursor + size]
        cursor += size
        if op == 1:
            if argc != 1 or args[0] not in CAPTURE_TAGS:
                raise ValueError('invalid native source capture operation')
            sources.update(capture_paths(payload))
        elif op == 7:
            if argc != 2:
                raise ValueError('invalid native publication operation')
            publications.append(product_name(payload))
    if cursor != len(raw) or len(publications) != count:
        raise ValueError('native release recipe extent or publication count mismatch')
    if len(set(publications)) != len(publications):
        raise ValueError('duplicate native release publication')
    return {'nodes': nodes, 'publications': publications, 'sources': sorted(sources),
            'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def read_source_table(raw):
    try:
        rows = [line.split('\t') for line in raw.decode('ascii').splitlines()]
        if not rows or len(rows[0]) != 3 or rows[0][0] != 'stage':
            raise ValueError('missing native release source table header')
        stages, output_count = int(rows[0][1]), int(rows[0][2])
        if not 1 <= stages <= 512 or not 1 <= output_count <= 512:
            raise ValueError('invalid native release source table count')
        widths = {'stage': 3, 'need': 4, 'compile': 5, 'kit': 4,
                  'resource': 3, 'output': 3, 'framing': 5}
        sources, outputs, seen_stages = set(), [], set()
        for row in rows[1:]:
            if row[0] not in widths or len(row) != widths[row[0]]:
                raise ValueError('invalid native release source table row')
            stage = int(row[1])
            if not 1 <= stage <= stages:
                raise ValueError('native release source table stage out of range')
            seen_stages.add(stage)
            if row[0] == 'compile':
                sources.add(source_path(PROGRAMS + row[4]))
            elif row[0] == 'kit':
                sources.update(source_path(PROGRAMS + path) for path in row[2:4])
            elif row[0] == 'resource':
                sources.add(source_path(row[2]))
            elif row[0] == 'output':
                outputs.append(product_name(row[2]))
        if seen_stages != set(range(1, stages + 1)):
            raise ValueError('native release source table omits a stage')
        if len(outputs) != output_count or len(set(outputs)) != len(outputs):
            raise ValueError('native release source table output count mismatch')
        return {'stages': stages, 'publications': outputs, 'sources': sorted(sources),
                'sha256': sha256(raw).hexdigest()}
    except (UnicodeError, IndexError) as exc:
        raise ValueError('invalid native release source table') from exc


def host_custody_metadata(root, required):
    """Report identity-only data separately from executable native sources."""
    from tools.hia_core_host_custody import ARCHIVE_PATH, DECODER_SOURCE, metadata
    if ARCHIVE_PATH not in required:
        return []
    if DECODER_SOURCE not in required:
        raise ValueError('Core host identity data has no captured native decoder')
    raw = (Path(root) / ARCHIVE_PATH).read_bytes()
    return [{'schema': 'hepta.hia.complete-host-identity-data.v1',
             'path': ARCHIVE_PATH, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
             'decoder': DECODER_SOURCE, 'records': metadata(raw),
             'use': 'complete byte identity inputs for the original eight-field Core manifests',
             'compiled_or_executed': False}]


def release_dependencies(root, *, names=None):
    root = Path(root)
    names = registered_dags(root) if names is None else names
    table = read_source_table((root / TABLE).read_bytes())
    required = set(table['sources']) | {TABLE, PROGRAMS + 'release_owner.hepta',
                                       PROGRAMS + 'release_dag.hepta'}
    publications, recipes = [], []
    for name in names:
        path = source_path(PROGRAMS + 'release_stage_' + name + '.hiastd')
        recipe = read_recipe((root / path).read_bytes())
        required.add(path)
        required.update(recipe['sources'])
        publications.extend(recipe['publications'])
        recipes.append({'name': name, 'path': path, **recipe})
    if publications != table['publications']:
        absent = sorted(set(table['publications']) - set(publications))
        extra = sorted(set(publications) - set(table['publications']))
        raise ValueError('registered native release DAG publications differ from source table: '
                         f'{len(publications)} actual / {len(table["publications"])} declared; '
                         f'missing={absent!r}; extra={extra!r}; publication order is binding')
    return {'schema': 'hepta.hia.native-release-dependencies.v1',
            'registered_dags': list(names), 'declared_stages': table['stages'],
            'publication_count': len(publications), 'publications': publications,
            'source_table_sha256': table['sha256'], 'recipes': recipes,
            'custody_data': host_custody_metadata(root, required),
            'required_sources': list(checked_paths(sorted(required)))}


def load_cold_files(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate cold native source inventory field')
            result[key] = value
        return result
    value = json.loads(Path(path).read_bytes(), object_pairs_hook=unique_object)
    if (type(value) is not dict or set(value) != {'schema', 'mode', 'files'}
            or value['schema'] != 'hepta.hia.native-source-files.v1'
            or value['mode'] != 'native_only'):
        raise ValueError('invalid cold native source inventory schema')
    return checked_paths(value['files'])


def check_authorities(root, required):
    root = Path(root)
    authority = load_native_source_authority(root / AUTHORITY)
    cold = load_cold_files(root / COLD_FILES)
    missing = {AUTHORITY: sorted(set(required) - set(authority)),
               COLD_FILES: sorted(set(required) - set(cold))}
    if any(missing.values()):
        raise ValueError('native release source dependencies absent from authority: '
                         + json.dumps(missing, sort_keys=True))
    return {'native_source_paths': len(authority), 'cold_source_paths': len(cold)}


def synchronize_authorities(root, required):
    root = Path(root)
    authority = checked_paths(sorted(set(load_native_source_authority(root / AUTHORITY)) | set(required)))
    cold = checked_paths(sorted(set(load_cold_files(root / COLD_FILES)) | set(required)))
    # Preserve each catalog's existing scope, including the frozen support contract
    # which the native Worker catalog includes separately from cold source files.
    values = ((AUTHORITY, {'schema': 'hepta.hia.native-source-authority.v1', 'paths': list(authority)}),
              (COLD_FILES, {'schema': 'hepta.hia.native-source-files.v1', 'mode': 'native_only',
                            'files': list(cold)}))
    for path, value in values:
        raw = (json.dumps(value, indent=2) + '\n').encode('ascii')
        if (root / path).read_bytes() != raw:
            (root / path).write_bytes(raw)


def check_source_files(root, required):
    root = Path(root).resolve(strict=True)
    for path in required:
        resolved = (root / path).resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError('native release dependency is not a local source file: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--write', action='store_true',
                        help='add the actual release dependencies to both explicit source catalogs')
    parser.add_argument('--check-source-files', action='store_true',
                        help='also require every dependency to exist within the source checkout')
    args = parser.parse_args()
    report = release_dependencies(args.source)
    if args.check_source_files:
        check_source_files(args.source, report['required_sources'])
    if args.write:
        synchronize_authorities(args.source, report['required_sources'])
    report.update(check_authorities(args.source, report['required_sources']))
    report.update({'source_catalog_closed': True,
                   'source_files_checked': args.check_source_files,
                   'whole_release_passed': False, 'whole_native_only_install_passed': False})
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
