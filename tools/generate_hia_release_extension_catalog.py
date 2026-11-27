"""Keep the current release catalog equal to the registered native DAGs.

The original fourteen stage groups retain every complete row. Additional DAGs
receive separate stage identities and are inserted in actual execution order.
This development author does not change the installed native release executor.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.hia_native_release_dependencies import (
    TABLE, PROGRAMS, read_recipe, read_source_table, registered_dags,
    release_dependencies, check_source_files,
)

ROOT = Path(__file__).resolve().parents[1]
BASE_GROUPS = {
    'safe': (1,), 'constructor': (2,), 'core': (3,),
    'additional': tuple(range(4, 11)),
    'controller': (11,), 'runtime': (12,), 'future': (13,),
    'generation_lease': (14,),
}
INITIAL_PRODUCTS = frozenset(('hia-source-build', 'hia-elf-link', 'selfhost.image.bin'))
PREFIX = 'native-release-dag-'


def imports(raw):
    """Read import records only after the whole recipe passed its decoder."""
    read_recipe(raw)
    cursor, found = 24, []
    for _ in range(struct.unpack_from('<Q', raw, 8)[0]):
        op, identity, argc, size = struct.unpack_from('<4Q', raw, cursor)
        cursor += 32 + argc * 8
        payload = raw[cursor:cursor + size]
        cursor += size
        if op == 11:
            if argc or not payload:
                raise ValueError('invalid extension product import')
            name = payload.decode('ascii')
            if name not in found:
                found.append(name)
    return tuple(found)


def generated_table(root=ROOT, *, source_table=None):
    root = Path(root)
    before = (root / TABLE).read_bytes() if source_table is None else source_table
    read_source_table(before)
    names = registered_dags(root)
    if tuple(name for name in names if name in BASE_GROUPS) != tuple(BASE_GROUPS):
        raise ValueError('original release DAG order changed')
    grouped = defaultdict(list)
    for line in before.decode('ascii').splitlines()[1:]:
        grouped[int(line.split('\t')[1])].append(line)
    if not set(range(1, 15)) <= set(grouped):
        raise ValueError('original release stage group missing')
    extra_names = tuple(name for name in names if name not in BASE_GROUPS)
    for number, rows in grouped.items():
        if number <= 14:
            continue
        markers = [row.split('\t')[2] for row in rows if row.startswith('stage\t')]
        if len(markers) != 1 or markers[0] not in {PREFIX + name for name in extra_names}:
            raise ValueError('unrecognized stage must not be discarded')
    records, publications, producers, stages = [], [], {}, {}
    next_stage = 15
    for name in names:
        path = PROGRAMS + 'release_stage_' + name + '.hiastd'
        raw = (root / path).read_bytes()
        decoded = read_recipe(raw)
        if name in BASE_GROUPS:
            selected = [row for number in BASE_GROUPS[name] for row in grouped[number]]
            actual = [row.split('\t')[2] for row in selected if row.startswith('output\t')]
            if actual != decoded['publications']:
                raise ValueError('original stage publications differ from their actual DAG: ' + name)
        else:
            number = next_stage
            next_stage += 1
            stages[name] = number
            selected = [f'stage\t{number}\t{PREFIX}{name}']
            for product in imports(raw):
                producer = producers.get(product, 0 if product in INITIAL_PRODUCTS else None)
                if producer is None:
                    raise ValueError('extension imports a product not yet published: ' + product)
                selected.append(f'need\t{number}\t{producer}\t{product}')
            selected.extend(f'resource\t{number}\t{source}'
                            for source in sorted(set(decoded['sources']) | {path}))
            selected.extend(f'output\t{number}\t{product}'
                            for product in decoded['publications'])
            selected.append(f'framing\t{number}\t0\tHIASTD01\tsource-bound-native-release-dag')
        records.extend(selected)
        for row in selected:
            columns = row.split('\t')
            if columns[0] == 'output':
                if columns[2] in producers:
                    raise ValueError('duplicate current publication')
                producers[columns[2]] = int(columns[1])
                publications.append(columns[2])
    maximum = max(int(row.split('\t')[1]) for row in records)
    header = f'stage\t{maximum}\t{len(publications)}'
    result = ('\n'.join([header, *records]) + '\n').encode('ascii')
    if len(result) > 262144:
        raise ValueError('current catalog exceeds the original table byte budget')
    checked = read_source_table(result)
    if checked['publications'] != publications:
        raise ValueError('current catalog publication order differs')
    # Compare every original group's complete rows, including their order.
    for number in range(1, 15):
        if [row for row in records if int(row.split('\t')[1]) == number] != grouped[number]:
            raise ValueError('an original stage row changed')
    return result, {'registered_dags': list(names), 'extension_stages': stages,
                    'stages': maximum, 'publications': len(publications),
                    'original_fourteen_groups_unchanged': True,
                    'input_sha256': sha256(before).hexdigest(),
                    'output_sha256': sha256(result).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw, report = generated_table(args.source)
    path = args.source / TABLE
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit('current release extension catalog differs')
    else:
        path.write_bytes(raw)
    dependencies = release_dependencies(args.source)
    check_source_files(args.source, dependencies['required_sources'])
    report.update(required_sources=len(dependencies['required_sources']),
                  catalog_closed=True, native_execution_qualified=False)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
