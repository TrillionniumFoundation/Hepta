"""Author the closed HIA Page manifest and Worker-composition byte owner.

Production consumes the emitted HIA and its exact native table.  The scheduler
base is opaque here: this owner binds all of its bytes, while the unchanged
scheduler and Store owners retain their independent admission rules.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.generate_hia_worker_manifest import Recipe, image_recipe, POLICY_SOURCE, sha_source
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from hepta.hia_agent_assembly import render_assembly

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/source_artifact_page_manifest.hepta'
TABLE_PATH = 'examples/hia_bootstrap/artifact_page_manifest_tables.hiastd'
MODEL_PATH = 'docs/HIA_ARTIFACT_PAGE_MANIFEST_RECORDS.json'
REQUEST_MAGIC = b'HIAPMF01'
TABLE_MAGIC = b'HIAPMT01'
POLICY_SCHEMA = 'hepta.hia.artifact-page-native.v2'
BUNDLE_SCHEMA = 'hepta.hia.artifact-page-bundle.v2'
WORKER_SCHEMA = 'hepta.hia.artifact-page-worker-bundle.v1'
TARGET = 'linux-x86_64-lp64'
ABI = 'hia-byte-six-argument-v1'


def recipes():
    entries = [
        image_recipe(1, 1, POLICY_SCHEMA, 'artifact-page-policy.image.bin',
                     'page/policy/manifest.json'),
        image_recipe(1, 2, 'hepta.hia.json-wire-native.v1', 'json-wire.image.bin',
                     'page/wire/manifest.json'),
    ]
    page = Recipe(2, 0, ['policy_manifest', 'wire_manifest'],
                  output_path='page/manifest.json')
    for index in range(2):
        page.bounds(index, 1, 8192)
        page.child(index, 1, index + 1)
    page.same_compiler(0, 1)
    page.json(dict(schema=BUNDLE_SCHEMA, policy_manifest='policy/manifest.json',
                   policy_manifest_sha256=page.digest(0), wire_manifest='wire/manifest.json',
                   wire_manifest_sha256=page.digest(1)))
    entries.append(page)
    wrapper = Recipe(3, 0, ['scheduler_base', 'page_manifest'],
                     output_path='page-worker.json')
    wrapper.bounds(0, 2, 65536)
    wrapper.bounds(1, 1, 8192)
    wrapper.child(1, 2, 0)
    wrapper.json(dict(schema=WORKER_SCHEMA, target=TARGET, abi=ABI,
                      base_bundle='schedulers.json', base_bundle_sha256=wrapper.digest(0),
                      page_bundle='page/manifest.json', page_bundle_sha256=wrapper.digest(1)))
    entries.append(wrapper)
    return entries


def render():
    entries = recipes()
    for entry in entries:
        if (len(entry.slots) > 512 or not 1 <= len(entry.operations) <= 4096
                or len(entry.validators) > 512):
            raise ValueError('Page manifest exceeds the original native table budgets')
    payload = b''.join(entry.encode() for entry in entries)
    table = struct.pack('<8s3Q', TABLE_MAGIC, 1, len(entries), 32 + len(payload)) + payload
    if len(table) > 1048576:
        raise ValueError('Page manifest table exceeds the original 1 MiB budget')
    pin = sha256(table).digest()
    source = POLICY_SOURCE
    for name, value in dict(MAGIC_REQUEST=REQUEST_MAGIC, MAGIC_TABLE=TABLE_MAGIC,
                            MAGIC_SPI=b'HIASPI01', MAGIC_INPROCESS=b'HIAINP01').items():
        source = source.replace(name, str(int.from_bytes(value, 'little')))
    source += '\ndef table_pin(o:mutbuf) -> u64:\n'
    for offset in range(0, 32, 8):
        source += f'    if get(o, {offset}) != {int.from_bytes(pin[offset:offset+8], "little")}:\n        return 0\n'
    source += '    return 1\n' + sha_source()
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('Page manifest author has duplicate function names')
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(a) for a in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v9',
        module='source_artifact_page_manifest', functions=functions))
    raw = render_assembly(document).encode()
    spec = dict(schema='hepta.hia.artifact-page-manifest-records.v1',
        request=REQUEST_MAGIC.decode(), source_path=SOURCE_PATH, source_bytes=len(raw),
        source_sha256=sha256(raw).hexdigest(), table_path=TABLE_PATH,
        table_bytes=len(table), table_sha256=pin.hex(),
        scheduler_admission='opaque exact bytes; the scheduler owner independently validates the bound base',
        records=[dict(mode=e.mode, role=e.role, pieces=[*e.pieces, 'tables'],
            output=e.output_path, slot_count=len(e.slots),
            validator_count=len(e.validators)) for e in entries])
    return raw, table, spec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    source, table, spec = render()
    for name, raw in ((SOURCE_PATH, source), (TABLE_PATH, table),
                      (MODEL_PATH, (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode())):
        path = ROOT / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit('generated Page manifest source differs: ' + name)
        else:
            path.write_bytes(raw)
        print(json.dumps(dict(path=name, bytes=len(raw), sha256=sha256(raw).hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
