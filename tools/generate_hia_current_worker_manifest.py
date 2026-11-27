"""Author the explicit current Worker manifest protocol and its source-bound table.

The original HIAWMF01/HIAWMT01 source and all 37 historical helper ordinals
remain separate immutable validation inputs. This owner uses protocol 02.
"""
from pathlib import Path
import argparse
import json
from tools.generate_hia_worker_manifest import render

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/source_worker_manifest_current.hepta'
TABLE_PATH = 'examples/hia_bootstrap/worker_manifest_current_tables.hiastd'
MODEL_PATH = 'docs/HIA_WORKER_MANIFEST_CURRENT_RECORDS.json'


def generated_files(native_source_authority=None):
    source, table, spec, stats = render(ROOT, native_source_authority, helper_extensions=True)
    spec.update(source_path=SOURCE_PATH, table_path=TABLE_PATH)
    return {SOURCE_PATH: source.encode('ascii'), TABLE_PATH: table,
            MODEL_PATH: (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode()}, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--native-source-authority', type=Path)
    args = parser.parse_args()
    products, stats = generated_files(args.native_source_authority)
    for name, data in products.items():
        path = ROOT / name
        if args.check:
            if path.read_bytes() != data:
                raise SystemExit('current Worker manifest source differs: ' + name)
        else:
            path.write_bytes(data)
    print(json.dumps(stats, sort_keys=True))


if __name__ == '__main__':
    main()
