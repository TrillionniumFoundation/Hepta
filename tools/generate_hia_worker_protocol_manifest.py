"""Generate one explicit native Worker manifest protocol.

Protocol 03 is the current product. The other protocols are generated into
separate source domains for complete real compatibility installations.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json

from tools.generate_hia_worker_manifest import render
from tools.hia_worker_protocols import PROTOCOLS, protocol as selected_protocol

ROOT = Path(__file__).resolve().parents[1]


def generated_files(native_source_authority=None, *, protocol="03"):
    selected = selected_protocol(protocol)
    source, table, spec, stats = render(
        ROOT, native_source_authority, protocol=protocol)
    files = {
        selected.manifest_source: source.encode("ascii"),
        selected.manifest_table: table,
        selected.manifest_spec: (json.dumps(spec, sort_keys=True, indent=2) + "\n").encode(),
    }
    return files, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--protocol", choices=PROTOCOLS, default="03")
    parser.add_argument("--native-source-authority", type=Path)
    args = parser.parse_args()
    files, stats = generated_files(args.native_source_authority, protocol=args.protocol)
    for name, raw in files.items():
        path = ROOT / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit("Worker protocol source differs: " + name)
        else:
            path.write_bytes(raw)
    print(json.dumps(dict(protocol=args.protocol, **stats), sort_keys=True))


if __name__ == "__main__":
    main()
