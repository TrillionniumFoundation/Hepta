"""Native HIASTD01 release/install-rebuild DAG for the exact NDU leaf."""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import struct

from tools.generate_hia_release_stage_recipes import Recipe
from tools.hia_ndu_evaluator_release import (
    CONTRACT, CONTRACT_SHA256, POLICY, PACKER, PRODUCT, CONTRACT_PRODUCT,
    ROLES, checked_contract,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "examples/hia_bootstrap/release_stage_ndu_evaluator.hiastd"


def recipe():
    r = Recipe()
    raw = (ROOT / CONTRACT).read_bytes()
    contract = checked_contract(raw)
    record = r.source(CONTRACT)
    r.node(9, (record,), bytes.fromhex(CONTRACT_SHA256))
    for name, digest in contract["source_files"].items():
        r.node(9, (r.source(name),), bytes.fromhex(digest))
    author, _, kit_images = r.kit(POLICY, PACKER)
    rows = {row["role"]: row for row in contract["build_inputs"]["modules"]}
    r.node(9, (kit_images["source_build_packer.hepta"],),
           bytes.fromhex(rows["packer"]["flat_sha256"]))
    named = {role + ".hepta": rows[role]["source_path"] for role in ROLES}
    _, images = r.compile(named)
    parts = [images[role + ".hepta"] for role in ROLES]
    for role, image in zip(ROLES, parts, strict=True):
        r.node(9, (image,), bytes.fromhex(rows[role]["flat_sha256"]))
    header = r.literal(b"HIANDP01" + struct.pack("<5Q",
        *(rows[role]["flat_bytes"] for role in ROLES), 0))
    wire = r.node(16, (header, *parts))
    first, second = r.run(author, wire), r.run(author, wire)
    r.node(8, (first, second))
    # The same original sources are re-captured before either publication.
    terminal_record = r.source(CONTRACT)
    r.node(8, (record, terminal_record))
    for name, digest in contract["source_files"].items():
        r.node(9, (r.source(name),), bytes.fromhex(digest))
    r.publish(PRODUCT, first, contract["binary_sha256"])
    r.publish(CONTRACT_PRODUCT, record, CONTRACT_SHA256)
    if r.published != [PRODUCT, CONTRACT_PRODUCT]:
        raise ValueError("NDU publication inventory differs")
    return r


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = recipe().binary()
    path = ROOT / SOURCE_PATH
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit("NDU release DAG differs")
    else:
        path.write_bytes(raw)
    print(SOURCE_PATH, len(raw), sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
