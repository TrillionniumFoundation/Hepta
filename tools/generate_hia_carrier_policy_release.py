"""Author stage 19: two HIA lifecycle policies and their native custody record.

Only the HIA release owner executes this DAG. The CPython compatibility ABI is
an explicit host boundary and is neither compiled nor executed by this stage.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.generate_hia_native_controller_release import ControllerRecipe
from tools.hia_native_release_dependencies import read_recipe

ROOT = Path(__file__).resolve().parents[1]
RECIPE = "examples/hia_bootstrap/release_stage_carrier_policies.hiastd"
SOURCES = (
    "examples/hia_bootstrap/carrier_image_policy.hepta",
    "examples/hia_bootstrap/carrier_cell_policy.hepta",
)
OUTPUTS = ("carrier-image-policy.flat", "carrier-cell-policy.flat",
           "carrier-policies.hiadat")
MAGIC = b"HIACPUB1"


def build_recipe():
    recipe = ControllerRecipe()
    recipe.compile_exact(SOURCES)
    compiler = recipe.import_product("selfhost.image.bin")
    seed = recipe.import_product("hia-source-build")
    record = [recipe.literal(struct.pack("<8s3Q", MAGIC, 1, 2, 0)),
              recipe.length(compiler), recipe.digest(compiler),
              recipe.length(seed), recipe.digest(seed)]
    for role, (source_name, output_name) in enumerate(zip(SOURCES, OUTPUTS[:2], strict=True), 1):
        source, image = recipe.source_views[source_name], recipe.compiled[source_name]
        record.extend((recipe.q(role, 0), recipe.length(source), recipe.length(image),
                       recipe.digest(source), recipe.digest(image)))
        recipe.publish(output_name, image)
    custody = recipe.concat(*record)
    recipe.node(8, (recipe.length(custody), recipe.q(304)))
    recipe.publish(OUTPUTS[2], custody)
    raw = recipe.binary()
    checked = read_recipe(raw)
    if (checked["publications"] != list(OUTPUTS)
            or sorted(set(checked["sources"])) != sorted(SOURCES)
            or len(raw) > 1048576 or recipe.next_handle > 2049):
        raise ValueError("carrier stage escaped its two-policy native source domain")
    return recipe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    before = {name: (args.source / name).read_bytes() for name in SOURCES}
    raw = build_recipe().binary()
    if any((args.source / name).read_bytes() != data for name, data in before.items()):
        raise ValueError("carrier policy source changed during authoring")
    path = args.source / RECIPE
    if args.check:
        if path.read_bytes() != raw:
            raise ValueError("carrier native release DAG differs")
    else:
        path.write_bytes(raw)
    if any((args.source / name).read_bytes() != data for name, data in before.items()):
        raise ValueError("carrier policy source changed before authoring completed")
    print(json.dumps({"recipe": RECIPE, "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                      "sources": {name: {"bytes": len(data), "sha256": sha256(data).hexdigest()}
                                  for name, data in before.items()},
                      "products": list(OUTPUTS), "native_execution_qualified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
