"""Author the native HIASTD01 Core companion release DAG."""
from __future__ import annotations

import argparse
from pathlib import Path
import struct

from tools.generate_hia_release_stage_recipes import Recipe
from tools.hia_core_companion_release import COMPANIONS, OWNER, CHECKER, inputs
from tools.hia_core_host_custody import ARCHIVE_PATH, DECODER_SOURCE, REQUEST_MAGIC

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "examples/hia_bootstrap/release_stage_core_companions.hiastd"


class CoreCompanionRecipe(Recipe):
    def __init__(self):
        super().__init__()
        self.lengths = {}

    def length(self, view):
        if view not in self.lengths:
            self.lengths[view] = self.node(17, (view,))
        return self.lengths[view]

    def manifest_request(self, role, parts):
        return self.node(16, (self.literal(struct.pack("<8sQ", b"HIACCM01", role)),
                              *(self.length(part) for part in parts), *parts))

    def check(self, checker, role, parts):
        views = [self.literal(struct.pack("<8s4Q", b"HIASTC01", 14, role, 7, 0))]
        for part in parts:
            views.extend((self.length(part), part))
        observed = self.run(checker, self.node(16, views))
        expected = self.node(16, (self.literal(struct.pack("<8s2Q", b"HIASTOK1", 14, role)),
                                  self.length(parts[0])))
        self.node(8, (observed, expected))


def recipe():
    r = CoreCompanionRecipe()
    author, author_sources, _ = r.kit(OWNER, "source_build_packer.hepta")
    checker, _, _ = r.kit(CHECKER, "source_build_packer.hepta")
    decoder, _, _ = r.kit(DECODER_SOURCE, "source_build_packer.hepta")
    custody = r.source(ARCHIVE_PATH)
    names = {"core_" + family + ".hepta": inputs(family)[0] for _, family in COMPANIONS}
    sources, images = r.compile(names)
    compiler = r.import_product("selfhost.image.bin")
    for role, family in COMPANIONS:
        name = "core_" + family + ".hepta"
        source, image = sources[name], images[name]
        abi = r.source(inputs(family)[1])
        bridge, selection = (r.run(decoder, r.node(16, (
            r.literal(struct.pack("<8s2Q", REQUEST_MAGIC, role, kind)), custody)))
            for kind in (1, 2))
        manifest = r.run(author, r.manifest_request(role, (
            source, image, author_sources["selfhost.hepta"], compiler, abi, bridge, selection)))
        r.check(checker, role, (manifest, source, image, compiler, abi, bridge, selection))
        r.publish("core-" + family + "-manifest.json", manifest)
        r.publish("core-" + family + ".image.bin", image)
    expected = [name for _, family in COMPANIONS
                for name in ("core-" + family + "-manifest.json", "core-" + family + ".image.bin")]
    if r.published != expected or len(expected) != 6:
        raise ValueError("Core companion release publication inventory differs")
    return r


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = recipe().binary()
    path = ROOT / SOURCE_PATH
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit("Core companion release DAG differs")
    else:
        path.write_bytes(raw)
    print(SOURCE_PATH, len(raw))


if __name__ == "__main__":
    main()
