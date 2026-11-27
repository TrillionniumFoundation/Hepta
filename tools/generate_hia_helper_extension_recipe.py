"""Author the isolated native DAG for the four HIAHLM02 helper extensions."""
from pathlib import Path
import struct

from tools.build_hia_worker_release import EXTENDED_INSTALLED_HELPERS
from tools.build_hia_json_preflight import CANDIDATES
from tools.generate_hia_release_stage_recipes import Recipe

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/release_stage_helper_extensions.hiastd'


class HelperExtensionRecipe(Recipe):
    def __init__(self):
        super().__init__()
        self.lengths = {}

    def length(self, view):
        if view not in self.lengths:
            self.lengths[view] = self.node(17, (view,))
        return self.lengths[view]

    def packet(self, header, parts):
        views = [self.literal(header)]
        for part in parts:
            views.extend((self.length(part), part))
        return self.node(16, views)

    def extension_frame(self, planner, role, parts):
        header = struct.pack('<8s5Q', b'HIASTF01', 4, 2, role, 0, len(parts))
        return self.run(planner, self.packet(header, parts))

    def extension_check(self, planner, role, manifest, source, image, compiler):
        parts = (manifest, source, image, compiler)
        request = self.packet(struct.pack('<8s4Q', b'HIASTC01', 13, role, 4, 0), parts)
        observed = self.run(planner, request)
        expected = self.node(16, (self.literal(struct.pack('<8s2Q', b'HIASTOK1', 13, role)),
                                  self.length(manifest)))
        self.node(8, (observed, expected))


def recipe():
    r = HelperExtensionRecipe()
    author, kit_sources, _ = r.kit('source_helper_manifest.hepta', 'source_build_packer.hepta')
    planner, _, _ = r.kit('source_helper_extension_stage.hepta', 'source_build_packer.hepta')
    names = [CANDIDATES[kind][0] + '.hepta' for _, kind in EXTENDED_INSTALLED_HELPERS]
    sources, images = r.compile({name: name for name in names})
    compiler = r.import_product('selfhost.image.bin')
    for (role, kind), name in zip(EXTENDED_INSTALLED_HELPERS, names, strict=True):
        source, image = sources[name], images[name]
        request = r.extension_frame(planner, role,
                                    [source, image, kit_sources['selfhost.hepta'], compiler])
        manifest = r.run(author, request)
        r.extension_check(planner, role, manifest, source, image, compiler)
        r.publish(kind + '-manifest.json', manifest)
        r.publish(CANDIDATES[kind][1] + '.image.bin', image)
    expected = [name for _, kind in EXTENDED_INSTALLED_HELPERS
                for name in (kind + '-manifest.json', CANDIDATES[kind][1] + '.image.bin')]
    if r.published != expected or len(expected) != 8:
        raise ValueError('helper extension publication inventory differs')
    return r


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = recipe().binary()
    path = ROOT / SOURCE_PATH
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit('native helper extension recipe differs')
    else:
        path.write_bytes(raw)
    print(SOURCE_PATH, len(raw))


if __name__ == '__main__':
    main()
