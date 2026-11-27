"""Author the independent eight-publication HIAHLM03 Agent helper release DAG."""
from pathlib import Path
import struct

from tools.generate_hia_source_agent_helper_manifest import (
    AGENT_HELPERS, STAGE_OPERATION, CHECK_MODE)
from tools.generate_hia_helper_extension_recipe import HelperExtensionRecipe

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/release_stage_agent_helpers.hiastd'


class AgentHelperRecipe(HelperExtensionRecipe):
    def agent_frame(self, planner, role, parts):
        header = struct.pack('<8s5Q', b'HIASTF01', 4, STAGE_OPERATION,
                             role, 0, len(parts))
        return self.run(planner, self.packet(header, parts))

    def agent_check(self, planner, role, manifest, source, image, compiler):
        parts = (manifest, source, image, compiler)
        request = self.packet(struct.pack('<8s4Q', b'HIASTC01',
                                          CHECK_MODE, role, 4, 0), parts)
        observed = self.run(planner, request)
        expected = self.node(16, (self.literal(struct.pack('<8s2Q', b'HIASTOK1',
                                                           CHECK_MODE, role)),
                                  self.length(manifest)))
        self.node(8, (observed, expected))


def recipe():
    r = AgentHelperRecipe()
    author, kit_sources, _ = r.kit('source_agent_helper_manifest.hepta',
                                  'source_build_packer.hepta')
    planner, _, _ = r.kit('source_agent_helper_stage.hepta',
                         'source_build_packer.hepta')
    names = [module + '.hepta' for _, _, module, _, _, _ in AGENT_HELPERS]
    sources, images = r.compile({name: name for name in names})
    compiler = r.import_product('selfhost.image.bin')
    for (role, candidate, module, image_name, schema, core), name in zip(AGENT_HELPERS, names, strict=True):
        source, image = sources[name], images[name]
        request = r.agent_frame(planner, role,
                                [source, image, kit_sources['selfhost.hepta'], compiler])
        manifest = r.run(author, request)
        r.agent_check(planner, role, manifest, source, image, compiler)
        r.publish(candidate + '-manifest.json', manifest)
        r.publish(image_name + '.image.bin', image)
    expected = [name for _, candidate, _, image, _, _ in AGENT_HELPERS
                for name in (candidate + '-manifest.json', image + '.image.bin')]
    if r.published != expected or len(expected) != 8:
        raise ValueError('Agent helper publication inventory differs')
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
            raise SystemExit('native Agent helper release recipe differs')
    else:
        path.write_bytes(raw)
    print(SOURCE_PATH, len(raw))


if __name__ == '__main__':
    main()
