"""Author the native DAG for the four explicit HIAHLM02 helper extensions."""
from pathlib import Path
from tools.build_hia_worker_release import EXTENDED_INSTALLED_HELPERS
from tools.build_hia_json_preflight import CANDIDATES
from tools.generate_hia_release_stage_recipes import Recipe

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/release_stage_helper_extensions.hiastd'


def recipe():
    r = Recipe()
    author, kit_sources, _ = r.kit('source_helper_manifest.hepta', 'source_build_packer.hepta')
    names = [CANDIDATES[kind][0] + '.hepta' for _, kind in EXTENDED_INSTALLED_HELPERS]
    sources, images = r.compile({name: name for name in names})
    compiler = r.import_product('selfhost.image.bin')
    for (role, kind), name in zip(EXTENDED_INSTALLED_HELPERS, names, strict=True):
        source, image = sources[name], images[name]
        manifest = r.frame_run(author, 4, 2, role,
                               [source, image, kit_sources['selfhost.hepta'], compiler])
        r.node(10, (13, role, manifest, source, image, compiler))
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
