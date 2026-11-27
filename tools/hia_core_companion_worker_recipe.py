"""Native Core additions to the existing closed Worker installation DAG."""
from __future__ import annotations

import struct

from tools.hia_core_companion_release import COMPANIONS, OWNER, CHECKER, inputs
from tools.generate_hia_core_companion_worker_manifest import REQUEST_MAGIC, TABLE_PATH


def publish_core(recipe):
    paths = [inputs(family)[0] for _, family in COMPANIONS]
    recipe.compile_paths(paths)
    owner = recipe.leaf(OWNER)
    checker = recipe.leaf(CHECKER)
    selfhost = recipe.source("examples/hia_bootstrap/selfhost.hepta")
    compiler = recipe.compiler()
    for role, family in COMPANIONS:
        path = inputs(family)[0]
        source, image = recipe.source_views[path], recipe.compiled[path]
        abi, bridge, selection = (recipe.source(name) for name in inputs(family)[1:])
        parts = (source, image, selfhost, compiler, abi, bridge, selection)
        request = recipe.concat(
            recipe.literal(struct.pack("<8sQ", b"HIACCM01", role)),
            *(recipe.length(part) for part in parts), *parts)
        manifest = recipe.run(owner, request)
        result = recipe.run(checker, recipe.wire(
            b"HIASTC01", (14, role, 7, 0),
            (manifest, source, image, compiler, abi, bridge, selection)))
        expected = recipe.concat(recipe.literal(struct.pack("<8s2Q", b"HIASTOK1", 14, role)),
                                 recipe.length(manifest))
        recipe.node(8, (result, expected))
        recipe.node(8, (image, recipe.import_product("core-" + family + ".image.bin")))
        recipe.node(8, (manifest, recipe.import_product("core-" + family + "-manifest.json")))
        recipe.publish("core/" + family + "/core-" + family + ".image.bin", image)
        recipe.publish("core/" + family + "/manifest.json", manifest)


def wrap_core(recipe, page):
    framer = recipe.leaf("source_core_companion_worker_manifest.hepta")
    parts = (page, *(recipe.import_product("core/" + family + "/manifest.json")
                     for _, family in COMPANIONS), recipe.compiler(), recipe.source(TABLE_PATH))
    wire = recipe.wire(REQUEST_MAGIC, (2, 0, len(parts)), parts)
    wrapper = recipe.run(framer, wire)
    recipe.publish("core-worker.json", wrapper)
    return wrapper
