"""Page-specific additions to the existing native Worker installation DAG.

The original Worker stage order and all original Store roles stay with their
owners.  Every copied installed helper is independently recompiled here, and
its canonical manifest is rebuilt by HIA before the Page bundle is published.
"""
from __future__ import annotations

from tools.generate_hia_artifact_page_manifest import TABLE_PATH, REQUEST_MAGIC


def _manifest(recipe, mode, role, *parts):
    if not hasattr(recipe, 'artifact_page_framer'):
        recipe.artifact_page_framer = recipe.leaf('source_artifact_page_manifest.hepta')
        recipe.artifact_page_tables = recipe.source(TABLE_PATH)
    wire = recipe.wire(REQUEST_MAGIC, (mode, role, len(parts) + 1),
                       (*parts, recipe.artifact_page_tables))
    return recipe.run(recipe.artifact_page_framer, wire)


def publish_page(recipe):
    rows = (
        (1, 'policy', 'artifact-page-policy', 'artifact_page'),
        (2, 'wire', 'json-wire', 'json_wire'),
    )
    paths = ['examples/hia_bootstrap/' + source + '.hepta' for _, _, _, source in rows]
    recipe.compile_paths(paths)
    manifests = []
    for (role, name, installed, _), path in zip(rows, paths, strict=True):
        image, source = recipe.compiled[path], recipe.source_views[path]
        manifest = _manifest(recipe, 1, role, source, image, recipe.compiler())
        recipe.node(8, (image, recipe.import_product(installed + '.image.bin')))
        recipe.node(8, (manifest, recipe.import_product(installed + '-manifest.json')))
        recipe.publish('page/' + name + '/' + installed + '.image.bin', image)
        recipe.publish('page/' + name + '/manifest.json', manifest)
        manifests.append(manifest)
    recipe.publish('page/manifest.json', _manifest(recipe, 2, 0, *manifests))


def wrap_page(recipe, scheduling):
    wrapper = _manifest(recipe, 3, 0, scheduling, recipe.import_product('page/manifest.json'))
    recipe.publish('page-worker.json', wrapper)
    return wrapper
