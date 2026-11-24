"""Author the source-pinned HIASTD01 Safe proof build recipe.

The release owner consumes the resulting data through its ordinary HIA DAG
interpreter. Compilation, nested packing, verification and publication execute
as native HIA programs. This development generator supplies declarations and
the fixed builtin transport template; it is never invoked by that owner.
The native interpreter must support view operations 16/17 and the checker must
support modes 10/11; unsupported components fail before publication.
"""
from __future__ import annotations

from pathlib import Path
import struct

from tools.generate_hia_release_stage_recipes import Recipe, outputs

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'examples/hia_bootstrap/release_stage_safe.hiastd'


def safe_proof(recipe):
    from tools.build_hia_safe_core_binder import (
        PARTS, MACHINE_PARTS, OBSERVATION_PARTS, OBLIGATION_PARTS)
    from tools.build_hia_supplied_safe_core_proof import HASH_SOURCE
    from tools.generate_hia_core_admission_cli import STATE_BYTES, ARENA_BYTES
    from tools.generate_hia_native_filter import template
    from tools.generate_hia_safe_core_binder_packer import ADAPTER, PACKER, PROOF_PACKER
    from tools.generate_hia_supplied_safe_core_proof import SOURCE_PATH
    from tools.generate_hia_supplied_safe_core_proof_packer import (
        ADAPTER as FINAL_ADAPTER, PACKER as FINAL_PACKER)

    lengths = {}

    def concat(*views):
        assert views
        return recipe.node(16, views)

    def length(view):
        if view not in lengths:
            lengths[view] = recipe.node(17, (view,))
        return lengths[view]

    def record(source, image, *, embedded=False):
        fields = (length(source), length(image), source)
        return concat(*fields) if embedded else concat(*fields, image)

    def request(role, rows):
        return concat(recipe.literal(struct.pack('<8sQ', b'HIASPR01', role)), *rows)

    groups = [('core_admission.hepta', 'core_proof_subject.hepta')]
    groups.extend(tuple(Path(path).name for path in parts.values())
                  for parts in (PARTS, MACHINE_PARTS, OBSERVATION_PARTS, OBLIGATION_PARTS))
    packers = ('core_proof_subject_cli_packer.hepta',
               *(Path(PACKER).name for _ in range(3)), Path(PROOF_PACKER).name)
    outer = (Path(SOURCE_PATH).name, Path(HASH_SOURCE).name)
    final_packer = Path(FINAL_PACKER).name
    names = {*packers, *outer, final_packer, *(name for group in groups for name in group)}
    sources, images = recipe.compile({name: name for name in sorted(names)})
    controllers = {name: recipe.kit('source_safe_proof.hepta', name)[0]
                   for name in dict.fromkeys((*packers, 'native_filter_packer.hepta'))}
    binder_adapter = recipe.source(ADAPTER)
    obligation_adapter = concat(recipe.literal(b'.set proof_transport, 1\n'), binder_adapter)
    prefix, holes = template(output_bytes=STATE_BYTES, workspace_bytes=ARENA_BYTES, formatter=True)
    prefix_view = recipe.literal(prefix)
    holes_view = recipe.literal(struct.pack('<' + 'Q' * len(holes), *holes))
    children = []
    final_rows = [record(sources[name], images[name]) for name in outer]
    for role, (names, packer) in enumerate(zip(groups, packers, strict=True), 1):
        child = recipe.run(controllers[packer], request(role, [record(sources[name], images[name]) for name in names]))
        if role == 1:
            # This template is immutable recipe data. Both actual object extents
            # and the two call targets are checked before the child is retained.
            recipe.node(10, (11, 2, child, prefix_view, holes_view, *(images[name] for name in names)))
        else:
            adapter = obligation_adapter if role == 5 else binder_adapter
            recipe.check_placement(child, sources[packer], adapter, [images[name] for name in names])
        children.append(child)
        final_rows.append(concat(length(child), child))
        final_rows.extend(record(sources[name], images[name], embedded=True) for name in names)

    # Role 6 emits the verified outer frame through the native filter's stdout
    # arena. Role 7 wraps the already compiled final packer as an executable.
    filter_owner = controllers['native_filter_packer.hepta']
    runner = recipe.run(filter_owner, request(7, [record(sources[final_packer], images[final_packer])]))
    frame = recipe.run(filter_owner, request(6, final_rows))
    product = recipe.run(runner, frame, 0)
    parts = [*(images[name] for name in outer), *children]
    recipe.node(10, (10, 3, product, sources[final_packer], recipe.source(FINAL_ADAPTER), *parts))
    recipe.publish('hia-safe-core-prove', product)
    assert recipe.published == outputs(1)


def build_recipe():
    recipe = Recipe()
    safe_proof(recipe)
    return recipe


def main():
    recipe = build_recipe()
    raw = recipe.binary()
    (ROOT / RESOURCE).write_bytes(raw)
    print(RESOURCE, 'nodes', len(recipe.nodes), 'publishes', len(recipe.published), 'bytes', len(raw))


if __name__ == '__main__':
    main()
