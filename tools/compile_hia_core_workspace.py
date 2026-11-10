"""Explicit host workspace custody -> HIA names/graph -> native Core compiler.

The workspace is inline and closed: no filesystem import discovery or package
manager, no high-level resolver, no reference-policy fallback. Selecting the
workspace JSON image also replaces host framing, fact encoding and Core JSON
materialization. General Core checking and filesystem/build transport remain
host bridges in both paths; native-only workspace delivery remains OPEN.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from hepta.hia_core_module_graph_native import installed_module_graph, link_workspace, MAX_BYTES
from tools.compile_hia_core_json import compile_core

def compile_workspace(wire, graph_manifest, frontend_manifest, compiler, output, *, output_profile='elf', workspace_json_manifest=None):
    if output_profile != 'elf':
        raise ValueError('workspace public scalar exports require explicit ELF output; no silent export stripping')
    if workspace_json_manifest is not None:
        from hepta.hia_core_workspace_json_native import installed_workspace_json, link_workspace as native_link
        if graph_manifest is not None:
            raise ValueError('select exactly one workspace image; no fallback manifest')
        manifest=workspace_json_manifest
        native=installed_workspace_json(str(manifest))
        selected_link=native_link
    else:
        manifest=graph_manifest
        native=installed_module_graph(str(manifest))
        selected_link=link_workspace
    pin = manifest.read_bytes()
    verified, receipt = selected_link(wire, native=native)
    image = compile_core(verified.canonical_bytes, frontend_manifest, compiler, output, output_profile=output_profile)
    if manifest.read_bytes() != pin:
        raise ValueError('Core module graph manifest changed during build')
    receipt['workspace_json_manifest_sha256' if workspace_json_manifest is not None else 'graph_manifest_sha256']=sha256(pin).hexdigest()
    receipt.update(status='NATIVE_LINKED_CORE_COMPILED',
                   output_profile=output_profile, output_sha256=sha256(image.read_bytes()).hexdigest())
    (output/'workspace.receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    return image

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'frontend-manifest', 'compiler', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    selection=p.add_mutually_exclusive_group(required=True)
    selection.add_argument('--graph-manifest',type=Path)
    selection.add_argument('--workspace-json-manifest',type=Path)
    p.add_argument('--output-profile', choices=('elf',), default='elf')
    a = p.parse_args()
    with a.source.open('rb') as f: wire = f.read(MAX_BYTES + 1)
    print(compile_workspace(wire, a.graph_manifest.resolve() if a.graph_manifest else None,
                            a.frontend_manifest.resolve(), a.compiler.resolve(), a.output.resolve(),
                            output_profile=a.output_profile,
                            workspace_json_manifest=a.workspace_json_manifest.resolve() if a.workspace_json_manifest else None))
