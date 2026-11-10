"""Explicit host workspace custody -> HIA names/graph -> native Core compiler.

The workspace is inline and closed: no filesystem import discovery or package
manager, no high-level resolver, no reference-policy fallback. The host still
parses/materializes/checks Core; native-only workspace delivery remains OPEN.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from hepta.hia_core_module_graph_native import installed_module_graph, link_workspace, MAX_BYTES
from tools.compile_hia_core_json import compile_core

def compile_workspace(wire, graph_manifest, frontend_manifest, compiler, output, *, output_profile='elf'):
    if output_profile != 'elf':
        raise ValueError('workspace public scalar exports require explicit ELF output; no silent export stripping')
    graph = installed_module_graph(str(graph_manifest))
    pin = graph_manifest.read_bytes()
    verified, receipt = link_workspace(wire, native=graph)
    image = compile_core(verified.canonical_bytes, frontend_manifest, compiler, output, output_profile=output_profile)
    if graph_manifest.read_bytes() != pin:
        raise ValueError('Core module graph manifest changed during build')
    receipt.update(status='NATIVE_LINKED_CORE_COMPILED', graph_manifest_sha256=sha256(pin).hexdigest(),
                   output_profile=output_profile, output_sha256=sha256(image.read_bytes()).hexdigest())
    (output/'workspace.receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    return image

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'graph-manifest', 'frontend-manifest', 'compiler', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--output-profile', choices=('elf',), default='elf')
    a = p.parse_args()
    with a.source.open('rb') as f: wire = f.read(MAX_BYTES + 1)
    print(compile_workspace(wire, a.graph_manifest.resolve(), a.frontend_manifest.resolve(), a.compiler.resolve(),
                            a.output.resolve(), output_profile=a.output_profile))
