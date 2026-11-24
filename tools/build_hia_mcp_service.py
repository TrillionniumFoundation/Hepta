"""Build the complete native MCP service from a matching cold compiler.

Every compiler, HIA packer and packer host runs from a sealed descriptor with an
empty PATH. The Python entry is the explicit development/bootstrap coordinator;
ordinary production release uses the equivalent checked HIASTD01 recipe.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import (
    _build_captured, _compiled_sources, _named_source_request, _run_captured, _source_bundle)
from tools.generate_hia_mcp_release import (
    FILTER_CAPACITY, FILTER_PATH, FILTER_WORK, POLICY_PATH, PRODUCTS, ROOT,
    component_paths, source_paths, specifications)
from tools.generate_hia_native_filter import template as filter_template
from tools.qualify_hia_selfhost_cli import inspect_executable


def digest(raw):
    return sha256(raw).hexdigest()


def verify_packer_host(raw, image):
    prefix, holes = filter_template(wire_bytes=FILTER_CAPACITY,
        output_bytes=FILTER_CAPACITY, workspace_bytes=FILTER_WORK)
    expected = bytearray(prefix)
    struct.pack_into('<2Q', expected, 96, len(prefix) + len(image), len(prefix) + len(image))
    assert len(holes) == 1
    struct.pack_into('<i', expected, holes[0], len(prefix) - holes[0] - 4)
    if raw != bytes(expected) + image:
        raise ValueError('compiler-bound packer host differs from its mechanical layout')


def verify_bundle(label, raw, roles, parts):
    # Independent development-time assembly of the mechanical adapter, without
    # calling the HIA packer or deriving an expected answer from its output.
    from tools import generate_hia_mcp_request_audit as audit
    from tools import generate_hia_mcp_job_bridge as bridge
    from tools import generate_hia_mcp_service as service
    prefix, holes = {'audit': audit, 'bridge': bridge, 'service': service}[label].template()
    expected = bytearray(prefix)
    size = len(prefix) + sum(len(parts[role]) for role in roles)
    struct.pack_into('<2Q', expected, 96, size, size)
    target = len(prefix)
    for role in roles:
        struct.pack_into('<i', expected, holes[role], target - holes[role] - 4)
        target += len(parts[role])
    if label == 'service':
        for role in ('bridge', 'audit'):
            struct.pack_into('<I', expected, holes[role + '_size'], len(parts[role]))
            expected[holes[role + '_pin']:holes[role + '_pin'] + 32] = sha256(parts[role]).digest()
    if raw != bytes(expected) + b''.join(parts[role] for role in roles):
        raise ValueError('native MCP ELF differs from its complete component/adapter inventory: ' + label)
    inspect_executable(raw)


def build_from_seed(output, seed, *, admitted=None, compiler_sha256=None, cold_report_sha256=None):
    """Drive native construction; callers must label any development seed honestly."""
    output = Path(output).resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    paths = component_paths()
    captured = {path: (ROOT / path).read_bytes() for path in source_paths()}
    if admitted is not None and any(admitted.get(path) != digest(raw) for path, raw in captured.items()):
        raise ValueError('MCP source inventory differs from the matching cold build')
    calls = []

    def run(name, executable, argument, wire):
        result = _run_captured(executable, argument, wire, output, timeout=300)
        calls.append({'name': name, 'executable_sha256': digest(executable),
                      'input_sha256': digest(wire), 'input_bytes': len(wire),
                      'returncode': result.returncode, 'stdout_bytes': len(result.stdout),
                      'stdout_sha256': digest(result.stdout), 'stderr_bytes': len(result.stderr)})
        (output / 'partial.json').write_text(json.dumps(calls, indent=2) + '\n')
        if result.returncode or result.stderr or not result.stdout:
            raise ValueError('native MCP source build refused ' + name + ': ' + str(calls[-1]))
        return result.stdout

    source_inputs = {Path(path).name: captured[path] for path in sorted(set(paths.values()))}
    images = {}
    names = list(source_inputs)
    for start in range(0, len(names), 12):
        chunk = {name: source_inputs[name] for name in names[start:start + 12]}
        packed = run('compile-' + str(start // 12), seed, 'sources', _named_source_request(chunk))
        images.update(_compiled_sources(packed, chunk))
    kit_sources = [captured[POLICY_PATH], captured['examples/hia_bootstrap/selfhost.hepta'], captured[FILTER_PATH]]
    kit = run('packer-host-source-images', seed, 'build', _source_bundle(kit_sources))
    host = run('packer-host', seed, 'pack', kit)
    products, components = {}, {}
    for label, stem, roles, companions, magic in specifications():
        name = Path(paths[label, 'packer']).name
        source, image = source_inputs[name], images[name]
        host_frame = struct.pack('<8s2Q', b'HIAMCF01', len(source), len(image)) + source + image
        packer = run(label + '-packer-host', host, 'build', host_frame)
        verify_packer_host(packer, image)
        parts = {role: products[role] if label == 'service' and role in ('bridge', 'audit')
                 else images[Path(paths[label, role]).name] for role in roles}
        pins = b''.join(sha256(parts[role]).digest() for role in ('bridge', 'audit')) if label == 'service' else b''
        wire = magic + struct.pack('<' + 'Q' * len(roles), *(len(parts[role]) for role in roles)) + pins + b''.join(parts[role] for role in roles)
        raw = run(label, packer, None, wire)
        verify_bundle(label, raw, roles, parts)
        products[label] = raw
        components[label] = {role: {'bytes': len(data), 'sha256': digest(data)} for role, data in parts.items()}
        target = output / PRODUCTS[len(products) - 1]
        target.write_bytes(raw)
        target.chmod(0o500)
        print('NATIVE_MCP_PRODUCT', target.name, len(raw), digest(raw), flush=True)
    if any((ROOT / path).read_bytes() != raw for path, raw in captured.items()):
        raise ValueError('MCP build input changed before publication')
    if admitted is not None and current_sources() != admitted:
        raise ValueError('source inventory changed during MCP build')
    report = {'schema': 'hepta.hia.mcp-service-source-build.v1',
              'matching_source_cold_build': admitted is not None,
              'whole_release_qualified': False,
              'source_builder_sha256': digest(seed), 'compiler_sha256': compiler_sha256,
              'cold_report_sha256': cold_report_sha256,
              'source_sha256': {path: digest(raw) for path, raw in captured.items()},
              'components': components, 'calls': calls,
              'products': {name: {'bytes': len(raw), 'sha256': digest(raw)}
                  for name, raw in zip(PRODUCTS, products.values(), strict=True)}}
    (output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return output / PRODUCTS[-1]


def build(output, compiler, cold_report):
    compiler, cold_report = Path(compiler), Path(cold_report)
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    work = Path(output).with_name(Path(output).name + '-source-builder')
    _, seed = _build_captured(work, compiler, cold_report)
    result = build_from_seed(output, seed, admitted=admitted,
                            compiler_sha256=digest(compiler_bytes), cold_report_sha256=digest(report_bytes))
    if compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes:
        raise ValueError('cold compiler or report changed during MCP build')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
