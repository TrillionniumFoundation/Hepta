"""Build the complete system Jobctl from an admitted matching cold compiler.

Only native sealed executables compile sources, bind the packer and produce the
ELF. The Python entry coordinates explicit development/bootstrap construction;
ordinary production release executes the equivalent HIASTD01 recipe.
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
from tools.generate_hia_mcp_release import FILTER_CAPACITY, FILTER_WORK, POLICY_PATH, FILTER_PATH
from tools.generate_hia_native_filter import (
    read_adapter_binding, template as filter_template, verify_adapter)
from tools.generate_hia_system_jobctl_packer import MAGIC, MODULES
from tools.generate_hia_system_jobctl_release import ROOT, PRODUCT, component_paths, source_paths
from tools.qualify_hia_selfhost_cli import inspect_executable


def digest(raw):
    return sha256(raw).hexdigest()


def verify_packer_host(raw, image):
    prefix, holes = filter_template(wire_bytes=FILTER_CAPACITY,
        output_bytes=FILTER_CAPACITY, workspace_bytes=FILTER_WORK)
    expected = bytearray(prefix)
    struct.pack_into('<2Q', expected, 96, len(prefix) + len(image), len(prefix) + len(image))
    if len(holes) != 1:
        raise ValueError('system Jobctl packer host requires one native entry')
    struct.pack_into('<i', expected, holes[0], len(prefix) - holes[0] - 4)
    if raw != bytes(expected) + image:
        raise ValueError('system Jobctl packer host differs from its source-bound layout')


def build_from_seed(output, seed, *, admitted=None, compiler_sha256=None,
                    cold_report_sha256=None, development=False):
    if admitted is None and development is not True:
        raise ValueError('a source seed without cold admission is development only')
    if admitted is not None and development:
        raise ValueError('development and matching cold modes cannot be combined')
    output = Path(output).resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    paths = component_paths()
    captured = {path: (ROOT / path).read_bytes() for path in source_paths()}
    if admitted is not None and any(admitted.get(path) != digest(raw) for path, raw in captured.items()):
        raise ValueError('system Jobctl sources differ from the matching cold inventory')
    binding = read_adapter_binding(captured[paths['packer']],
        captured['tools/hia_system_jobctl_syscalls.S'], calls=len(MODULES))
    calls = []

    def run(name, executable, argument, wire):
        result = _run_captured(executable, argument, wire, output, timeout=300)
        calls.append({'name': name, 'executable_sha256': digest(executable),
            'input_sha256': digest(wire), 'input_bytes': len(wire),
            'returncode': result.returncode, 'stdout_bytes': len(result.stdout),
            'stdout_sha256': digest(result.stdout), 'stderr_bytes': len(result.stderr)})
        (output / 'partial.json').write_text(json.dumps(calls, indent=2) + '\n')
        if result.returncode or result.stderr or not result.stdout:
            raise ValueError('native system Jobctl construction refused ' + name + ': ' + str(calls[-1]))
        return result.stdout

    source_inputs = {Path(path).name: captured[path] for path in paths.values()}
    images = {}
    names = list(source_inputs)
    for offset in range(0, len(names), 12):
        chunk = {name: source_inputs[name] for name in names[offset:offset + 12]}
        raw = run('compile-' + str(offset // 12), seed, 'sources', _named_source_request(chunk))
        images.update(_compiled_sources(raw, chunk))
    kit = run('packer-host-source-images', seed, 'build',
        _source_bundle([captured[POLICY_PATH], captured['examples/hia_bootstrap/selfhost.hepta'],
                        captured[FILTER_PATH]]))
    host = run('packer-host', seed, 'pack', kit)
    name = Path(paths['packer']).name
    frame = struct.pack('<8s2Q', b'HIAMCF01', len(source_inputs[name]), len(images[name]))
    packer = run('source-bound-packer', host, 'build', frame + source_inputs[name] + images[name])
    verify_packer_host(packer, images[name])
    parts = [images[Path(paths[role]).name] for role, _ in MODULES]
    wire = MAGIC + struct.pack('<20Q', *map(len, parts)) + b''.join(parts)
    raw = run(PRODUCT, packer, None, wire)
    entries = []
    offset = 0
    for part in parts:
        entries.append(offset)
        offset += len(part)
    verify_adapter(raw, b''.join(parts), binding, entries=entries)
    inspection = inspect_executable(raw)
    if any((ROOT / path).read_bytes() != data for path, data in captured.items()):
        raise ValueError('system Jobctl input changed before publication')
    if admitted is not None and current_sources() != admitted:
        raise ValueError('source inventory changed during system Jobctl build')
    target = output / PRODUCT
    with target.open('xb') as stream:
        stream.write(raw)
    target.chmod(0o500)
    report = {
        'schema': 'hepta.hia.system-jobctl-source-build.v1',
        'matching_source_cold_build': admitted is not None,
        'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
        'whole_release_qualified': False,
        'source_builder_sha256': digest(seed),
        'compiler_sha256': compiler_sha256, 'cold_report_sha256': cold_report_sha256,
        'source_sha256': {path: digest(data) for path, data in captured.items()},
        'components': {role: {'source': paths[role], 'source_sha256': digest(captured[paths[role]]),
            'bytes': len(part), 'sha256': digest(part)}
            for (role, _), part in zip(MODULES, parts, strict=True)},
        'packer': {'source': paths['packer'], 'source_sha256': digest(captured[paths['packer']]),
            'flat_sha256': digest(images[name]), 'executable_sha256': digest(packer)},
        'calls': calls,
        'products': {PRODUCT: {'bytes': len(raw), 'sha256': digest(raw)}},
        'executable_path': PRODUCT, 'executable_sha256': digest(raw), 'executable': inspection,
        'transport_adapter_sha256': binding[0].hex(),
        'transport_assembled_during_build': False,
        'runtime_python_or_libc_or_child_policy_required': False,
        'build_inputs_unchanged': True,
    }
    (output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('NATIVE_SYSTEM_JOBCTL_PRODUCT', target.name, len(raw), digest(raw), flush=True)
    return target


def build(output, compiler, cold_report):
    compiler, cold_report = Path(compiler), Path(cold_report)
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    work = Path(output).with_name(Path(output).name + '-source-builder')
    _, seed = _build_captured(work, compiler, cold_report)
    result = build_from_seed(output, seed, admitted=admitted,
        compiler_sha256=digest(compiler_bytes), cold_report_sha256=digest(report_bytes))
    if compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes:
        raise ValueError('cold compiler or report changed during system Jobctl build')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
