"""Qualify native Worker owner, configuration and controller members from source.

The fixture drives native programs with an empty PATH and compares embedded and
retained images with separate source compiler results. Named source roles must
remain order independent and reject missing, extra or mismatched companions.
Full source/cold release and Worker installation are qualified separately.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


def qualify(source: Path, seed: Path, kit: Path, output: Path):
    source, seed, kit = (path.resolve(strict=True) for path in (source, seed, kit))
    output = output.resolve()
    output.mkdir(mode=0o700)
    sys.path.insert(0, str(source))
    from tools.build_hia_source_build import _named_source_request
    from tools.build_hia_native_store_release import _member_with_objects

    captured = {}
    def read(path):
        raw = path.read_bytes()
        captured[str(path)] = sha256(raw).hexdigest()
        return raw

    bootstrap = source / 'examples/hia_bootstrap'
    read(seed)
    read(kit)
    calls = []
    def call(name, executable, argument, wire):
        result = subprocess.run([str(executable), argument], input=wire,
                                capture_output=True, env={'PATH': ''}, timeout=180)
        calls.append({'name': name, 'program_sha256': sha256(executable.read_bytes()).hexdigest(),
                      'input_sha256': sha256(wire).hexdigest(), 'returncode': result.returncode,
                      'stdout_bytes': len(result.stdout), 'stderr_bytes': len(result.stderr)})
        return result

    members = {}
    specifications = (
        ('hia-worker-install-owner', 'worker_install_owner', 'worker_install_dag'),
        ('hia-worker-config-bind', 'worker_config_bind', 'worker_config_json'),
        ('hia-controller-install', 'controller_install', 'controller_probe'),
    )
    for product, primary, companion in specifications:
        directory = output / product
        directory.mkdir(mode=0o700)
        primary_alias = product + '.hepta'
        companion_alias = companion + '.hepta'
        parts = {
            primary_alias: read(bootstrap / (primary + '.hepta')),
            companion_alias: read(bootstrap / companion_alias),
            'sha256_stream.hepta': read(bootstrap / 'sha256_stream.hepta'),
        }
        independent = {}
        for name, raw in parts.items():
            result = call(product + '/independent-' + name, seed, 'compile', raw)
            if result.returncode or result.stderr or not result.stdout:
                raise ValueError('independent source compilation failed: ' + name)
            independent[name] = result.stdout
            (directory / (name + '.image.bin')).write_bytes(result.stdout)

        builder_sources = {
            'source_build_policy.hepta': read(bootstrap / 'source_filter_member.hepta'),
            'selfhost.hepta': read(bootstrap / 'selfhost.hepta'),
            'source_build_packer.hepta': read(bootstrap / (primary + '_packer.hepta')),
        }
        result = call(product + '/member-kit', kit, 'build',
                      _named_source_request(builder_sources, tag=b'HIAKIT01'))
        if result.returncode or result.stderr or not result.stdout.startswith(b'\x7fELF'):
            raise ValueError('native member kit construction failed: ' + product)
        builder = directory / 'member-builder'
        builder.write_bytes(result.stdout)
        builder.chmod(0o500)
        read(builder)

        result = call(product + '/member', builder, 'build',
                      _named_source_request(parts, tag=b'HIAMUL01'))
        if result.returncode or result.stderr:
            raise ValueError('native member construction failed: ' + product)
        image, retained = _member_with_objects(result.stdout, parts)
        ordered = b''.join(independent.values())
        if (retained != independent or not image.startswith(b'\x7fELF') or
                image[-len(ordered):] != ordered):
            raise ValueError('member differs from independently compiled images: ' + product)
        program = directory / product
        program.write_bytes(image)
        program.chmod(0o500)

        reordered = dict(reversed(tuple(parts.items())))
        result = call(product + '/member-reordered', builder, 'build',
                      _named_source_request(reordered, tag=b'HIAMUL01'))
        if result.returncode or result.stderr:
            raise ValueError('native member rejected reordered named sources: ' + product)
        other, other_images = _member_with_objects(result.stdout, reordered)
        if other != image or other_images != independent:
            raise ValueError('named source order changed executable: ' + product)

        bad = [
            ('missing-companion', {k: v for k, v in parts.items() if k != companion_alias}),
            ('missing-hash', {k: v for k, v in parts.items() if k != 'sha256_stream.hepta'}),
            ('wrong-primary-module', {**parts, primary_alias: parts['sha256_stream.hepta']}),
            ('wrong-companion-module', {**parts, companion_alias: parts['sha256_stream.hepta']}),
            ('wrong-hash-module', {**parts, 'sha256_stream.hepta': parts[companion_alias]}),
            ('extra-source', {**parts, 'unrelated.hepta': parts['sha256_stream.hepta']}),
            ('unknown-primary-alias', {('wrong.hepta' if k == primary_alias else k): v
                                       for k, v in parts.items()}),
        ]
        for name, values in bad:
            result = call(product + '/' + name, builder, 'build',
                          _named_source_request(values, tag=b'HIAMUL01'))
            if result.returncode == 0 or result.stdout or result.stderr:
                raise ValueError('native source refusal differs: ' + product + '/' + name)
        members[product] = {
            'elf_bytes': len(image), 'elf_sha256': sha256(image).hexdigest(),
            'independent_images_equal': True, 'source_order_independent': True,
            'refusal_cases': len(bad),
            'image_sha256': {name: sha256(raw).hexdigest() for name, raw in independent.items()},
        }

    if any(sha256(Path(name).read_bytes()).hexdigest() != pin for name, pin in captured.items()):
        raise ValueError('qualification input changed')
    report = {'schema': 'hepta.hia.worker-install-source-qualification.v2',
              'scope': 'NATIVE_WORKER_INSTALLATION_MEMBER_COMPONENTS', 'status': 'passed',
              'members': members, 'refusal_cases': sum(row['refusal_cases'] for row in members.values()),
              'source_and_tool_sha256': captured, 'calls': calls}
    (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--seed', type=Path, required=True)
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.source, args.seed, args.kit, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
