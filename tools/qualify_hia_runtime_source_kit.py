"""Rebuild stage 12 with the real HIA compiler, source kit and evaluator packer.

This external development fixture checks the retained runtime DAG's source and
output pins. The full HIASTD01 release owner and cold/install reconstruction have
separate gates; this fixture does not promote their completion state.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

from tools.build_hia_source_build import _compiled_sources
from tools.hia_native_release_dependencies import PROGRAMS, check_source_files, read_recipe

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTION = 'docs/HIA_NATIVE_NDU_EVALUATOR_RECIPE.json'
RECEIPT = 'docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json'
DAG = PROGRAMS + 'release_stage_runtime.hiastd'
KIT = (('source_build_policy.hepta', 'source_native_filter_pack.hepta'),
       ('selfhost.hepta', 'selfhost.hepta'),
       ('source_build_packer.hepta', 'native_filter_packer.hepta'))


def digest(raw):
    return sha256(raw).hexdigest()


def check(value, message):
    if not value:
        raise ValueError(message)


def write_exact(path, raw, *, executable=False):
    if path.exists():
        check(path.read_bytes() == raw, 'rebuild changed an existing qualification artifact: ' + path.name)
    else:
        path.write_bytes(raw)
    if executable:
        path.chmod(0o500)
    return path


def native_smoke(executable):
    def candidate(name, cost):
        return {'id': name, 'cost_q32': cost, 'uncertainty_q32': 0,
                'resource_q32': 0, 'hard_violation': False, 'support_sha256': '22' * 32}
    request = {'schema': 'hepta.hia.ndu-request.v1', 'objective_sha256': '11' * 32,
               'generation': 1, 'resource_cap_q32': 1 << 32,
               'candidates': [candidate('abstain', 10 << 32), candidate('fast', 1 << 32)]}
    wire = json.dumps(request, separators=(',', ':')).encode('ascii')
    result = subprocess.run([str(executable)], input=wire, capture_output=True,
                            env={'PATH': ''}, timeout=30)
    check(result.returncode == 0 and not result.stderr, 'rebuilt evaluator one-shot failed')
    response = json.loads(result.stdout)
    check(response['schema'] == 'hepta.hia.ndu-native-response.v1'
          and response['entry_point'] == 'hepta.hia.ndu_evaluator.v1'
          and response['advisory_recommendation'] == 'fast'
          and response['pareto_frontier'] == ['fast']
          and response['authority'] == 'ADVISORY_ONLY'
          and response['request_sha256'] == digest(wire), 'rebuilt evaluator response binding failed')
    bad = subprocess.run([str(executable)], input=b'{}', capture_output=True,
                         env={'PATH': ''}, timeout=30)
    check(bad.returncode == 2 and not bad.stdout
          and json.loads(bad.stderr)['schema'] == 'hepta.hia.ndu-error.v1',
          'rebuilt evaluator did not preserve malformed-request refusal')
    session = b'33' * 32
    # Distinct exact JSON bytes must get distinct request hashes in one session.
    requests = (wire, wire + b'\n')
    frames = b''.join(struct.pack('>2I', len(part) + 68, index) + session + part
                      for index, part in enumerate(requests, 1))
    stream = subprocess.run([str(executable), '--stream-v1', session.decode('ascii'), '2'],
                            input=frames, capture_output=True, env={'PATH': ''}, timeout=30)
    check(stream.returncode == 0 and not stream.stderr, 'rebuilt evaluator framed session failed')
    at, observed = 0, []
    while at < len(stream.stdout):
        check(len(stream.stdout) - at >= 72, 'truncated rebuilt evaluator response frame')
        size, sequence = struct.unpack_from('>2I', stream.stdout, at)
        check(68 < size <= 1048644 and size + 4 <= len(stream.stdout) - at,
              'invalid rebuilt evaluator response frame extent')
        check(stream.stdout[at + 8:at + 72] == session, 'rebuilt evaluator session changed')
        observed.append((sequence, json.loads(stream.stdout[at + 72:at + 4 + size])))
        at += 4 + size
    check([sequence for sequence, _ in observed] == [0, 1, 2], 'rebuilt evaluator frame sequence changed')
    check(observed[0][1]['schema'] == 'hepta.hia.ndu-native-stream-hello.v1',
          'rebuilt evaluator omitted native stream identity')
    for (_, value), request_bytes in zip(observed[1:], requests):
        check(value['advisory_recommendation'] == 'fast'
              and value['request_sha256'] == digest(request_bytes),
              'rebuilt evaluator reused another request identity')
    return [{'case': 'one-shot-native-evaluator', 'passed': True,
             'request_sha256': digest(wire), 'response_sha256': digest(result.stdout)},
            {'case': 'malformed-request-refused', 'passed': True},
            {'case': 'two-fresh-framed-requests', 'passed': True,
             'response_sha256': digest(stream.stdout)}]


def qualify(root, compiler, output):
    root, compiler, output = (Path(path).resolve() for path in (root, compiler, output))
    description = json.loads((root / DESCRIPTION).read_bytes())
    receipt_raw = (root / RECEIPT).read_bytes()
    receipt = json.loads(receipt_raw)
    check(description['schema'] == 'hepta.hia.ndu-native-recipe.v1'
          and receipt['schema'] == 'hepta.hia.ndu-native-build.v1', 'runtime receipt schema differs')
    recipe_raw = (root / DAG).read_bytes()
    recipe = read_recipe(recipe_raw)
    check(recipe['publications'] == ['hia-ndu-evaluator', 'hia-ndu-evaluator-build.json'],
          'runtime DAG publication names differ')
    check_source_files(root, recipe['sources'])
    source_bytes = {path: (root / path).read_bytes() for path in recipe['sources']}
    for path, pin in receipt['source_files'].items():
        check(path in source_bytes and digest(source_bytes[path]) == pin,
              'runtime frozen source pin differs: ' + path)
    compiler_raw = compiler.read_bytes()
    check({'bytes': len(compiler_raw), 'sha256': digest(compiler_raw)} == receipt['build_inputs']['compiler'],
          'runtime source compiler differs from the frozen construction identity')
    check(description['publish']['require_exact_output_sha256'] == receipt['binary_sha256'],
          'runtime description and receipt output identities differ')
    check(description['pack']['magic'] == 'HIANDP01'
          and description['pack']['tail_roles'] == ['transport', 'evaluator', 'number', 'debug']
          and description['pack']['reserved_zero_at'] == 40, 'runtime packet contract differs')
    output.mkdir(parents=True, exist_ok=True)
    commands = []

    def run(path, args, wire):
        result = subprocess.run([str(path), *args], input=wire, capture_output=True,
                                env={'PATH': ''}, timeout=60)
        commands.append({'executable_sha256': digest(Path(path).read_bytes()), 'argv': list(args),
                         'stdin_sha256': digest(wire), 'stdout_sha256': digest(result.stdout),
                         'returncode': result.returncode, 'stderr_bytes': len(result.stderr)})
        check(result.returncode == 0 and not result.stderr and bool(result.stdout),
              'native construction failed: ' + Path(path).name + ' ' + ' '.join(args))
        return result.stdout

    report = {'schema': 'hepta.hia.native-runtime-release-rebuild.v1', 'passed': False,
              'scope': 'ACTUAL_NATIVE_SOURCE_COMPILATION_KIT_AND_STAGE12_PRODUCT_REBUILD',
              'source_files_checked': True, 'runtime_dag_sha256': digest(recipe_raw),
              'source_files': {path: digest(raw) for path, raw in source_bytes.items()},
              'compiler_sha256': digest(compiler_raw), 'commands': commands, 'rounds': [],
              'native_dag_executed': False, 'whole_release_passed': False,
              'whole_native_only_install_passed': False, 'production_activated': False}
    try:
        for iteration in range(2):
            flats = {}
            for path, raw in source_bytes.items():
                if path.endswith('.hepta'):
                    flat = run(compiler, ['compile'], raw)
                    flats[path] = flat
                    write_exact(output / (Path(path).stem + '.flat'), flat)
            for row in description['compile']['roles']:
                raw, flat = source_bytes[row['source_path']], flats[row['source_path']]
                check((len(raw), digest(raw), len(flat), digest(flat)) ==
                      (row['source_bytes'], row['source_sha256'], row['flat_bytes'], row['flat_sha256']),
                      'runtime module does not match qualified source/image: ' + row['role'])
            kit_sources = {alias: source_bytes[PROGRAMS + name] for alias, name in KIT}
            wire = bytearray(b'HIAREL01' + struct.pack('<2Q', len(kit_sources), 0))
            for alias, raw in kit_sources.items():
                wire += struct.pack('<3Q', len(alias), 0o400, len(raw)) + alias.encode('ascii') + raw
            compiled = run(compiler, ['build'], bytes(wire))
            kit_images = _compiled_sources(compiled, kit_sources)
            check(kit_images == {alias: flats[PROGRAMS + name] for alias, name in KIT},
                  'native source kit changed its source or compiled image')
            kit_image = run(compiler, ['pack'], compiled)
            kit_path = write_exact(output / 'native-filter-source-kit', kit_image, executable=True)
            packer = flats[next(row['source_path'] for row in description['compile']['roles']
                                if row['role'] == 'packer')]
            wrapper = run(kit_path, ['build'], b'HIANPF01' + struct.pack('<2Q', 1, len(packer)) + packer)
            check(digest(wrapper) == receipt['build_inputs']['packer_wrapper_sha256'],
                  'runtime packer wrapper differs from the qualified native image')
            packer_path = write_exact(output / 'hia-ndu-evaluator-pack', wrapper, executable=True)
            by_role = {row['role']: flats[row['source_path']] for row in description['compile']['roles']}
            parts = [by_role[name] for name in description['pack']['tail_roles']]
            packet = b'HIANDP01' + struct.pack('<5Q', *(len(part) for part in parts), 0) + b''.join(parts)
            image = run(packer_path, [], packet)
            check((len(image), digest(image)) == (receipt['binary_bytes'], receipt['binary_sha256']),
                  'runtime product differs from the frozen qualified native image')
            executable = write_exact(output / 'hia-ndu-evaluator', image, executable=True)
            write_exact(output / 'hia-ndu-evaluator-build.json', receipt_raw)
            report['rounds'].append({'iteration': iteration + 1, 'module_count': len(flats),
                                     'source_kit_sha256': digest(kit_image),
                                     'packer_wrapper_sha256': digest(wrapper),
                                     'product_bytes': len(image), 'product_sha256': digest(image),
                                     'receipt_sha256': digest(receipt_raw)})
        report['checks'] = native_smoke(executable)
        report['two_native_rebuilds_identical'] = True
        report['passed'] = True
    finally:
        (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.source, args.compiler, args.output), indent=2))


if __name__ == '__main__':
    main()
