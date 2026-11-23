"""Pack a cold-built HIA borrowed-buffer application as an independent ELF."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import CANDIDATES, admit_cold_build, build as build_image, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_native_filter import EVALUATE_PROJECTOR_FILTER_MAGIC, MAGIC, SAFE_CORE_LOADER_FILTER_MAGIC
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
PACKER = 'native-filter'


def build_filter(output: Path, compiler: Path, cold_report: Path, *,
                 application: str, filename: str, schema: str,
                 packer=PACKER, magic=MAGIC, adapter=None) -> Path:
    roles = application, packer
    sources = tuple(ROOT / 'examples/hia_bootstrap' / (CANDIDATES[role][0] + '.hepta') for role in roles)
    if adapter is not None:
        sources += (ROOT / adapter,)
    pins = {path: path.read_bytes() for path in (compiler, cold_report, *sources)}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted.get(path.relative_to(ROOT).as_posix()) != sha256(pins[path]).hexdigest()
           for path in sources):
        raise ValueError(f'{application} filter source differs from cold source')

    output.mkdir(mode=0o700)
    applications = {}
    for role in roles:
        manifest = build_image(output / role, compiler, cold_report, candidate=role)
        pins[manifest] = manifest.read_bytes()
        metadata = json.loads(pins[manifest])
        image = manifest.parent / metadata['image_path']
        pins[image] = image.read_bytes()
        if sha256(pins[image]).hexdigest() != metadata['image_sha256']:
            raise ValueError(f'{role} image differs from its receipt')
        applications[role] = image, metadata

    application_bytes = pins[applications[application][0]]
    packer_image = applications[packer][0]
    frame = struct.pack('<2Q', magic, len(application_bytes)) + application_bytes
    receipt, packed = invoke(output, 'native-pack', packer_image, frame)
    executable_bytes = _check_pack_output(receipt, packed, artifact=pins[packer_image], source=frame)
    inspection = inspect_executable(executable_bytes)
    if adapter is not None:
        from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter

        binding = read_adapter_binding(pins[sources[1]], pins[ROOT / adapter], calls=1)
        verify_adapter(executable_bytes, application_bytes, binding, entries=(0,))
    if any(path.read_bytes() != before for path, before in pins.items()) or current_sources() != admitted:
        raise ValueError(f'{application} filter build input changed')
    executable = output / filename
    with executable.open('xb') as stream:
        stream.write(executable_bytes)
    executable.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': schema,
        'executable': inspection,
        'executable_sha256': sha256(executable_bytes).hexdigest(),
        'compiler_sha256': sha256(pins[compiler]).hexdigest(),
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'images': {role: metadata for role, (_, metadata) in applications.items()},
        'native_pack_receipt': receipt,
    }, indent=2, sort_keys=True) + '\n')
    return executable


def build_evaluate_projector(output, compiler, cold_report):
    return build_filter(output, compiler, cold_report, application='evaluate-reference-wire',
                        packer='evaluate-reference-wire-filter', magic=EVALUATE_PROJECTOR_FILTER_MAGIC,
                        filename='hia-evaluate-projector', schema='hepta.hia.evaluate-projector-filter-build.v1')


def build_execution_budget_session(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_execution_budget_session import ADAPTER, PACK_MAGIC

    return build_filter(output, compiler, cold_report, application='execution-budget',
                        packer='execution-budget-session-packer', magic=PACK_MAGIC, adapter=ADAPTER,
                        filename='hia-execution-budget-session',
                        schema='hepta.hia.execution-budget-session-build.v1')


def build_evaluate_reference_batch(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_reference_batch import ADAPTER, PACK_MAGIC

    return build_filter(output, compiler, cold_report, application='evaluate-reference-batch',
                        packer='evaluate-reference-batch-packer', magic=PACK_MAGIC, adapter=ADAPTER,
                        filename='hia-evaluate-reference-batch',
                        schema='hepta.hia.evaluate-reference-batch-build.v1')


def build_evaluate_paired_batch(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_paired_batch import ADAPTER, PACK_MAGIC

    return build_filter(output, compiler, cold_report, application='evaluate-paired-batch',
                        packer='evaluate-paired-batch-packer', magic=PACK_MAGIC, adapter=ADAPTER,
                        filename='hia-evaluate-paired-batch',
                        schema='hepta.hia.evaluate-paired-batch-build.v1')


def build_evaluate_budget_store(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_budget_store import PACK_MAGIC

    return build_filter(output, compiler, cold_report, application='evaluate-budget-store',
                        packer='evaluate-budget-store-packer', magic=PACK_MAGIC,
                        filename='hia-evaluate-budget-store', schema='hepta.hia.evaluate-budget-store-build.v1')


def build_evaluate_reference_report(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_reference_report import MAGIC as report_magic

    return build_filter(output, compiler, cold_report, application='evaluate-reference-report',
                        packer='evaluate-reference-report-packer', magic=report_magic,
                        filename='hia-evaluate-reference-report',
                        schema='hepta.hia.evaluate-reference-report-build.v1')


def build_evaluate_native_report(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_native_report import MAGIC as report_magic

    return build_filter(output, compiler, cold_report, application='evaluate-native-report',
                        packer='evaluate-native-report-packer', magic=report_magic,
                        filename='hia-evaluate-native-report',
                        schema='hepta.hia.evaluate-native-report-build.v1')


def build_evaluate_measurements(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_measurements import MAGIC as report_magic

    return build_filter(output, compiler, cold_report, application='evaluate-measurements',
                        packer='evaluate-measurements-packer', magic=report_magic,
                        filename='hia-evaluate-measurements',
                        schema='hepta.hia.evaluate-measurements-build.v1')


def build_evaluate_settlement(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.generate_hia_evaluate_settlement import MAGIC as settlement_magic

    return build_filter(output, compiler, cold_report, application='evaluate-settlement',
                        packer='evaluate-settlement-packer', magic=settlement_magic,
                        filename='hia-evaluate-settlement',
                        schema='hepta.hia.evaluate-settlement-build.v1')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', choices=('safe-core-elf-inventory', 'evaluate-reference-wire',
                                                  'evaluate-reference-batch', 'evaluate-paired-batch', 'evaluate-settlement', 'evaluate-measurements', 'evaluate-native-report', 'evaluate-reference-report',
                                                  'execution-budget-session', 'evaluate-budget-store'),
                        default='safe-core-elf-inventory')
    for flag in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + flag, type=Path, required=True)
    args = parser.parse_args()
    output, compiler, cold_report = args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()
    if args.application == 'evaluate-budget-store':
        print(build_evaluate_budget_store(output, compiler, cold_report))
        return
    if args.application == 'evaluate-reference-report':
        print(build_evaluate_reference_report(output, compiler, cold_report))
        return
    if args.application == 'evaluate-native-report':
        print(build_evaluate_native_report(output, compiler, cold_report))
        return
    if args.application == 'evaluate-measurements':
        print(build_evaluate_measurements(output, compiler, cold_report))
        return
    if args.application == 'evaluate-settlement':
        print(build_evaluate_settlement(output, compiler, cold_report))
        return
    if args.application == 'execution-budget-session':
        print(build_execution_budget_session(output, compiler, cold_report))
        return
    if args.application == 'evaluate-paired-batch':
        print(build_evaluate_paired_batch(output, compiler, cold_report))
        return
    if args.application == 'evaluate-reference-batch':
        print(build_evaluate_reference_batch(output, compiler, cold_report))
        return
    if args.application == 'evaluate-reference-wire':
        print(build_evaluate_projector(output, compiler, cold_report))
        return
    print(build_filter(output, compiler, cold_report,
                       application='safe-core-elf-inventory', packer='safe-core-loader-filter',
                       magic=SAFE_CORE_LOADER_FILTER_MAGIC, filename='hia-safe-core-loader',
                       schema='hepta.hia.safe-core-loader-filter-build.v1'))


if __name__ == '__main__':
    main()
