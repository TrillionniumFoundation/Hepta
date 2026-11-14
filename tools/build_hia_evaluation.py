"""Build the full Agent evaluation control owner with exact source custody."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

SOURCE_NAME = 'examples/hia_bootstrap/evaluation.hepta'
INPUTS = (SOURCE_NAME, 'tools/generate_hia_evaluation.py', 'tools/build_hia_evaluation.py',
          'hepta/hia_evaluation_native.py', 'hepta/hia_evaluation_protocol.py',
          'hepta/hia_agent_service.py', 'hepta/hia_service_context_native.py',
          'tools/generate_hia_service_context.py', 'tools/hia_service_context_arithmetic.py',
          'hepta/hia_json_preflight_native.py', 'hepta/hia_store_lifecycle_native.py',
          'tests/fixtures/hia_evaluate_19065.py.txt')


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose exactly one matching cold report or explicit development mode')
    output, compiler = Path(output), Path(compiler)
    compiler_bytes = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    if sources is not None and any(sources.get(name) != sha256(raw).hexdigest()
                                   for name, raw in captured.items()):
        raise ValueError('evaluation inputs are not bound by current cold source')
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, 'evaluation', compiler, source)
    image_bytes = image.read_bytes()
    full_output = (output / 'evaluation.output.bin').read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or (sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                        or current_sources() != sources))):
        raise ValueError('evaluation construction inputs or output changed')
    manifest = {'schema': 'hepta.hia.evaluation-native.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    report = {'schema': 'hepta.hia.evaluation-build.v1',
              'scope': 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT',
              'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
              'source_manifest': sources, 'manifest': manifest, 'native_compile_receipt': receipt,
              'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
              'evaluation_control_branches_and_ordered_effects_owned_by_hia': True,
              'exact_integer_arithmetic_owned_by_hia': True,
              'binary64_true_division_and_comparison_hosted': True,
              'foreign_object_protocols_and_providers_hosted': True,
              'retained_evaluation_body_invoked': False,
              'whole_stack_rewritten_in_hia': False, 'all_input_equivalence_proved': False}
    (output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return output / 'manifest.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development))


if __name__ == '__main__':
    main()
