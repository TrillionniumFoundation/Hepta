"""Build the ordinary inspect report owner from matching source-complete cold HIA."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_selfhost_contract import PROFILE

SOURCES = (
    'examples/hia_bootstrap/cli_inspect.hepta',
    'tools/generate_hia_cli_inspect.py',
    'tools/build_hia_cli_inspect.py',
    'hepta/hia_cli_inspect_native.py',
)


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    compiler_bytes = compiler.read_bytes()
    cold_bytes = cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    captured = {name: (ROOT / name).read_bytes() for name in SOURCES}
    for name, raw in captured.items():
        if sources.get(name) != sha256(raw).hexdigest():
            raise ValueError('HIA inspect input differs from admitted cold source: ' + name)
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'cli-inspect', compiler, captured[SOURCES[0]])
    image_bytes = image.read_bytes()
    if not 0 < len(image_bytes) <= 1048576:
        raise ValueError('HIA inspect image exceeds the unchanged native image profile')
    if (any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes
            or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('HIA inspect build inputs changed')
    manifest = {
        'schema': 'hepta.hia.cli-inspect-native.v1',
        'source_sha256': sha256(captured[SOURCES[0]]).hexdigest(),
        'image_path': image.name, 'image_sha256': sha256(image_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
    }
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.cli-inspect-native-build.v1',
        'status': 'NATIVE_CANDIDATE_BUILT', 'profile': PROFILE,
        'source_manifest': sources, 'manifest': manifest,
        'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'native_compile_receipt': receipt,
        'inspect_report_image_built': True,
        'whole_core_admission_still_adjacent': True,
        'ordinary_inspect_selects_explicit_provider': True,
        'default_inspect_provider_selected': False,
        'all_fifteen_cli_actions_native': False,
        'all_input_equivalence_proved': False,
        'whole_stack_rewritten_in_hia': False,
    }, sort_keys=True, indent=2) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
