"""Build source-bound native Agent finite binary64 shortest printing; no default activation."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/agent_binary64_format.hiaasm'


def build(output, compiler, cold_report):
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes()
    try:
        sources = admit_cold_build(compiler_raw, cold_raw)
    except ValueError as exc:
        raise ValueError('completed matching-source cold qualification required for Agent binary64 printing') from exc
    cold = json.loads(cold_raw)
    if cold.get('qualification_wall_limit_seconds') != 180 or cold.get('cleanup_wall_limit_seconds') != 3:
        raise ValueError('completed matching-source cold qualification required for Agent binary64 printing')
    source = (ROOT / SOURCE).read_bytes()
    if SOURCE not in sources or sha256(source).hexdigest() != sources[SOURCE]:
        raise ValueError('Agent binary64 printing source differs from admitted cold source')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'agent-binary64-format', compiler, source)
    image_bytes = image.read_bytes()
    if (compiler.read_bytes() != compiler_raw or cold_report.read_bytes() != cold_raw
            or (ROOT / SOURCE).read_bytes() != source or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('Agent binary64 printing native build custody changed')
    manifest = {'schema': 'hepta.hia.agent-binary64-format-native.v1', 'source_sha256': sha256(source).hexdigest(),
        'image_path': image.name, 'image_sha256': sha256(image_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_raw).hexdigest()}
    path = output / 'manifest.json'
    with path.open('x') as stream: json.dump(manifest, stream, indent=2, sort_keys=True); stream.write('\n')
    record = {'status': 'NATIVE_AGENT_BINARY64_FORMAT_BUILT', 'source_manifest': sources,
        'cold_report_sha256': sha256(cold_raw).hexdigest(), 'native_compile_receipt': receipt,
        'native_shortest_roundtrip_binary64_printing': True,
        'native_float_printing': True, 'foreign_float_boxing_is_hosted': True,
        'native_Agent_persistence': False, 'default_changed': False, 'whole_native_delivery_qualified': False}
    with (output / 'build.json').open('x') as stream: json.dump(record, stream, indent=2, sort_keys=True); stream.write('\n')
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'): parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
