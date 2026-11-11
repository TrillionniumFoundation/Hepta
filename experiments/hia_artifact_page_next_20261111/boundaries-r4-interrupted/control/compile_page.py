"""Compile the exact page policy once with the pinned development B3 image."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path('/tmp/hia-e26e-artifact-page-r4')
SOURCE = ROOT / 'source'
sys.path.insert(0, str(SOURCE))
from tools.qualify_hia_selfhost import compile_stage

compiler = ROOT / 'inputs/B3.image.bin'
assert sha256(compiler.read_bytes()).hexdigest() == '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
source = (SOURCE / 'examples/hia_bootstrap/artifact_page.hiaasm').read_bytes()
assert sha256(source).hexdigest() == '4cedc0e1442d6f2cb479e194cb1d5c14898055651ccaaa0afb3b907a91dea0b6'
output = ROOT / 'development-r4'
output.mkdir(mode=0o700)
started = time.monotonic_ns()
image, receipt = compile_stage(output, 'artifact-page', compiler, source)
assert sha256(image.read_bytes()).hexdigest() == 'f2aaee2be275fb3f8831ae994e4c03f0ec6a12c53892fe8840eb4a4fa8270d3d'
manifest = {'schema': 'hepta.hia.artifact-page-native.v1', 'source_sha256': sha256(source).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}
manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
(output / 'manifest.json').write_bytes(manifest_raw)
wire_manifest = ROOT / 'wire/manifest.json'
wire = json.loads(wire_manifest.read_bytes())
assert wire['image_sha256'] == '5eba1c2bc33693692f038bdea7f775f1d49b8203aa22d15bb2a981531baa62dc'
bundle = {'schema': 'hepta.hia.artifact-page-bundle.v1',
          'policy_manifest': 'development-r4/manifest.json', 'policy_manifest_sha256': sha256(manifest_raw).hexdigest(),
          'wire_manifest': 'wire/manifest.json', 'wire_manifest_sha256': sha256(wire_manifest.read_bytes()).hexdigest()}
(ROOT / 'page-bundle.json').write_text(json.dumps(bundle, indent=2, sort_keys=True) + '\n')
assert (SOURCE / 'examples/hia_bootstrap/artifact_page.hiaasm').read_bytes() == source
report = {'schema': 'hia.artifact-page.development-build.v1', 'status': 'DEVELOPMENT_BUILD_COMPLETE',
          'compiler_sha256': manifest['compiler_sha256'], 'native_receipt': receipt,
          'manifest': manifest, 'source_preserved': True, 'seconds': (time.monotonic_ns() - started) / 1e9,
          'matching_current_cold_qualified': False, 'whole_native_delivery_qualified': False}
(output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': report['status'], 'image_sha256': manifest['image_sha256'], 'seconds': report['seconds']}))
