"""Compile only the draft page using an explicitly pinned development image."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/hia-native-wire-entry')
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path('/tmp/hia-artifact-page-draft')
OUTPUT = ROOT / 'development-r1'
COMPILER = Path('/workspace/scratch/e26ed3e2edcf/journal-recovered-development-r1/development-compiler.bin')
EXPECTED = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
os.umask(0o077)
os.nice(10)
assert sha256(COMPILER.read_bytes()).hexdigest() == EXPECTED
OUTPUT.mkdir(mode=0o700)
source = (ROOT / 'artifact_page.hiaasm').read_bytes()
started = time.monotonic()
image, receipt = compile_stage(OUTPUT, 'artifact-page', COMPILER, source)
manifest = {'schema': 'hepta.hia.artifact-page-native.v1', 'source_sha256': sha256(source).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256': EXPECTED}
(OUTPUT / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
report = {'scope': 'EXPLICIT_DEVELOPMENT_COMPILER_ONLY_NOT_COLD_QUALIFICATION',
          'native_compile_receipt': receipt, 'manifest': manifest,
          'source_preserved': (ROOT / 'artifact_page.hiaasm').read_bytes() == source,
          'seconds': time.monotonic() - started, 'whole_native_delivery_qualified': False}
assert report['source_preserved']
(OUTPUT / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'scope': report['scope'], 'manifest': manifest, 'seconds': report['seconds']}))
