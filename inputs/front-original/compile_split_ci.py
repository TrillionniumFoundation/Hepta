"""Two fresh HIA images using the exact retained development compiler."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
OUT = ROOT / 'native-build-r1'
OUT.mkdir(exist_ok=False)
COMPILER = ROOT / 'retained-inputs/retained-B3.image.bin'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
for name in tuple(os.environ):
    if name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST'):
        os.environ.pop(name)
sys.path.insert(0, str(SOURCE))
from tools.qualify_hia_selfhost import compile_stage
from tools.build_hia_core_json_bytes import admit_compile_receipt

def sources():
    return {p.relative_to(SOURCE).as_posix(): {
        'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': p.stat().st_mode & 0o777}
        for p in SOURCE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}

before = sources()
compiler_bytes = COMPILER.read_bytes()
assert len(compiler_bytes) == 669494 and sha256(compiler_bytes).hexdigest() == COMPILER_SHA
report = {'schema': 'hia.front.two-independent-images.v81.r1', 'status': 'STARTED',
          'scope': 'EXPLICIT_RETAINED_COMPILER_DEVELOPMENT_ONLY', 'python': sys.version,
          'compiler_sha256': COMPILER_SHA, 'compiler_bytes': len(compiler_bytes),
          'original_child_seconds': 20, 'source_before': before, 'images': {},
          'old_thirteen_root_results_inherited': False, 'current_cold': False,
          'whole_normalization': False, 'physical_recursion': False}
started = time.monotonic()
try:
    for stem in ('core_verification', 'assembly_front'):
        directory = OUT / stem
        directory.mkdir(exist_ok=False)
        source = SOURCE / ('examples/hia_bootstrap/' + stem + '.hiaasm')
        raw = source.read_bytes()
        label = stem.replace('_', '-')
        image, receipt = compile_stage(directory, label, COMPILER, raw)
        image = Path(image)
        image_bytes = image.read_bytes()
        admit_compile_receipt(receipt, compiler_bytes=compiler_bytes,
                              source_bytes=raw, image_bytes=image_bytes)
        receipt_path = directory / (label + '.receipt.json')
        receipt_bytes = receipt_path.read_bytes()
        disk = json.loads(receipt_bytes)
        admit_compile_receipt(disk, compiler_bytes=compiler_bytes,
                              source_bytes=raw, image_bytes=image_bytes)
        assert json.dumps(disk, sort_keys=True) == json.dumps(receipt, sort_keys=True)
        assert receipt['case'] == label and receipt['produced_image'] == str(image)
        assert COMPILER.read_bytes() == compiler_bytes and source.read_bytes() == raw
        manifest = {'schema': 'hepta.hia.' + label + '-native.v1',
                    'source_sha256': sha256(raw).hexdigest(), 'image_path': image.name,
                    'image_sha256': sha256(image_bytes).hexdigest(),
                    'compiler_sha256': COMPILER_SHA}
        path = directory / 'development-manifest.json'
        encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        with path.open('xb') as stream:
            stream.write(encoded)
        assert path.read_bytes() == encoded
        report['images'][stem] = {'manifest_path': str(path), 'manifest': manifest,
                                 'manifest_sha256': sha256(encoded).hexdigest(),
                                 'image_bytes': len(image_bytes), 'receipt': receipt,
                                 'receipt_sha256': sha256(receipt_bytes).hexdigest()}
    report['status'] = 'DEVELOPMENT_TWO_IMAGES_BUILT'
except BaseException:
    report['status'] = 'FAIL'
    report['traceback'] = traceback.format_exc()
finally:
    report['source_after'] = sources()
    report['source_unchanged'] = report['source_after'] == before
    report['compiler_unchanged'] = COMPILER.read_bytes() == compiler_bytes
    report['seconds'] = time.monotonic() - started
    if not report['source_unchanged'] or not report['compiler_unchanged']:
        report['status'] = 'FAIL'
    (OUT / 'RESULT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({key: report[key] for key in ('status', 'scope', 'seconds', 'source_unchanged', 'compiler_unchanged')}, sort_keys=True))
raise SystemExit(0 if report['status'] == 'DEVELOPMENT_TWO_IMAGES_BUILT' else 1)
