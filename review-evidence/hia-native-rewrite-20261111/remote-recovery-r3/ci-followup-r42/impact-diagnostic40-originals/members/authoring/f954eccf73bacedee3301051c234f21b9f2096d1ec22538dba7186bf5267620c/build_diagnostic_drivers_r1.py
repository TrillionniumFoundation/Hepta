"""Compile new independent program/publication diagnostic routing, original B3 limits."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / 'Hepta-v66-restored'
sys.path[:0] = [str(ROOT), str(BASE)]
from tools.qualify_hia_selfhost import compile_stage
from hepta.hia_agent_assembly import _parse_assembly_document

dest = ROOT / 'development/build-drivers-r1'
dest.mkdir(exist_ok=False)
compiler = ROOT.parent / 'native-composite-core-final-recovery-next/dependencies/f50-B3.image.bin'
compiler_bytes = compiler.read_bytes()
compiler_sha = sha256(compiler_bytes).hexdigest()
assert compiler_sha == '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
pins = {compiler: compiler_bytes, Path(__file__): Path(__file__).read_bytes(),
        ROOT / 'dependencies/core_admission.authoring.py': (ROOT / 'dependencies/core_admission.authoring.py').read_bytes()}
for folder in ('tools', 'docs', 'examples'):
    for p in (ROOT / folder).rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:
            pins[p] = p.read_bytes()
for path, record in json.loads((ROOT / 'checkpoints/contract-r1/inventory.json').read_bytes())['files'].items():
    p = Path(path); raw = p.read_bytes()
    assert len(raw) == record['bytes'] and sha256(raw).hexdigest() == record['sha256']
    pins[p] = raw
(dest / 'source-before.json').write_text(json.dumps({str(p): {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    for p, raw in pins.items()}, indent=2, sort_keys=True) + '\n')
for p, raw in pins.items():
    if p.is_relative_to(ROOT):
        target = dest / 'frozen-source' / p.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
started = time.monotonic_ns()
report = {'scope': 'FULL_CORE_DIAGNOSTIC_PROGRAM_PUBLICATION_ROUTING_BUILD_R1', 'status': 'INCOMPLETE',
          'compiler_sha256': compiler_sha, 'compiler_path': str(compiler), 'components': {},
          'original_compiler_limits_unchanged': True, 'whole_stack_closed': False,
          'current_cold_qualification': False, 'activation': False}
try:
    for name in ('diagnostic_program_driver', 'diagnostic_publication_driver'):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hiaasm')
        raw = pins[path]
        doc = _parse_assembly_document(raw)
        counts = {'functions': len(doc['functions']),
                  'blocks': sum(len(f['blocks']) for f in doc['functions']),
                  'instructions': sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])}
        assert counts['functions'] <= 128 and counts['blocks'] <= 1536 and counts['instructions'] <= 8192
        folder = dest / name
        folder.mkdir()
        (folder / 'source.hiaasm').write_bytes(raw)
        image, receipt = compile_stage(folder, name, compiler, raw)
        assert receipt['input_sha256'] == sha256(raw).hexdigest() and receipt['artifact_sha256'] == compiler_sha
        assert receipt['produced_sha256'] == sha256(image.read_bytes()).hexdigest()
        row = {'source_path': str(path), 'source_sha256': sha256(raw).hexdigest(),
               'frozen_source_path': str(folder / 'source.hiaasm'), 'source_bytes': len(raw),
               'image_path': str(image), 'image_sha256': receipt['produced_sha256'],
               'image_bytes': image.stat().st_size, 'receipt_path': str(folder / (name + '.receipt.json')),
               'counts': counts}
        report['components'][name] = row
        print(json.dumps({'component': name, **row}, sort_keys=True), flush=True)
    report['status'] = 'PASS'
except BaseException as exc:
    report.update(status='FAIL', error_class=type(exc).__name__, error=str(exc))
    raise
finally:
    assert all(p.read_bytes() == raw for p, raw in pins.items())
    report['all_source_and_compiler_pins_unchanged'] = True
    report['wall_ns'] = time.monotonic_ns() - started
    (dest / 'bundle.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True), flush=True)
