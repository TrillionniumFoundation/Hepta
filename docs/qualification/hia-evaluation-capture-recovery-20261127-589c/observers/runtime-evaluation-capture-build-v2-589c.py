from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
OUT = Path('/tmp/runtime-evaluation-capture-native-build-v2-589c')
OUT.mkdir(mode=0o700)
sys.path.insert(0, str(ROOT))
from tools import qualify_hia_selfhost
from tools import build_hia_evaluation, build_hia_native_build_admission

compiler = Path('/tmp/hia-runtime-589c-language-all-fixtures-20261127-v3/B1.image.bin')
compiler_raw = compiler.read_bytes()
assert sha256(compiler_raw).hexdigest() == 'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
carrier = Path('/tmp/hia-historical-p3-final-cold-589c.json').read_bytes()
assert sha256(carrier).hexdigest() == '00ef3a2c17ec6424bc2fd61a87ea1b6c469341a6385464b3c7c9c172eb69c42e'
observer = bytes.fromhex(json.loads(carrier)['native_flat_observer_hex'])
assert len(observer) == 1107
assert sha256(observer).hexdigest() == '830b80e8b1acf852cb7cb103abe453cfdd800b34d6f992e5396769cb6c7f8e30'
qualify_hia_selfhost.NATIVE_OBSERVER = observer
names = set(build_hia_evaluation.INPUTS) | set(build_hia_native_build_admission.INPUTS)
names.update(('tests/hia_evaluation_capture_successor.py', 'tests/test_hia_evaluation_capture.py',
              'tests/test_hia_evaluation_native.py', 'hepta/hia_evaluation_protocol.py'))
before = {name: (ROOT / name).read_bytes() for name in sorted(names)}
started = time.monotonic()
manifests = {}
for name, module in (('evaluation', build_hia_evaluation), ('admission', build_hia_native_build_admission)):
    manifests[name] = str(module.build(OUT / name, compiler, development=True))
    print(name, manifests[name], flush=True)
after = {name: (ROOT / name).read_bytes() for name in before}
receipt = {
    'schema': 'hepta.hia.evaluation-capture-development-construction.v1',
    'base_commit': '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375',
    'scope': 'EXPLICIT_DEVELOPMENT_COMPONENT; historical native B1 and observer only',
    'compiler_sha256': sha256(compiler_raw).hexdigest(),
    'observer_sha256': sha256(observer).hexdigest(), 'manifests': manifests,
    'elapsed_seconds': time.monotonic() - started,
    'source_before': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                      for name, raw in before.items()},
    'source_after': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                     for name, raw in after.items()},
    'source_unchanged': before == after,
    'compiler_unchanged': compiler.read_bytes() == compiler_raw,
    'current_cold_qualified': False, 'whole_stack_rewritten_in_hia': False,
}
(OUT / 'construction-custody.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
assert receipt['source_unchanged'] and receipt['compiler_unchanged']
print(json.dumps({key: receipt[key] for key in ('elapsed_seconds', 'source_unchanged', 'compiler_unchanged', 'manifests')}))
