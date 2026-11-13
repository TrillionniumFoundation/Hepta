from pathlib import Path
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT.parent / 'source-original/tools/hia_selfhost_contract.py'
CANDIDATE = ROOT / 'source/tools/hia_selfhost_contract.py'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'source'))


def observe(path, case, root):
    events = []
    class Name(str):
        def __hash__(self):
            events.append(('key-hash', str(self)))
            return hash('open')
        def __eq__(self, other):
            events.append(('key-equality', type(other).__name__, str(other)))
            if case == 'raising-key':
                raise LookupError('same real foreign type-key failure')
            return str.__eq__(self, other)
    key = Name('diagnostic-unrelated-name')
    original_posix = pathlib.PosixPath
    concrete = type('ProbePosix', (original_posix,), {
        '__module__': 'pathlib', '__slots__': (), key: None,
    })
    assert any(type(item) is Name and item is key for item in vars(concrete))
    events.clear()
    result = {'case': case, 'key_retained_as_exact_foreign_object': True}
    with patch.object(pathlib, 'PosixPath', concrete):
        spec = importlib.util.spec_from_file_location('_protocol_key_' + case, path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except BaseException as error:
            result['capture_error'] = {'type': type(error).__name__, 'args': error.args}
            result['capture_events'] = list(events)
            return result
        result['captured'] = module._SOURCE_PATH_PROTOCOL is not None
        result['capture_events'] = list(events)
        events.clear()
        result['guard'] = module._source_protocol_current(module.ROOT)
        result['guard_events'] = list(events)
        events.clear()
        module.SOURCE_FILES = ('a',)
        try:
            result['map'] = list(module.file_digests(root).items())
        except BaseException as error:
            result['map_error'] = {'type': type(error).__name__, 'args': error.args}
        result['map_events'] = list(events)
    return result


rows = []
with tempfile.TemporaryDirectory(prefix='hia-real-type-dict-key-') as temporary:
    root = Path(temporary)
    (root / 'hepta').mkdir()
    (root / 'a').write_bytes(b'first')
    (root / 'hepta/b.py').write_bytes(b'second')
    for case in ('ordinary-foreign-key', 'raising-key'):
        original = observe(ORIGINAL, case, root)
        candidate = observe(CANDIDATE, case, root)
        row = {'case': case, 'original': original, 'candidate': candidate, 'equal': original == candidate}
        rows.append(row)
report = {'schema': 'hepta.type-dict-foreign-key-guard-control.v1', 'python': sys.version,
          'status': 'PASS' if all(row['equal'] for row in rows) else 'FAIL',
          'cases': rows, 'qualification': False, 'whole_native': False}
(ROOT / 'TYPE-KEY-CONTROLS.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
assert report['status'] == 'PASS'
