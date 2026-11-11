"""Actual draft/native-code differential controls; no production qualification."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path('/workspace/scratch/e26ed3e2edcf/hia-native-wire-entry')
FOLDER = Path('/tmp/hia-artifact-page-draft')
sys.path.insert(0, str(ROOT))
from hepta import hia_agent_service as service_module
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_json_wire_native import installed_json_wire

spec = importlib.util.spec_from_file_location('hepta.hia_artifact_page_native', FOLDER / 'hia_artifact_page_native.py')
page = importlib.util.module_from_spec(spec)
spec.loader.exec_module(page)
manifest = json.loads((FOLDER / 'development-r1/manifest.json').read_bytes())
policy = NativeHiaJsonImage((FOLDER / 'development-r1' / manifest['image_path']).read_bytes(), manifest['image_sha256'])
wire = installed_json_wire('/workspace/scratch/e26ed3e2edcf/wire-entry-development-r1/manifest.json')
owner = page.NativeArtifactPage(policy, wire)
paths = [FOLDER / 'generate_hia_artifact_page.py', FOLDER / 'hia_artifact_page_native.py',
         FOLDER / 'artifact_page.hiaasm', Path(__file__),
         ROOT / 'hepta/hia_agent_service.py', ROOT / 'hepta/hia_agent_store.py',
         ROOT / 'hepta/hia_json_wire_native.py', ROOT / 'examples/hia_bootstrap/json_wire.hiaasm']
before = {str(p): sha256(p.read_bytes()).hexdigest() for p in paths}


def service(data):
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
    return SimpleNamespace(store=SimpleNamespace(get=lambda ref: (data, {}), db=db))


def observed(operation):
    try:
        return {'returned': operation()}
    except BaseException as exc:
        return {'exception_type': type(exc).__name__, 'message': str(exc),
                'code': getattr(exc, 'code', None)}


def rows(service_):
    return [tuple(row) for row in service_.store.db.execute('SELECT * FROM cursors ORDER BY id')]


cases = [('empty', b'', 512), ('ascii-cursor', b'abcdef', 2),
         ('utf8-3-boundary', 'A雪Z'.encode(), 3), ('utf8-4-boundary', 'A🦉Z'.encode(), 4),
         ('invalid-late-byte', b'abcdef\xff', 3), ('invalid-surrogate', b'\xed\xa0\x80Z', 2),
         ('short-utf8-page', '雪'.encode(), 1), ('control-string', b'\x00"\\\n' * 5, 12)]
report = {'scope': 'EXPLICIT_DEVELOPMENT_NATIVE_PAGE_AND_WIRE_DIFFERENTIAL',
          'policy_manifest': manifest, 'wire_image_sha256': wire.image_sha256,
          'source_before': before, 'observations': [], 'whole_native_delivery_qualified': False}
started = time.monotonic()
try:
    with patch.dict(os.environ, {}, clear=True):
        for name, data, limit in cases:
            ref = {'id': 'a-test', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://test'}
            args = {'artifact': ref, 'max_bytes': limit}
            old, new = service(data), service(data)
            try:
                expected = observed(lambda: service_module.HIAAgentService._hia_read(old, args))
                with (patch.object(service_module.HIAAgentService, '_hia_read', side_effect=AssertionError('retained page owner')),
                      patch.object(service_module, 'digest', side_effect=AssertionError('retained cursor digest')),
                      patch.object(service_module.base64, 'b64encode', side_effect=AssertionError('retained base64 encoder')),
                      patch.object(service_module, 'wire', side_effect=AssertionError('retained page wire caller'))):
                    actual = observed(lambda: owner.read(new, args))
                assert actual == expected, (name, actual, expected)
                assert rows(new) == rows(old), (name, rows(new), rows(old))
                assert actual['returned']['artifact'] is ref
                report['observations'].append({'case': name, 'source_bytes': len(data),
                                               'result': actual, 'cursor_rows': rows(new), 'alias_preserved': True})
                cursor = actual['returned']['next_cursor']
                if cursor is not None:
                    again = {**args, 'cursor': cursor}
                    expected_again = observed(lambda: service_module.HIAAgentService._hia_read(old, again))
                    actual_again = observed(lambda: owner.read(new, again))
                    assert actual_again == expected_again, (name, actual_again, expected_again)
                    assert rows(new) == rows(old)
                    bad = {**again, 'artifact': {**ref, 'sha256': 'f' * 64}}
                    bad_expected = observed(lambda: service_module.HIAAgentService._hia_read(old, bad))
                    bad_actual = observed(lambda: owner.read(new, bad))
                    assert bad_actual == bad_expected, (name, bad_actual, bad_expected)
                    assert bad_actual['code'] == 'E_HIA_CURSOR'
                    report['observations'][-1].update(second_page_equal=True, cross_digest_cursor_rejected=True)
            finally:
                old.store.db.close()
                new.store.db.close()
    report['status'] = 'DEVELOPMENT_NATIVE_CONTROLS_PASS'
except BaseException as exc:
    report.update(status='DEVELOPMENT_NATIVE_HOLD', error=repr(exc))
    (FOLDER / 'native-r1.stderr.log').write_text(traceback.format_exc())
report['source_after'] = {str(p): sha256(p.read_bytes()).hexdigest() for p in paths}
if before != report['source_after']:
    report['status'] = 'DEVELOPMENT_NATIVE_HOLD'
    report['source_drift'] = True
report['seconds'] = time.monotonic() - started
(FOLDER / 'native-r1.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
print(json.dumps({'status': report['status'], 'cases': len(report['observations']),
                  'seconds': report['seconds'], 'error': report.get('error'), 'source_preserved': before == report['source_after']}))
raise SystemExit(0 if report['status'] == 'DEVELOPMENT_NATIVE_CONTROLS_PASS' else 1)
