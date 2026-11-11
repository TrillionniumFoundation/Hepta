"""Small independent Core VM witness; explicit development wire image only."""
import ctypes
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import resource
import sqlite3
import sys
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path('/workspace/scratch/e26ed3e2edcf/hia-native-wire-entry')
FOLDER = Path('/tmp/hia-artifact-page-draft')
sys.path.insert(0, str(ROOT))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from hepta.hia_json_wire_native import installed_json_wire
from hepta.hia_agent_service import HIAAgentService

spec = importlib.util.spec_from_file_location('hepta.hia_artifact_page_native', FOLDER / 'hia_artifact_page_native.py')
page = importlib.util.module_from_spec(spec)
spec.loader.exec_module(page)
source = (FOLDER / 'artifact_page.hiaasm').read_bytes()
program = assemble_program(source)
wire = installed_json_wire('/workspace/scratch/e26ed3e2edcf/wire-entry-development-r1/manifest.json')


class VM:
    def __init__(self):
        self.calls = 0

    def _entry(self, s, ns, o, no, w, nw):
        owners = [_Owner(-1, bytearray(ctypes.string_at(s, ns))),
                  _Owner(-2, bytearray(ctypes.string_at(o, no))),
                  _Owner(-3, bytearray(ctypes.string_at(w, nw)))]
        machine = _Machine(program, 10000000, 64 << 20, None, 128)
        result = machine.invoke(program.as_dict()['functions'][0],
                                [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        ctypes.memmove(o, bytes(owners[1].data), no)
        ctypes.memmove(w, bytes(owners[2].data), nw)
        self.calls += 1
        return result


def service(data):
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
    return SimpleNamespace(store=SimpleNamespace(get=lambda ref: (data, {}), db=db))


report = {'scope': 'INDEPENDENT_CORE_VM_POLICY_WITH_DEVELOPMENT_NATIVE_WIRE_ONLY',
          'policy_native_image_loaded': False, 'wire_image_sha256': wire.image_sha256,
          'policy_source_sha256': sha256(source).hexdigest(), 'observations': [],
          'whole_native_delivery_qualified': False}
started = time.monotonic()
try:
    with patch.dict(os.environ, {}, clear=True):
        for data, limit in ((b'', 512), ('雪!'.encode(), 512)):
            ref = {'id': 'a-test', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://test'}
            args = {'artifact': ref, 'max_bytes': limit}
            old, new = service(data), service(data)
            try:
                expected = HIAAgentService._hia_read(old, args)
                vm = VM()
                got = page.NativeArtifactPage(vm, wire).read(new, args)
                assert got == expected, (got, expected)
                assert got['artifact'] is ref
                assert new.store.db.execute('SELECT COUNT(*) FROM cursors').fetchone()[0] == 0
                report['observations'].append({'bytes': len(data), 'policy_vm_calls': vm.calls,
                                               'result': got, 'alias_preserved': True})
            finally:
                old.store.db.close()
                new.store.db.close()
    report['status'] = 'DEVELOPMENT_VM_CONTROLS_PASS'
except BaseException as exc:
    report.update(status='DEVELOPMENT_VM_HOLD', error=repr(exc))
    (FOLDER / 'vm-r1.stderr.log').write_text(traceback.format_exc())
report['seconds'] = time.monotonic() - started
(FOLDER / 'vm-r1.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
print(json.dumps(report, ensure_ascii=False))
raise SystemExit(0 if report['status'] == 'DEVELOPMENT_VM_CONTROLS_PASS' else 1)
