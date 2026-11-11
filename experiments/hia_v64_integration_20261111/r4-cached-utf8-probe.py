"""Compare retained and actual native cached-BLOB refusal precedence."""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path('/workspace/scratch/e26ed3e2edcf/Hepta')
MANIFEST = Path('/workspace/scratch/e26ed3e2edcf/journal-recovered-development-r4/manifest.json')
DEST = Path('/workspace/scratch/e26ed3e2edcf/journal-v64-cached-utf8-recheck')
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_journal_native import SELECTOR, installed_agent_journal
from hepta.hia_agent_store import wire

DEST.mkdir(exist_ok=False)
image = installed_agent_journal(str(MANIFEST))
manifest = json.loads(MANIFEST.read_bytes())
assert sha256((ROOT / 'examples/hia_bootstrap/agent_journal.hiaasm').read_bytes()).hexdigest() == manifest['source_sha256']
payloads = {
    'invalid-start': b'"\xff"',
    'invalid-continuation': b'"\xe2("',
    'truncated-codepoint': b'"\xe2\x82',
    'encoded-surrogate': b'"\xed\xa0\x80"',
    'invalid-before-size-limit': b'\xff' + b' ' * (8 << 20),
}
records = []
for name, payload in payloads.items():
    outcomes = []
    for native in (False, True):
        service = HIAAgentService(DEST / (name + ('-native' if native else '-reference')))
        arguments = {'request_key': 'cache-utf8'}
        identity = image.session()
        identity.prepare(wire({'tool': 'hia_artifact', 'arguments': arguments}))
        service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
            (identity.key, identity.request_digest, 'hia_artifact', 'completed', payload, '1'))
        with ExitStack() as stack:
            stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1, 9]))
            stack.enter_context(patch.object(service, '_hia_artifact', side_effect=AssertionError('cached refusal reexecuted effect')))
            if native:
                stack.enter_context(patch.dict(os.environ, {SELECTOR: str(MANIFEST)}))
                stack.enter_context(patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('native fallback')))
            response = service.call('hia_artifact', arguments) if native else service._reference_call('hia_artifact', arguments)
        retained = service.store.db.execute('SELECT response FROM requests WHERE key=?', (identity.key,)).fetchone()[0]
        costs = [dict(row) for row in service.store.db.execute('SELECT * FROM costs')]
        service.close()
        assert type(retained) is bytes and retained == payload
        outcomes.append({'native': native, 'response': response, 'costs': costs, 'cached_blob_preserved': True})
    records.append({'case': name, 'payload_bytes': len(payload), 'payload_sha256': sha256(payload).hexdigest(),
                    'equal': outcomes[0]['response'] == outcomes[1]['response'] and outcomes[0]['costs'] == outcomes[1]['costs'],
                    'outcomes': outcomes})
report = {'schema': 'hia.journal-independent-cached-utf8-review.v1',
          'source_commit': 'd9d96d388c559ddb683c77215e78abe8f9900f99', 'source_root': str(ROOT),
          'source_sha256': manifest['source_sha256'], 'image_sha256': image.image_sha256,
          'scope': 'DEVELOPMENT_ONLY: original cached SQLite BLOB bytes and actual native image',
          'records': records, 'mismatch_cases': [x['case'] for x in records if not x['equal']]}
(DEST / 'audit.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'cases': len(records), 'mismatch_cases': report['mismatch_cases'], 'report': str(DEST / 'audit.json')}))
