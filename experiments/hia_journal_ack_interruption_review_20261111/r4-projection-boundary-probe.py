"""Small independent first-refusal comparison at the legacy numeric mask boundary."""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(sys.argv[1])
MANIFEST = Path(sys.argv[2])
OUTPUT = Path(sys.argv[3])
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_journal_native import installed_agent_journal
from hepta.hia_agent_store import decode_data, wire

image = installed_agent_journal(str(MANIFEST))
cases = ['"\\u"123456e7', '"\\uG"12345e7', '"\\u00"12345e7', '"\\u𐐷"12345e7']
results = []
def observe(fn):
    try:
        return {'value': fn()}
    except BaseException as exc:
        return {'type': type(exc).__name__, 'message': str(exc)}
with patch.dict(os.environ, {
    'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST': '',
    'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST': '',
    'HEPTA_HIA_AGENT_BINARY64_MANIFEST': '',
}):
    for text in cases:
        session = image.session()
        session.prepare(wire({'tool': 'hia_artifact', 'arguments': {'request_key': 'projection'}}))
        session.lookup({'digest': session.request_digest, 'state': 'completed'})
        reference = observe(lambda: decode_data(text))
        native = observe(lambda: session.cached(text))
        results.append({'input': text, 'reference': reference, 'native': native, 'equal': reference == native})
output = {'manifest': str(MANIFEST), 'manifest_data': json.loads(MANIFEST.read_bytes()), 'cases': results}
with OUTPUT.open('x') as handle:
    json.dump(output, handle, ensure_ascii=False, sort_keys=True, indent=2)
    handle.write('\n')
print(json.dumps(output, ensure_ascii=False, sort_keys=True))
raise SystemExit(0 if all(row['equal'] for row in results) else 1)
