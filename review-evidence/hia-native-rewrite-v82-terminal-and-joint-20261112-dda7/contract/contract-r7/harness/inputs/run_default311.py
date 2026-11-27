"""Actual original/public default comparison and explicit unsupported admission."""
from pathlib import Path
import json
import os
import sys
from unittest.mock import patch

root = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir()
sys.path.insert(0, str(root))
assert sys.version_info[:2] == (3, 11)
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_'):
        del os.environ[key]
from hepta import hia_agent_contract as api
from hepta import hia_agent_contract_selection as selection
from tests.hia_agent_contract_fixtures import ordinary_cases, namespace, outcome, SELECTOR

rows = []
for name, arguments, keywords in ordinary_cases():
    old = outcome(namespace()[name], *arguments, **keywords)
    new = outcome(getattr(api, name), *arguments, **keywords)
    rows.append({'entry': name, 'arguments': repr(arguments), 'original': old, 'public': new, 'equal': old == new})
assert len(rows) == 65
assert 'hepta.hia_agent_contract_native' not in sys.modules
assert 'hepta.hia_agent_contract_foreign' not in sys.modules
assert selection.capture_agent_contract() is None
with selection.held_agent_contract_scope(None), patch.dict(os.environ, {SELECTOR: '/unsupported/ambient'}):
    assert selection.selected_agent_contract() is None
    assert api._valid(1, True)
from hepta.hia_json_preflight_native import NativeHiaJsonImage
mapped = []
def forbidden(*args, **kwargs):
    mapped.append(True)
    raise AssertionError('unsupported contract mapped an executable')
with patch.object(NativeHiaJsonImage, '__init__', forbidden), patch.dict(os.environ, {SELECTOR: '/unsupported/manifest'}):
    try:
        api._valid(1, True)
    except RuntimeError as error:
        refusal = {'type': type(error).__name__, 'message': str(error)}
        assert 'agent-contract' in str(error) and 'reviewed CPython ABI' in str(error)
    else:
        raise AssertionError('unreviewed CPython ABI was admitted')
assert not mapped
passed = all(row['equal'] for row in rows)
report = {'schema': 'hia.agent-contract.default311.v1', 'status': 'PASS' if passed else 'FAIL',
    'scope': 'ORIGINAL_DEFAULT_MATCH_AND_EXPLICIT_UNSUPPORTED_NATIVE_REFUSAL',
    'python': sys.version, 'rows': rows, 'count': len(rows), 'native_mappings': len(mapped),
    'unsupported_refusal': refusal,
    'original_baseline_exceptions': [row for row in rows if row['original'][0] == 'error'],
    'baseline_exceptions_are_not_reclassified_as_successful_policy_results': True,
    'current_cold': False, 'whole': False, 'default_replaced': False}
(out / 'REPORT.json').write_text(json.dumps(report, indent=2, default=repr) + '\n')
print(json.dumps({'status': report['status'], 'count': len(rows), 'native_mappings': 0,
                  'baseline_exception_count': len(report['original_baseline_exceptions'])}))
raise SystemExit(0 if passed else 1)
