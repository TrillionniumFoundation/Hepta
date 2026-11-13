"""Adapt the prior readonly failure audit to the exact closed r3 failure."""
import ast
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-failure-r2b-20261112-e26e/audit_originals.py')
raw = OLD.read_bytes()
text = raw.decode()
replacements = [
    ('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e', '/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e'),
    ('/tmp/hia-cli-json-c-runtime-lifetime-actual-r2b-20261112-e26e', '/tmp/hia-cli-json-c-runtime-lifetime-actual-r3-20261112-e26e'),
    ('/tmp/hia-cli-json-c-runtime-lifetime-failure-r2b-20261112-e26e', str(ROOT)),
    ('5f1c4f6bc7f8ebdf3b3e3c9c17f543a6281346d0', '7e2d37f425987c827a09f5cd0207595fd86e2e56'),
    ('82380a6976d8618ef386f092b27fc8f76780236eeb7b1e02038b2697d2b2b766', '3c9057cc8b1ed7722beb6a7f9cdca01571459290b66b0334263f0eeb908d00b7'),
    ('2e97663689dd224aab5717bb0c97a87f4f48e19e6079949e01d19b420cd76b74', '29e590a10fe3d32ef911aa19db6b73eb3cc2a0681d004c45b3bd653fb12d4849'),
    ('cli-c-runtime-lifetime-invocation-r2b', 'cli-c-runtime-lifetime-invocation-r3'),
    ('cli-c-runtime-lifetime-review-r2b', 'cli-c-runtime-lifetime-review-r3'),
    ('review_cli_finite_r2b_inputs.py', 'review_cli_finite_r3_inputs.py'),
    ('invoke_cli_finite_r2b_once.py', 'invoke_cli_finite_r3_once.py'),
    ('audit_cli_finite_r2b_actual.py', 'audit_cli_finite_r3_actual.py'),
    ('capture_closed(ACTUAL / \'work\', 32 << 20)', 'capture_closed(ACTUAL / \'work\', 64 << 20)'),
    ("len(inventory['rows']) == 34", "len(inventory['rows']) == 35"),
    ('3906208', '3907508'),
    ("case, case_pin, _ = obj(ACTUAL / ('work/runtime/' + policy['runtime_ids'][0] + '.json'))",
     "passed_case, passed_case_pin, _ = obj(ACTUAL / ('work/runtime/' + policy['runtime_ids'][0] + '.json'))\n    case, case_pin, _ = obj(ACTUAL / ('work/runtime/' + policy['runtime_ids'][1] + '.json'))"),
    ("runtime['loaded_ids'] == policy['runtime_ids'][:1] and runtime['executed_ids'] == []",
     "runtime['loaded_ids'] == policy['runtime_ids'][:2] and runtime['executed_ids'] == policy['runtime_ids'][:1]"),
    ("runtime['outcomes'] == [case] and case['status'] == 'HOLD'",
     "runtime['outcomes'] == [passed_case,case] and passed_case['status'] == 'PASS' and case['status'] == 'HOLD'"),
    ('undefined symbol: _PyErr_SetRaisedException', 'runtime ELF profile differs'),
    ("tls = [x for x in symbols if x['section'] == 0 and x['name'] == '_PyErr_SetRaisedException']\n    check('actual-ELF-undefined-raised-setter', len(tls) == 1 and tls[0]['type'] == 0)",
     "old_missing = [x for x in symbols if x['section'] == 0 and x['name'] in ('_PyErr_SetRaisedException','_Py_tss_tstate')]\n    check('actual-ELF-old-unavailable-imports-absent', old_missing == [])"),
    ('0d2a0d0085a851e77d463561025d7537915fa421298c058f92e0fc836023cf1d', '8d205b2b0c08ff12ecec8fe0a4d8cd8131a21c0137973b68565f0f6db28dca09'),
    ('75a56b7d3d317a2361f2e3b4ca71421b6cfc27508e49441a402c8806aec90164', '4a3fae22a312f457546301bdca9ccb4da65feb6341613bd1797f833eba1fcd78'),
    ("root_readback['runtime_completed'] == 0", "root_readback['runtime_completed'] == 1"),
    ("check('complete-actual-41-copied', sum(x['path'].startswith('originals/actual/') for x in originals) == 41)",
     "check('complete-actual-42-copied', sum(x['path'].startswith('originals/actual/') for x in originals) == 42)"),
    ('hia.cli-json.finite-r2b-failure-originals.v1', 'hia.cli-json.finite-r3-failure-originals.v1'),
    ('hia.cli-json.finite-r2b-independent-failure-readback.v1', 'hia.cli-json.finite-r3-independent-failure-readback.v1'),
    ("'runtime_report':runtime_pin,'failed_case':case_pin,", "'runtime_report':runtime_pin,'passed_case':passed_case_pin,'failed_case':case_pin,"),
    ("'runtime_executed_ids':[]", "'runtime_executed_ids':runtime['executed_ids']"),
    ("'actual_work_namespace_rows':34", "'actual_work_namespace_rows':35"),
    ("'actual_regular_originals':41", "'actual_regular_originals':42"),
]
counts = []
for before, after in replacements:
    count = text.count(before)
    assert count > 0, before
    counts.append({'before': before, 'after': after, 'count': count})
    text = text.replace(before, after)
result = text.encode()
ast.parse(result)
for name, payload in [
    ('audit_originals.py', result),
    ('ADAPTATION.json', (json.dumps({'schema': 'hia.cli-json.r3-failure-reader-adaptation.v1',
        'original_path': str(OLD), 'original_sha256': hashlib.sha256(raw).hexdigest(),
        'new_sha256': hashlib.sha256(result).hexdigest(), 'exact_replacements': counts,
        'new_qualification_executed': False, 'same_unchanged_owner_and_actual_output_readers': True,
        'capture_limit_64MiB_matches_original_launcher': True}, sort_keys=True) + '\n').encode())]:
    fd = os.open(ROOT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        at = 0
        while at < len(payload):
            n = os.write(fd, payload[at:]); assert n > 0; at += n
        os.fsync(fd)
    finally:
        os.close(fd)
    assert (ROOT / name).read_bytes() == payload
print(json.dumps({'status': 'READONLY_READER_AUTHORED_NOT_RUN', 'bytes': len(result),
                  'sha256': hashlib.sha256(result).hexdigest(), 'replacement_groups': len(counts)}))
