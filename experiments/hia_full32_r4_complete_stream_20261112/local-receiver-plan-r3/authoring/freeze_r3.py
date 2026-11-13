"""Refresh only this unexecuted r3 request's source pins and review artifacts."""
from pathlib import Path
import ast
import difflib
import hashlib
import json

ROOT = Path(__file__).resolve().parent.parent
OLD = Path('/tmp/hia-full32-r4-gzip-stream-reader-plan-r2-20261112-e26e')

def raw_pin(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def doc(name, value):
    path = ROOT / name
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.chmod(0o600)

def definitions(path):
    text = path.read_text(); lines = text.splitlines(keepends=True)
    return {node.name: ''.join(lines[node.lineno - 1:node.end_lineno])
            for node in ast.parse(text).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}

def main():
    policy = json.loads((ROOT / 'POLICY.json').read_bytes())
    reference = 'reference/http-client-3.12.14.original.py'
    names = list(policy['inputs'])
    if reference not in names:
        names.append(reference)
    policy['inputs'] = {name: raw_pin(ROOT / name) for name in names}
    policy['private_proxy_protocol']['TLS_context_factory'] = 'Pinned CPython http.client._create_https_context(11): original CA loading, ALPN http/1.1 and optional post_handshake_auth'
    doc('POLICY.json', policy)
    request = json.loads((ROOT / 'CONTROL-REQUEST.json').read_bytes())
    control_names = list(request['inputs'])
    if reference not in control_names:
        control_names.append(reference)
    request['inputs'] = {name: raw_pin(ROOT / name) for name in control_names}
    doc('CONTROL-REQUEST.json', request)
    launch = json.loads((ROOT / 'LAUNCH.json').read_bytes())
    launch['policy'] = {'path': str(ROOT / 'POLICY.json'), **raw_pin(ROOT / 'POLICY.json')}
    doc('LAUNCH.json', launch)
    plan = json.loads((ROOT / 'PLAN.json').read_bytes())
    plan['phases'][0]['action'] = plan['phases'][0]['action'].replace('31source', '32source')
    plan['private_proxy'] = policy['private_proxy_protocol']
    plan['source_control_changes']['method23_preserves_TLS_ALPN_and_PHA'] = True
    plan['history'] = {'unexecuted_tls_context_draft': 'history/unexecuted-tls-context-draft',
                       'reason': 'Peer found bare SSLContext would omit default HTTP/1.1 ALPN and optional PHA; final uses original helper.'}
    doc('PLAN.json', plan)
    old_policy = json.loads((OLD / 'POLICY.json').read_bytes())
    assert policy['limits'] == old_policy['limits']
    assert policy['parts'] == old_policy['parts']
    assert policy['original_full32_limits'] == old_policy['original_full32_limits']
    assert request['expected_ids'] == json.loads((OLD / 'CONTROL-REQUEST.json').read_bytes())['expected_ids']
    assert request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
    old_defs = definitions(OLD / 'control/local_io.py')
    new_defs = definitions(ROOT / 'control/local_io.py')
    unchanged = [name for name in old_defs if name not in ('configured_environment', 'download')]
    assert all(old_defs[name] == new_defs[name] for name in unchanged)
    old_test = ast.parse((OLD / 'controls/check_stream_consumer.py').read_bytes())
    new_test = ast.parse((ROOT / 'controls/check_stream_consumer.py').read_bytes())
    methods = lambda tree: {node.name: ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}
    a, b = methods(old_test), methods(new_test)
    assert list(a) == list(b) and len(a) == 24
    changed_methods = [name for name in a if a[name] != b[name]]
    assert changed_methods == ['test_23_configured_proxy_kept_or_rejected_before_serialization']
    for name in ('control/stream_format.py', 'control/guardian.py', 'control/process_owner_impl.py',
                 'controls/run_controls.py'):
        assert (ROOT / name).read_bytes() == (OLD / name).read_bytes()
    scripts = []
    for name in names:
        if name.endswith('.py'):
            ast.parse((ROOT / name).read_bytes(), filename=name)
            scripts.append(name)
    changed = [name for name in names if (OLD / name).exists() and (ROOT / name).read_bytes() != (OLD / name).read_bytes()]
    changed += ['POLICY.json', 'CONTROL-REQUEST.json', 'LAUNCH.json', 'PLAN.json']
    patch = ''.join(''.join(difflib.unified_diff((OLD / name).read_text().splitlines(keepends=True),
                 (ROOT / name).read_text().splitlines(keepends=True), fromfile='r2/' + name, tofile='r3/' + name))
                    for name in changed)
    (ROOT / 'REVISION-r3.patch').write_text(patch)
    (ROOT / 'REVISION-r3.patch').chmod(0o600)
    doc('STATIC-PINS.json', {'schema': 'hia.full32.private-proxy-static-pins.v1',
        'AST_parse_only': scripts, 'input_count': len(names), 'control_input_count': len(control_names),
        'source_control_count': 24, 'same_control_IDs': request['expected_ids'],
        'only_changed_control_body': changed_methods, 'old_IO_definitions_byte_equal': unchanged,
        'whole_stream_guardian_owner_runner_unchanged': True,
        'all_transfer_storage_and_product_limits_equal_r2': True,
        'tests_requests_provider_GET_or_private_capture_executed': False,
        'files': {name: raw_pin(ROOT / name) for name in names +
                  ['POLICY.json', 'CONTROL-REQUEST.json', 'LAUNCH.json', 'PLAN.json',
                   'PRIVATE-PROXY-SCHEMA.json', 'REVISION-NOTES.json', 'REVISION-r3.patch']}})
    print(json.dumps({'policy': raw_pin(ROOT / 'POLICY.json'), 'request': raw_pin(ROOT / 'CONTROL-REQUEST.json'),
        'launch': raw_pin(ROOT / 'LAUNCH.json'), 'inputs': len(names), 'control_inputs': len(control_names),
        'AST_only_scripts': len(scripts), 'source24_executed': False, 'GETs': 0}, sort_keys=True))

if __name__ == '__main__':
    main()
