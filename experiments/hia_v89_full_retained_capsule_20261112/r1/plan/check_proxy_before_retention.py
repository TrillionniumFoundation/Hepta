"""Finite source-only proxy admission controls; no network, owner or product.

Execute only the exact require/clean_environment AST from the frozen source.
The environment object is a synthetic mapping, never the process environment.
"""
from pathlib import Path
from hashlib import sha256, sha1
from types import SimpleNamespace
import ast
import json
import sys
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
KEYS = ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')
GOOD = (
    '', 'http://proxy.example:8080', 'https://proxy.example:443',
    'proxy.example:8080', '[::1]:8080', 'http://[::1]:8080',
    'socks5://proxy.example:1080',
)
BAD = (
    'http://synthetic-user:synthetic-password@proxy.example:8080',
    'http://synthetic-user@proxy.example:8080',
    'http://:synthetic-password@proxy.example:8080',
    'http://proxy.example:8080/?token=synthetic-query-secret',
    'http://proxy.example:8080/#synthetic-fragment-secret',
    'synthetic-user:synthetic-password@proxy.example:8080',
    '//synthetic-user:synthetic-password@proxy.example:8080',
    'http://synthetic%40user:synthetic%3Apassword@proxy.example:8080',
    'http://[broken', 'http://proxy.example:synthetic-port-secret',
    'http://proxy.example:8080\n', 'http://proxy.example:\t8080',
)
SAFE_ERRORS = {
    'malformed proxy cannot enter retained capsule requests',
    'credential-bearing proxy cannot enter retained capsule requests',
}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def load_exact(raw):
    module = ast.parse(raw)
    nodes = [node for node in module.body if isinstance(node, ast.FunctionDef)
             and node.name in {'require', 'clean_environment'}]
    assert [node.name for node in nodes] == ['require', 'clean_environment']
    namespace = {'os': SimpleNamespace(environ={}), 'urllib': SimpleNamespace(parse=urllib.parse)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<exact frozen proxy functions>', 'exec'), namespace)
    return namespace


def main():
    source = ROOT / 'control/full_common.py'
    before = source.read_bytes()
    space = load_exact(before)
    rows = []

    def attempt(name, environment, network, expected_failure=False):
        fixture = dict(environment)
        space['os'].environ = fixture
        serialized = []
        try:
            output = space['clean_environment'](network=network)
            # This is a synthetic stand-in for the downstream retained request.
            # It is reached only after the real admission function returns.
            serialized.append(json.dumps({'env': output}, sort_keys=True))
        except ValueError as error:
            assert expected_failure and not serialized
            assert str(error) in SAFE_ERRORS
            assert fixture == environment
            rows.append({'name': name, 'passed': True, 'refused_before_serialization': True,
                         'serialization_calls': 0, 'safe_error': str(error)})
            return None
        assert not expected_failure
        assert fixture == environment and len(serialized) == 1
        rows.append({'name': name, 'passed': True, 'refused_before_serialization': False,
                     'serialization_calls': 1, 'inherited_mapping_unchanged': True})
        return output

    for key in KEYS:
        for index, value in enumerate(GOOD):
            result = attempt(f'{key}.preserve-valid-{index:02d}', {key: value, 'PATH': '/synthetic/path'}, True)
            assert result[key] == value and result['PATH'] == '/synthetic/path'
        for index, value in enumerate(BAD):
            attempt(f'{key}.refuse-unsafe-{index:02d}', {key: value}, True, True)
        for index, value in enumerate((0, False, None)):
            attempt(f'{key}.refuse-nontext-{index:02d}', {key: value}, True, True)
        result = attempt(f'{key}.product-network-false-excludes-proxy', {key: BAD[0]}, False)
        assert key not in result
    combined = {key: 'http://proxy.example:8080' for key in KEYS}
    combined.update(no_proxy='localhost,127.0.0.1,.example,::1', NO_PROXY='localhost,.example',
                    SSL_CERT_FILE='/synthetic/ca.pem', GITHUB_TOKEN='synthetic-token-must-be-excluded')
    result = attempt('preserve-all-routing-and-CA-without-token', combined, True)
    assert all(result[key] == value for key, value in combined.items() if key != 'GITHUB_TOKEN')
    assert 'GITHUB_TOKEN' not in result
    assert source.read_bytes() == before
    self_raw = Path(__file__).read_bytes()
    report = {'schema': 'hia.v88.full-capsule.proxy-source-controls.v1',
              'status': 'FINITE_PROXY_SOURCE_CONTROLS_PASS', 'expected': 139,
              'loaded': len(rows), 'executed': len(rows), 'controls': rows,
              'source': pin(before), 'script': pin(self_raw),
              'interpreter': sys.version, 'actual_process_environment_reassigned': False,
              'network_or_owner_or_product_executed': False,
              'scope': 'Synthetic proxy mappings and exact frozen function bodies. No package/network/tool supply, native test, or qualification claim.'}
    assert len(rows) == report['expected']
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
