"""Exercise native catalog, artifact capture and resource-URI decisions."""
from pathlib import Path
from hashlib import sha256
import argparse
import copy
import ctypes
import json
import mmap
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_mcp_service_admission import (
    CAPTURE_REFUSED, CATALOG_CHANGED, OUTPUT_BYTES, RESOURCE_REFUSED,
    SOURCE, WORKSPACE_BYTES, render,
)
from tools.qualify_hia_mcp_service_config import expected, fixture


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flat', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    source = (root / SOURCE).read_bytes()
    assert source.decode() == render()
    flat = args.flat.read_bytes()
    image = mmap.mmap(-1, len(flat), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    image.write(flat)
    entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                             ctypes.c_size_t)(ctypes.addressof(ctypes.c_ubyte.from_buffer(image)))
    output = ctypes.create_string_buffer(OUTPUT_BYTES)
    workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
    context = expected(fixture())
    cases = []

    def invoke(name, role, arguments, *, ctx=None, want=None, refusal=None):
        value = {'context': context if ctx is None else ctx, 'arguments': arguments, 'tool': role}
        raw = compact(value)
        buf = ctypes.create_string_buffer(raw)
        result = entry(buf, len(raw), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        row = {'name': name, 'input_sha256': sha256(raw).hexdigest(), 'status': result}
        if refusal is not None:
            assert result == refusal, (name, result, refusal)
        else:
            assert 0 < result <= OUTPUT_BYTES, (name, result)
            expected_wire = compact(arguments if want is None else want)
            got = output.raw[:result]
            assert got == expected_wire, (name, got, expected_wire)
            row['output_sha256'] = sha256(got).hexdigest()
        cases.append(row)

    for role in range(1, 12):
        arguments = {'catalog_sha256': 'c' * 64, 'kept': {'array': [1, True, None], 'text': '中😀'}}
        if role == 2:
            arguments['source'] = {'kind': 'text', 'text': 'retained'}
        invoke('ordinal-' + str(role) + '-identity', role, arguments)
        if role != 1:
            invoke('ordinal-' + str(role) + '-catalog-change', role,
                   {**arguments, 'catalog_sha256': 'd' * 64}, refusal=CATALOG_CHANGED)
            missing = dict(arguments)
            del missing['catalog_sha256']
            invoke('ordinal-' + str(role) + '-missing-catalog', role, missing, refusal=CATALOG_CHANGED)

    def capture(name, path, selected=None, *, ctx=None, refusal=False):
        arguments = {'catalog_sha256': 'c' * 64, 'request_key': 'same-original-key',
                     'source': {'kind': 'path', 'path': path}, 'kept': ['same', {'n': 17}]}
        want = copy.deepcopy(arguments)
        if selected is not None:
            want['source']['path'] = selected
        invoke(name, 2, arguments, ctx=ctx, want=want, refusal=CAPTURE_REFUSED if refusal else None)

    for path in ('/srv/artifacts/a', '/srv//artifacts/a', '/srv/artifacts/',
                 '/srv/artifacts/中😀', '/srv/artifacts/a\tb', '/srv/artifacts/a"b\\c'):
        capture('bare-' + path, path)
    for scheme in ('ssh://', 'sftp://'):
        for alias in ('rog', 'rog-test', '[rog]', '[rog]ignored'):
            capture(scheme + alias, scheme + alias + '/srv/artifacts/a', '/srv/artifacts/a')
    for path in ('relative', 'file:///srv/artifacts/a', 'http://rog/srv/artifacts/a',
                 'ssh://else/srv/artifacts/a', 'ssh://user@rog/srv/artifacts/a',
                 'ssh://rog:22/srv/artifacts/a', 'ssh://rog:garbage/srv/artifacts/a',
                 'ssh://[rog]:22/srv/artifacts/a', 'ssh://rog/srv/artifacts/a@b',
                 '/srv/artifacts/../secret', '/srv/artifacts/./a', '/srv/artifacts2/a',
                 '/srv/artifacts/a\n', '/srv/artifacts/a\r', '/srv/artifacts/a\x00',
                 'ssh:///srv/artifacts/a', ''):
        capture('refuse-' + path, path, refusal=True)
    ctx = copy.deepcopy(context)
    ctx['profile']['artifact_roots'].append('/~')
    ctx['host']['allowed_read_path_prefixes'].append('/~')
    capture('remote-no-path-original-default', 'ssh://rog', '/~', ctx=ctx)
    ctx = copy.deepcopy(context)
    ctx['aliases'] = [['rog', '[rog']]
    capture('unclosed-bracket-original-alias', 'ssh://[rog/srv/artifacts/a', '/srv/artifacts/a', ctx=ctx)
    for order in (0, 1):
        ctx = copy.deepcopy(context)
        ctx['aliases'] = [['rog', 'rog-test'], ['aaa', 'rog']]
        if order:
            ctx['aliases'].reverse()
        capture('lexicographically-first-foreign-alias-' + str(order), '/srv/artifacts/a', ctx=ctx, refusal=True)
    ctx = copy.deepcopy(context)
    ctx['aliases'] = [['zzz', 'rog'], ['rog', 'rog-test']]
    capture('lexicographically-first-selected-alias', 'ssh://rog/srv/artifacts/a', '/srv/artifacts/a', ctx=ctx)
    ctx = copy.deepcopy(context)
    ctx['host']['protected_path_prefixes'] = ['/srv/artifacts/private']
    capture('protected-artifact-path', '/srv/artifacts/private/a', ctx=ctx, refusal=True)
    ctx = copy.deepcopy(context)
    ctx['host']['allowed_read_path_prefixes'] = ['/srv/hia']
    capture('outside-host-read-roots', '/srv/artifacts/a', ctx=ctx, refusal=True)
    ctx = copy.deepcopy(context)
    ctx['profile']['artifact_roots'] = []
    capture('outside-profile-artifact-roots', '/srv/artifacts/a', ctx=ctx, refusal=True)

    for uri in ('hia://artifacts/a', 'hia://artifacts/A0._~-', 'hia://artifacts/' + 'x' * 192):
        for bound in (None, 512, 65536):
            arguments = {'uri': uri}
            if bound is not None:
                arguments['max_bytes'] = bound
            invoke('resource-' + str(len(uri)) + '-' + str(bound), 12, arguments)
    for uri in ('hia://artifacts/', 'hia://artifacts/_a', 'hia://artifacts/' + 'x' * 193,
                'hia://artifacts/a/b', 'hia://artifacts/a?b', 'hia://artifacts/中',
                'HIA://artifacts/a', 'ssh://rog/srv/artifacts/a'):
        invoke('bad-resource-' + uri[:60], 12, {'uri': uri}, refusal=RESOURCE_REFUSED)
    for bound in (0, 511, 65537, 512.0, '512', None, True):
        invoke('bad-resource-bound-' + str(bound), 12, {'uri': 'hia://artifacts/a', 'max_bytes': bound},
               refusal=RESOURCE_REFUSED)
    invoke('resource-unknown-field', 12, {'uri': 'hia://artifacts/a', 'extra': 0}, refusal=RESOURCE_REFUSED)
    assert args.flat.read_bytes() == flat and (root / SOURCE).read_bytes() == source
    report = {'scope': 'NATIVE_MCP_CATALOG_CAPTURE_RESOURCE_COMPONENT', 'passed': True,
              'count': len(cases), 'flat_sha256': sha256(flat).hexdigest(),
              'source_sha256': sha256(source).hexdigest(),
              'requires_authenticated_context_and_independent_input_schema': True,
              'original_request_key_and_nonpath_bytes_preserved': True,
              'whole_mcp_server_qualified': False, 'cases': cases}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases), 'flat_sha256': report['flat_sha256']}), flush=True)
    del entry
    image.close()


if __name__ == '__main__':
    main()
