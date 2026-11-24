"""Exercise native HIA MCP envelopes against independent JSON expectations."""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import json
import mmap
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_mcp_service_reply import (
    INPUT_BYTES, RESPONSE_BYTES, SOURCE, WORKSPACE_BYTES, render,
)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flat', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / SOURCE).read_bytes()
    assert source.decode() == render()
    flat = args.flat.read_bytes()
    args.output.mkdir(mode=0o700, exist_ok=False)
    image = mmap.mmap(-1, len(flat), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    image.write(flat)
    entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                             ctypes.c_size_t)(ctypes.addressof(ctypes.c_ubyte.from_buffer(image)))
    workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
    output = ctypes.create_string_buffer(RESPONSE_BYTES)
    cases = []
    meta = {'resultType': 'complete', '_meta': {
        'io.modelcontextprotocol/serverInfo': {'name': 'hepta-hia', 'version': '1'}}}
    cache = {'cacheScope': 'private', 'ttlMs': 0}
    message = ('HIA resource read is pending or unavailable; repeat the same URI, '
               'or use hia_read with its original artifact reference')

    def invoke(name, value, expected=None, refusal=False, raw_id=None):
        wire = compact(value) if isinstance(value, dict) else value
        buf = ctypes.create_string_buffer(wire, max(1, len(wire)))
        status = entry(buf, len(wire), output, RESPONSE_BYTES, workspace, WORKSPACE_BYTES)
        record = {'name': name, 'input_sha256': sha256(wire).hexdigest(), 'status': status}
        if refusal:
            assert status > RESPONSE_BYTES, (name, status, output.raw[:256])
        else:
            assert 0 < status <= RESPONSE_BYTES, (name, status, output.raw[:256])
            answer = output.raw[:status]
            assert answer.endswith(b'\n') and answer.count(b'\n') == 1, (name, answer[:128])
            got = json.loads(answer)
            assert got == expected, (name, got, expected)
            if raw_id is not None:
                assert answer.startswith(b'{"jsonrpc":"2.0","id":' + raw_id + b','), name
            record['output_sha256'] = sha256(answer).hexdigest()
        cases.append(record)

    def request(kind, payload, *, modern=False, identifier='kept☺', uri=None):
        return {'id': identifier, 'kind': kind, 'modern': modern, 'payload': payload, 'uri': uri}

    def envelope(identifier, field, value):
        return {'jsonrpc': '2.0', 'id': identifier, field: value}

    for modern in (False, True):
        for label, payload in (('empty', {}), ('catalog', {'tools': [{'name': 'hia_describe'}]}),
                               ('resources', {'resources': []}), ('templates', {'resourceTemplates': []})):
            value = request(1, payload, modern=modern)
            expected = {**payload, **(cache if modern else {}), **(meta if modern else {})}
            invoke(f'result-{label}-{modern}', value, envelope(value['id'], 'result', expected))
        for status in ('completed', 'accepted', 'unknown', 'rejected'):
            payload = {'status': status, 'result': {'unicode': '中😀', 'escapes': '\\"\n\r\t\b\f\x00\x1f', 'float': 0.125}}
            value = request(2, payload, modern=modern)
            result = {'content': [{'type': 'text', 'text': compact(payload).decode()}],
                      'isError': status in ('rejected', 'unknown'), 'structuredContent': payload}
            if modern:
                result.update(meta)
            invoke(f'tool-{status}-{modern}', value, envelope(value['id'], 'result', result))
        for index, result in enumerate(({}, [], None, True, False, -17, 1.25, '中\n"\\')):
            payload = {'status': 'completed', 'result': result}
            value = request(4, payload, modern=modern, uri='hia://artifacts/中?a="\\')
            expected = {'contents': [{'uri': value['uri'], 'text': compact(result).decode()}]}
            if modern:
                expected.update(cache)
                expected.update(meta)
            invoke(f'resource-completed-{index}-{modern}', value, envelope(value['id'], 'result', expected))
        for status in ('accepted', 'unknown', 'rejected'):
            payload = {'status': status, 'reason': 'same key stays pending'}
            value = request(4, payload, modern=modern, uri='hia://artifacts/a')
            error = {'code': -32603, 'message': message, 'data': payload}
            invoke(f'resource-{status}-{modern}', value, envelope(value['id'], 'error', error))
    for identifier in (None, '', -9223372036854775808, 9223372036854775807):
        error = {'code': -32602, 'message': 'bad "argument"\n中', 'data': {'reason': 1}}
        value = request(3, error, identifier=identifier)
        invoke('error-id-' + str(identifier), value, envelope(identifier, 'error', error))
    identifier = b'"unchanged\\u263a\\\\\\\""'
    wire = b'{"id":' + identifier + b',"kind":1,"modern":false,"payload":{},"uri":null}'
    invoke('raw-escaped-id', wire, envelope(json.loads(identifier), 'result', {}), raw_id=identifier)
    valid = request(1, {})
    for key in tuple(valid):
        value = dict(valid)
        del value[key]
        invoke('missing-' + key, value, refusal=True)
    for name, changes in (
        ('unknown-field', {'extra': 0}), ('nonobject-payload', {'payload': []}),
        ('null-id-result', {'id': None}), ('boolean-id', {'id': True}),
        ('unsigned-id-overflow', {'id': 9223372036854775808}),
        ('signed-id-overflow', {'id': -9223372036854775809}),
        ('float-id', {'id': 1.5}), ('kind-zero', {'kind': 0}),
        ('kind-five', {'kind': 5}), ('kind-boolean', {'kind': True}),
        ('kind-float', {'kind': 1.0}), ('modern-string', {'modern': 'true'}),
        ('nonresource-uri', {'uri': 'hia://a'}), ('tool-no-status', {'kind': 2}),
        ('tool-unknown-status', {'kind': 2, 'payload': {'status': 'pending'}}),
        ('error-no-code', {'kind': 3, 'payload': {'message': 'bad'}}),
        ('error-float-code', {'kind': 3, 'payload': {'code': -1.5, 'message': 'bad'}}),
        ('error-message-array', {'kind': 3, 'payload': {'code': -1, 'message': []}}),
        ('resource-no-uri', {'kind': 4, 'payload': {'status': 'completed', 'result': {}}}),
        ('resource-no-result', {'kind': 4, 'uri': 'hia://a', 'payload': {'status': 'completed'}}),
    ):
        invoke(name, {**valid, **changes}, refusal=True)
    invoke('duplicate-field', b'{"id":1,"id":2,"kind":1,"modern":false,"payload":{},"uri":null}', refusal=True)
    invoke('invalid-json', b'{', refusal=True)
    small = compact(valid)
    invoke('exact-private-input-bound', b' ' * (INPUT_BYTES - len(small)) + small,
           envelope(valid['id'], 'result', {}))
    invoke('private-input-over-bound', b' ' * (INPUT_BYTES + 1), refusal=True)
    invoke('quoted-output-over-bound', request(2, {'status': 'completed', 'result': '"' * (3 << 20)}), refusal=True)
    assert args.flat.read_bytes() == flat and (root / SOURCE).read_bytes() == source
    report = {'scope': 'NATIVE_MCP_SERVICE_REPLY_COMPONENT', 'passed': True,
              'count': len(cases), 'flat_sha256': sha256(flat).hexdigest(),
              'source_sha256': sha256(source).hexdigest(), 'cases': cases,
              'grants_effect_authority': False, 'whole_mcp_server_qualified': False}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases), 'flat_sha256': report['flat_sha256']}), flush=True)
    del entry
    image.close()


if __name__ == '__main__':
    main()
