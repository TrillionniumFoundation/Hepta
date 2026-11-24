"""Exercise native HIA MCP service dispatch without granting tool authority."""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import json
import mmap
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_mcp_service_session import (
    DISPATCH, LIMIT, MODERN_VERSION, RESPONSE_BYTES, SOURCE, WORKSPACE_BYTES, render,
)
from tools.generate_hia_mcp_request import tool_names


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
    image_memory = mmap.mmap(-1, len(flat), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    image_memory.write(flat)
    address = ctypes.addressof(ctypes.c_ubyte.from_buffer(image_memory))
    entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                             ctypes.c_size_t)(address)
    workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
    output = ctypes.create_string_buffer(RESPONSE_BYTES)
    cases = []

    def fresh():
        ctypes.memset(workspace, 0, WORKSPACE_BYTES)

    def invoke(name, raw, *, action=None, tool=None, error=None, modern=0,
               identifier=None, arguments=None, notification=False):
        if isinstance(raw, dict):
            raw = json.dumps(raw, ensure_ascii=True, separators=(',', ':')).encode()
        value = ctypes.create_string_buffer(raw, max(1, len(raw)))
        result = entry(value, len(raw), output, RESPONSE_BYTES, workspace, WORKSPACE_BYTES)
        record = {'name': name, 'input_sha256': sha256(raw).hexdigest(), 'status': result}
        if action is not None:
            assert result == DISPATCH, (name, result, output.raw[:256])
            magic, *words = struct.unpack('<8s11Q', output.raw[:96])
            selected, id_at, id_size, ordinal, arg_at, arg_size, inline, params_at, params_size, z0, z1 = words
            assert (magic, selected, inline, z0, z1) == (b'HIAMSQ01', action, modern, 0, 0), name
            assert id_at + id_size <= len(raw) and id_size > 0
            assert arg_at + arg_size <= len(raw) and params_at + params_size <= len(raw)
            if tool is not None:
                assert ordinal == tool, (name, ordinal, tool)
            if identifier is not None:
                assert raw[id_at:id_at + id_size] == identifier, (name, 'ID bytes changed')
            if arguments is not None:
                assert raw[arg_at:arg_at + arg_size] == arguments, (name, 'argument bytes changed')
            record.update(action=selected, tool=ordinal, id_bytes=id_size, arguments_bytes=arg_size)
            return_value = words
        elif notification:
            assert result == 0, (name, result)
            return_value = None
        else:
            assert 0 < result <= RESPONSE_BYTES, (name, result)
            answer = output.raw[:result]
            assert answer.endswith(b'\n') and answer.count(b'\n') == 1
            reply = json.loads(answer)
            assert reply['jsonrpc'] == '2.0'
            if error is not None:
                assert reply['error']['code'] == error, (name, reply)
            else:
                assert 'result' in reply, (name, reply)
            record['response_sha256'] = sha256(answer).hexdigest()
            return_value = reply
        cases.append(record)
        return return_value

    def request(method, identifier=1, params=None):
        value = {'jsonrpc': '2.0', 'id': identifier, 'method': method}
        if params is not None:
            value['params'] = params
        return value

    initialize = {'protocolVersion': '2025-06-18', 'capabilities': {},
                  'clientInfo': {'name': 'native-service-qualification', 'version': '1'}}
    invoke('list-before-initialize', request('tools/list'), error=-32002)
    invoke('ping-before-initialize', request('ping'))
    answer = invoke('initialize', request('initialize', 'a☺', initialize))
    assert answer['result']['capabilities'] == {'tools': {}, 'resources': {}}
    assert answer['result']['protocolVersion'] == '2025-06-18'
    invoke('bad-initialized-notification', {'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': 1}, notification=True)
    invoke('list-before-ready', request('tools/list'), error=-32002)
    invoke('initialized-notification', {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, notification=True)
    for index, name in enumerate(tool_names(), 1):
        identifier = b'"kept\\u263a\\\\\\\""'
        arguments = b'{ "escaped":"\\n\\u4e2d", "value":17, "nested":[null,true,{}] }'
        wire = b'{"jsonrpc":"2.0","id":' + identifier + b',"method":"tools/call","params":{"name":' + json.dumps(name).encode() + b',"arguments":' + arguments + b'}}'
        invoke('call-' + name, wire, action=2, tool=index, identifier=identifier, arguments=arguments)
    for name, suffix in (('missing-arguments', b''), ('null-arguments', b',"arguments":null')):
        wire = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hia_describe"' + suffix + b'}}'
        words = invoke(name, wire, action=2, tool=1, identifier=b'1', arguments=b'')
        assert words[5] == 0
    invoke('unknown-tool', request('tools/call', params={'name': 'unknown_hia', 'arguments': {}}), error=-32601)
    invoke('invalid-arguments', request('tools/call', params={'name': 'hia_describe', 'arguments': []}), error=-32602)
    for method, action in (('tools/list', 1), ('resources/list', 3), ('resources/templates/list', 4)):
        invoke(method, request(method), action=action, tool=0, identifier=b'1')
        invoke(method + '-cursor', request(method, params={'cursor': 'opaque'}), action=action, tool=0)
        invoke(method + '-bad-cursor', request(method, params={'cursor': []}), error=-32602)
        invoke(method + '-bad-shape', request(method, params=[]), error=-32602)
    invoke('resource-read', request('resources/read', params={'uri': 'hia://artifacts/a'}),
           action=5, tool=12, arguments=b'"hia://artifacts/a"')
    invoke('resource-read-missing-uri', request('resources/read', params={}), error=-32602)
    invoke('resource-read-nonstring', request('resources/read', params={'uri': 3}), error=-32602)
    invoke('reinitialize', request('initialize', params=initialize), error=-32002)
    fresh()
    meta = {'io.modelcontextprotocol/protocolVersion': MODERN_VERSION,
            'io.modelcontextprotocol/clientCapabilities': {}}
    discovered = invoke('inline-discovery', request('server/discover', params={'_meta': meta}))
    assert discovered['result']['capabilities'] == {'tools': {}, 'resources': {}}
    for index, name in enumerate(tool_names(), 1):
        invoke('inline-' + name, request('tools/call', params={'_meta': meta, 'name': name, 'arguments': {}}),
               action=2, tool=index, modern=1, arguments=b'{}')
    for method, action in (('tools/list', 1), ('resources/list', 3), ('resources/templates/list', 4)):
        invoke('inline-' + method, request(method, params={'_meta': meta}), action=action, modern=1)
    invoke('inline-resource-read', request('resources/read', params={'_meta': meta, 'uri': 'hia://artifacts/a'}),
           action=5, tool=12, modern=1, arguments=b'"hia://artifacts/a"')
    for value in ('pending', 0, -9223372036854775808, 9223372036854775807):
        invoke('cancellation-' + str(value), {'jsonrpc': '2.0', 'method': 'notifications/cancelled',
               'params': {'requestId': value, 'reason': 'caller stopped waiting'}},
               action=6, tool=0, identifier=json.dumps(value, separators=(',', ':')).encode())
    invoke('cancellation-preserves-escaped-id',
           b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"\\u4e2d\\n"}}',
           action=6, tool=0, identifier=b'"\\u4e2d\\n"')
    for value in (None, False, [], {}, 1.5, 9223372036854775808, -9223372036854775809):
        invoke('invalid-cancellation-' + str(value), {'jsonrpc': '2.0', 'method': 'notifications/cancelled',
               'params': {'requestId': value}}, notification=True)
    invoke('missing-cancellation-target', {'jsonrpc': '2.0', 'method': 'notifications/cancelled',
           'params': {}}, notification=True)
    invoke('inline-did-not-ready-legacy', request('tools/list'), error=-32002)
    wrong = {**meta, 'io.modelcontextprotocol/protocolVersion': '2099-01-01'}
    invoke('unsupported-inline', request('tools/call', params={'_meta': wrong, 'name': 'hia_describe'}), error=-32022)
    malformed = {**meta, 'io.modelcontextprotocol/clientCapabilities': []}
    invoke('malformed-inline', request('tools/call', params={'_meta': malformed, 'name': 'hia_describe'}), error=-32602)
    for name, wire, code in (
        ('invalid-json', b'not JSON', -32700),
        ('invalid-envelope', b'{}', -32600),
        ('null-id', b'{"jsonrpc":"2.0","id":null,"method":"ping"}', -32600),
        ('boolean-id', b'{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600),
        ('unsigned-overflow-id', b'{"jsonrpc":"2.0","id":9223372036854775808,"method":"ping"}', -32600),
        ('signed-overflow-id', b'{"jsonrpc":"2.0","id":-9223372036854775809,"method":"ping"}', -32600),
        ('batch-envelope', b'[]', -32600),
        ('unknown-method', b'{"jsonrpc":"2.0","id":1,"method":"unknown"}', -32002),
    ):
        invoke(name, wire, error=code)
    for value in (-9223372036854775808, 9223372036854775807):
        invoke('signed-boundary-' + str(value), request('ping', value))
    ping = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    invoke('exact-input-limit', b' ' * (LIMIT - len(ping)) + ping)
    assert args.flat.read_bytes() == flat and (root / SOURCE).read_bytes() == source
    report = {'scope': 'NATIVE_MCP_SERVICE_SESSION_COMPONENT', 'passed': True, 'count': len(cases),
              'flat_sha256': sha256(flat).hexdigest(), 'source_sha256': sha256(source).hexdigest(),
              'dispatch_grants_effect_authority': False, 'whole_mcp_server_qualified': False, 'cases': cases}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases), 'flat_sha256': report['flat_sha256']}), flush=True)
    del entry
    image_memory.close()


if __name__ == '__main__':
    main()
