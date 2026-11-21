"""Verify the HIA MCP wire classifier independently and on its native image."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from tests.test_hia_elf_linker import reference
from tools.generate_hia_mcp_request import (
    ACCEPT, INVALID_ENVELOPE, INVALID_PARAMS, MAGIC, METHODS, METHOD_NOT_FOUND,
    OUTPUT_BYTES, SOURCE, WIRE_FORMAT, render, tool_names,
)
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]


class RoutingCases:
    def check_route(self, wire, method, request_id, *, params=None, arguments=None,
                    tool=None, decision=ACCEPT):
        value, output = self.run_route(wire)
        self.assertEqual(value, struct.calcsize(WIRE_FORMAT))
        (magic, role, kind, id_at, id_width, param_at, param_width, ordinal,
         arg_at, arg_width, found_decision) = struct.unpack_from(WIRE_FORMAT, output)
        self.assertEqual(magic, MAGIC)
        self.assertEqual(role, METHODS.index(method) + 1 if method else 0)
        self.assertEqual(kind, 0 if request_id is None else (4 if request_id[0] == 34 else 3))
        self.assertEqual(ordinal, tool_names().index(tool) + 1 if tool else 0)
        self.assertEqual(found_decision, decision)
        for offset, width, expected in (
            (id_at, id_width, request_id),
            (param_at, param_width, params),
            (arg_at, arg_width, arguments),
        ):
            if expected is None:
                self.assertEqual((offset, width), (0, 0))
            else:
                self.assertLessEqual(offset + width, len(wire))
                self.assertEqual(wire[offset:offset + width], expected)

    def test_original_id_params_and_arguments_bytes_for_every_catalog_tool(self):
        arguments = rb'{ "nested": [{"test":[]}, 0, 123, -0.25E+01, 0.5e-300], "text": "\ud83d\ude00" }'
        request_id = rb'"i\u0064\u0000"'
        for tool in tool_names():
            with self.subTest(tool=tool):
                params = b'{"arguments" : ' + arguments + b', "name" : ' + json.dumps(tool).encode() + b'}'
                wire = (b' {"params":' + params + rb',"metho\u0064":"tools\/call","jsonrpc":"2.0","id":'
                        + request_id + b'} \t')
                self.check_route(wire, 'tools/call', request_id, params=params, arguments=arguments,
                                 tool=tool)

    def test_session_routes_id_limits_and_no_dispatch_for_other_notifications(self):
        for method in METHODS:
            if method == 'tools/call':
                continue
            request_id = None if method.startswith('notifications/') else b'-9223372036854775808'
            wire = b'{"jsonrpc":"2.0","method":' + json.dumps(method).encode() + b',"params":{ }'
            if request_id is not None:
                wire += b',"id":' + request_id
            self.check_route(wire + b'}', method, request_id, params=b'{ }')
        self.check_route(b'{"jsonrpc":"2.0","method":"ping","id":9223372036854775807}',
                         'ping', b'9223372036854775807')
        self.check_route(b'{"jsonrpc":"2.0","method":"tools/call"}', None, None)

    def test_resource_read_preserves_the_exact_uri_string_from_the_explicit_route(self):
        raw_uri = rb'"hia:\/\/artifact\/test\u002didentity"'
        params = rb'{"ignored":{"uri":"wrong"},"ur\u0069":' + raw_uri + b'}'
        request_id = rb'"id\u0031"'
        original = rb'{"jsonrpc":"2.0","method":"resources\/read","id":' + request_id + b',"params":'
        self.check_route(original + params + b'}', 'resources/read', request_id,
                         params=params, arguments=raw_uri)
        self.assertEqual(json.loads(raw_uri), 'hia://artifact/test-identity')

    def test_refusals_keep_valid_ids_but_never_return_a_dispatch_for_bad_wire(self):
        for params, code in ((b'{}', INVALID_PARAMS), (b'{"name":"unknown"}', METHOD_NOT_FOUND),
                             (b'[]', INVALID_PARAMS), (b'null', INVALID_PARAMS)):
            wire = b'{"jsonrpc":"2.0","id":-0,"method":"tools/call","params":' + params + b'}'
            self.check_route(wire, 'tools/call', b'-0', params=None if params == b'null' else params,
                             decision=code)
        self.check_route(b'{"jsonrpc":"2.0","id":1,"method":"unknown"}', None, b'1',
                         decision=METHOD_NOT_FOUND)
        for request_id in (b'null', b'1.0', b'1e0', b'9223372036854775808', b'-9223372036854775809'):
            wire = b'{"jsonrpc":"2.0","method":"ping","id":' + request_id + b'}'
            self.assertEqual(self.run_route(wire)[0], INVALID_ENVELOPE)
        for wire in (b'[]', b'{"method":"ping"}', b'{"jsonrpc":"2.0","method":"notifications/initialized","id":1}'):
            self.assertEqual(self.run_route(wire)[0], INVALID_ENVELOPE)
        for malformed in (
            rb'{"jsonrpc":"2.0","id":1,"\u0069d":2,"method":"ping"}',
            b'{"jsonrpc":"2.0","id":"\xff","method":"ping"}',
            b'{"jsonrpc":"2.0","method":"ping"',
            b'{"jsonrpc":"2.0","method":"ping","params":[1.e2]}',
            b'{"jsonrpc":"2.0","method":"ping","params":[1e-]}',
            b'{"jsonrpc":"2.0","method":"ping","params":[00.5]}',
        ):
            self.assertGreaterEqual(self.run_route(malformed)[0], 0xfffffff0)


class McpRequestSourceTests(RoutingCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE).read_text()
        if render() != source:
            raise AssertionError('generated MCP request source drifted')
        cls.checked = assemble_program(source)

    def run_route(self, wire):
        return reference(self.checked, wire, capacity=OUTPUT_BYTES, workspace=1 << 14)


    def test_native_wire_packer_keeps_exact_image_and_rejects_before_writing(self):
        from tools.generate_hia_mcp_stdio_packer import CONNECTION_MODE, MAGIC, SOURCE, render, template
        from tools.qualify_hia_selfhost_cli import inspect_executable

        source = (ROOT / SOURCE).read_text()
        self.assertEqual(source, render())
        checked = assemble_program(source)
        image = b'\x00\x01opaque-HIA-image'
        for mode in range(CONNECTION_MODE + 1):
            with self.subTest(mode=mode):
                prefix, call = template(mode)
                request = struct.pack('<2Q', MAGIC, mode) + image
                size = len(prefix) + len(image)
                status, output = reference(checked, request, capacity=size, workspace=0)
                self.assertEqual(status, size)
                self.assertEqual(inspect_executable(output)['bytes'], size)
                self.assertEqual(output[len(prefix):], image)
                self.assertEqual(call + 4 + struct.unpack_from('<i', output, call)[0],
                                 len(prefix))
                self.assertEqual(reference(checked, request, capacity=size-1, workspace=0),
                                 (0xfffffffe, b'\xa5' * (size-1)))

        for request in (struct.pack('<2Q', MAGIC, CONNECTION_MODE + 1) + image,
                        struct.pack('<2Q', MAGIC ^ 1, 0) + image,
                        struct.pack('<2Q', MAGIC, 0)):
            self.assertEqual(reference(checked, request, capacity=128, workspace=0),
                             (0xffffffff, b'\xa5' * 128))


class McpRequestNativeTests(RoutingCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-mcp-request-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, 'B1', seed,
                                     (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes(),
                                     image_format='seed-shared')
        cls.image, _ = compile_stage(cls.folder, 'route', compiler, (ROOT / SOURCE).read_bytes())
        cls.sequence = 0

    def run_route(self, wire):
        self.__class__.sequence += 1
        result, output = invoke(self.folder, f'wire-{self.sequence}', self.image, wire,
                                capacity=OUTPUT_BYTES, workspace_size=1 << 14)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['abi_status'], 0, result)
        return result['core_u32'], output
