"""Check the HIA bootstrap descriptor before any service state is selected."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from tests.test_hia_elf_linker import reference
from tools.generate_hia_mcp_negotiation import (
    DESCRIPTOR, DISCOVER, INLINE, INVALID_METADATA, LEGACY_FALLBACK,
    LEGACY_INITIALIZE, NO_BOOTSTRAP_ACTION, PING, SOURCE, UNSUPPORTED_INLINE, VERSIONS, render,
)
from tools.generate_hia_mcp_request import MAGIC, OUTPUT_BYTES
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]


def message(method, params=None, *, token=12):
    envelope = {'jsonrpc': '2.0', 'method': method}
    if token is not None:
        envelope['id'] = token
    if params is not None:
        envelope['params'] = params
    return json.dumps(envelope, ensure_ascii=False, separators=(',', ':')).encode()


class NegotiationCases:
    def check(self, payload, expected):
        status, buffer = self.run_wire(payload)
        self.assertEqual(status, DESCRIPTOR)
        self.assertEqual(buffer[:8], MAGIC)
        self.assertEqual(struct.unpack_from('<3Q', buffer, 88), expected)

    def test_existing_initialized_profiles_and_fallback(self):
        for version in (*VERSIONS, '2035-01-02'):
            requested = VERSIONS.index(version) + 1 if version in VERSIONS else 0
            legacy = VERSIONS.index(LEGACY_FALLBACK) + 1
            expected = requested if 0 < requested <= legacy else legacy
            wire = message('initialize', {'clientInfo': {'name': 'test', 'version': '1'},
                                          'capabilities': {}, 'protocolVersion': version})
            self.check(wire, (LEGACY_INITIALIZE, requested, expected))

    def test_inline_bootstrap_discovery_and_metadata(self):
        for version in (*VERSIONS, '2032-01-01'):
            metadata = {'io.modelcontextprotocol/protocolVersion': version,
                        'io.modelcontextprotocol/clientCapabilities': {'roots': {}}}
            ordinal = VERSIONS.index(version) + 1 if version in VERSIONS else 0
            self.check(message('server/discover', {'_meta': metadata}), (DISCOVER, ordinal, 0))
            decision = INLINE if ordinal else UNSUPPORTED_INLINE
            self.check(message('tools/list', {'_meta': metadata}), (decision, ordinal, ordinal))
        bad = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
               'io.modelcontextprotocol/clientCapabilities': 5}
        self.check(message('tools/list', {'_meta': bad}), (INVALID_METADATA, 0, 0))
        self.check(message('tools/list', {}), (INVALID_METADATA, 0, 0))

    def test_ping_and_notifications_do_not_select_a_session(self):
        self.check(message('ping'), (PING, 0, 0))
        self.check(message('notifications/initialized', token=None), (NO_BOOTSTRAP_ACTION, 0, 0))
        self.check(message('initialize', {'clientInfo': {'name':'test','version':1},
                                         'capabilities': {},'protocolVersion': '2025-03-26'}),
                   (INVALID_METADATA, 0, 0))


class McpNegotiationSourceTests(NegotiationCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE).read_text()
        if render() != source:
            raise AssertionError('generated MCP bootstrap source drifted')
        cls.checked = assemble_program(source)

    def run_wire(self, wire):
        return reference(self.checked, wire, capacity=OUTPUT_BYTES, workspace=1 << 14)


class McpNegotiationNativeTests(NegotiationCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='hia-mcp-negotiation-')
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, 'B1', seed,
                                     (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes(),
                                     image_format='seed-shared')
        cls.image, _ = compile_stage(cls.folder, 'negotiate', compiler, (ROOT / SOURCE).read_bytes())
        cls.sequence = 0

    def run_wire(self, wire):
        self.__class__.sequence += 1
        result, output = invoke(self.folder, f'wire-{self.sequence}', self.image, wire,
                                capacity=OUTPUT_BYTES, workspace_size=1 << 14)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['abi_status'], 0, result)
        return result['core_u32'], output
