"""Exercise the real sealed stdio ABI for MCP's existing HIA schema kernels."""
from __future__ import annotations

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_agent_contract import VERSION
from tools.build_hia_agent_read_page import pack_stdio
from tools.generate_hia_mcp_request import tool_names
from tools.generate_hia_mcp_stdio_packer import SCHEMA_MODE, SOURCE as STDIO_PACKER
from tools.qualify_hia_selfhost import build_seed, compile_stage

ROOT = Path(__file__).resolve().parents[1]
CATALOG = sha256((ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()).hexdigest().encode()
ROLES = {name: ordinal for ordinal, name in enumerate(tool_names(), 1)}


class McpSchemaStdioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = tempfile.TemporaryDirectory(prefix='hia-mcp-schema-')
        cls.addClassCleanup(scratch.cleanup)
        cls.folder = Path(scratch.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, 'B1', seed,
                                     (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes(),
                                     image_format='seed-shared')
        sources = {STDIO_PACKER: (ROOT / STDIO_PACKER).read_bytes()}
        cls.images = {}
        for profile, name in (('input', 'agent_schema'), ('response', 'agent_response_schema'),
                              ('proof', 'agent_verify_response_schema')):
            bits, _ = compile_stage(cls.folder, name, compiler,
                                     (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes())
            target = cls.folder / profile
            target.mkdir()
            elf, _ = pack_stdio(target, compiler, sources, SCHEMA_MODE, bits.read_bytes(), {})
            executable = target / 'hia-schema'
            executable.write_bytes(elf)
            executable.chmod(0o500)
            cls.images[profile] = executable

    def run_schema(self, profile, role, value, *, catalog=CATALOG):
        packet = struct.pack('<Q64s', role, catalog) + json.dumps(value).encode()
        fd = os.memfd_create('hia-schema-private-input', os.MFD_ALLOW_SEALING)
        with os.fdopen(fd, 'wb', buffering=0) as stream:
            stream.write(packet)
            stream.seek(0)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
            result = subprocess.run([self.images[profile]], stdin=stream, env={'PATH': ''},
                                    capture_output=True, timeout=3, check=True)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(len(result.stdout), 8)
        return struct.unpack('<Q', result.stdout)[0]

    def test_input_roles_and_pinned_catalog(self):
        role = ROLES['hia_describe']
        request = {'section': 'manifest'}
        self.assertEqual(self.run_schema('input', role, request), 0)
        self.assertEqual(self.run_schema('input', role, {'section': ['manifest']}), 1)
        self.assertEqual(self.run_schema('input', role, request, catalog=b'0' * 64), 0xfffffffd)
        self.assertEqual(self.run_schema('input', 0, request), 0xfffffffd)

    def test_output_and_proof_schemas_have_disjoint_roles(self):
        result = {'contract_version': VERSION, 'request_id': 'example', 'status': 'rejected',
                  'error': {'code': 'E_TEST', 'phase': 'admission', 'message': 'test',
                            'retry_action': 'correct_input', 'details_artifact': None}}
        ordinary = ROLES['hia_read']
        proof = ROLES['hia_verify']
        self.assertEqual(self.run_schema('response', ordinary, result), 0)
        self.assertEqual(self.run_schema('proof', proof, result), 0)
        self.assertEqual(self.run_schema('response', proof, result), 0xfffffffd)
        self.assertEqual(self.run_schema('proof', ordinary, result), 0xfffffffd)
        self.assertEqual(self.run_schema('proof', proof, dict(result, error=None)), 1)
