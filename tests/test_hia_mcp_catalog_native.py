"""Check native MCP catalog projection, exact values and pre-publication refusals."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from tests.test_hia_elf_linker import reference
from tools.generate_hia_mcp_catalog import PROFILE, SOURCE, render
from tools.generate_hia_mcp_request import CATALOG, INVALID_ENVELOPE, OUTPUT_BYTES, tool_names
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]


def example():
    return {'schema': PROFILE, 'status': 'not for publication', 'tools': [
        {'name': name, 'description': 'quote " \t 🔒',
         'inputSchema': {'type': 'object', 'minimum': -0.125e-20},
         'outputSchema': {'type': 'object'},
         'annotations': {'readOnlyHint': False}}
        for name in tool_names()]}


class CatalogCases:
    def compare(self, source, expected):
        status, data = self.run_wire(source)
        self.assertLessEqual(status, len(data))
        raw = data[:status]
        self.assertTrue(raw.endswith(b'\n'))
        self.assertEqual(raw.count(b'\n'), 1)
        self.assertEqual(json.loads(raw), {'tools': [
            {'title': tool['name'].replace('_', ' ').upper(), **tool} for tool in expected]})
        return raw

    def test_tools_only_preserve_escapes_and_schema_text(self):
        catalog = example()
        source = json.dumps(catalog, ensure_ascii=True, indent=2).encode()
        raw = self.compare(source, catalog['tools'])
        self.assertIn(rb'quote \" \t \ud83d\udd12"', raw)
        self.assertIn(b'-1.25e-21', raw)
        self.assertNotIn(b'not for publication', raw)

    def test_incomplete_duplicate_reordered_and_wrong_fields_do_not_publish(self):
        duplicate = json.dumps(example()).replace('"schema":', '"schema":"x","schema":', 1)
        self.assertEqual(self.run_wire(duplicate.encode())[0], 0xfffffffc)
        for variant in ('wrong profile', 'short', 'reordered', 'wrong field', 'extra field'):
            doc = example()
            tools = doc['tools']
            if variant == 'wrong profile':
                doc['schema'] = 'unowned'
            elif variant == 'short':
                tools.pop()
            elif variant == 'reordered':
                tools[0], tools[1] = tools[1], tools[0]
            elif variant == 'wrong field':
                tools[-1]['annotations'] = False
            else:
                tools[-1]['title'] = 'not derived from the known name'
            status, _ = self.run_wire(json.dumps(doc).encode())
            self.assertEqual(status, INVALID_ENVELOPE)


class McpCatalogSourceTests(CatalogCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE).read_text()
        if render() != source:
            raise AssertionError('generated MCP catalog source drifted')
        cls.checked = assemble_program(source)

    def run_wire(self, wire):
        return reference(self.checked, wire, capacity=4 * OUTPUT_BYTES, workspace=1 << 17)


class McpCatalogNativeTests(CatalogCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='hia-mcp-catalog-')
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, 'B1', seed,
                                     (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes(),
                                     image_format='seed-shared')
        cls.image, _ = compile_stage(cls.folder, 'catalog', compiler, (ROOT / SOURCE).read_bytes())
        cls.sequence = 0

    def run_wire(self, wire):
        self.__class__.sequence += 1
        result, output = invoke(self.folder, f'wire-{self.sequence}', self.image, wire,
                                capacity=1 << 20, workspace_size=1 << 20)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['abi_status'], 0, result)
        return result['core_u32'], output

    def test_current_installed_catalog(self):
        source = CATALOG.read_bytes()
        self.compare(source, json.loads(source)['tools'])
