"""Characterize blockers to integration, not implemented production fixes."""
import inspect
import unittest
from hepta.ast import HeptaError
from hepta.modules import load_project
from .prototype import Prepared, Rejected
from . import test_prototype as fixtures
CC = fixtures.CC


@unittest.skipUnless(CC, 'GCC required')
class IntegrationGapTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CharPrototypeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_emitted_source_expires_with_live_session(self):
        p,_ = self.fixture.prepared()
        source = p._source()
        self.fixture.execute(p)
        p.close()
        result = self.fixture.mutation_compile(p,source)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('original.h',result.stderr)
        self.assertIn('No such file',result.stderr)

    def test_locked_request_cannot_be_silently_routed_to_prototype(self):
        entry,_ = self.fixture.fixture()
        with self.assertRaises(HeptaError):
            load_project(entry,locked=True)
        with Prepared(entry,cc=CC):
            pass
        self.assertNotIn('locked',inspect.signature(Prepared).parameters)

    def test_source_overrides_have_no_preparation_contract(self):
        entry,_ = self.fixture.fixture()
        with self.assertRaises(TypeError):
            Prepared(entry,cc=CC,source_overrides={str(entry):'invalid'})

    def test_crate_modes_have_no_preparation_contract(self):
        p,_ = self.fixture.prepared()
        for mode in ['obj','staticlib','cdylib']:
            with self.subTest(mode=mode),self.assertRaises(TypeError):
                p.compile(crate_type=mode)

    def test_mixed_header_not_a_supported_routing_shortcut(self):
        entry,_ = self.fixture.fixture('char echo_char(char x); int native_count(int x);','')
        with self.assertRaisesRegex(Rejected,'non-char-only'):
            Prepared(entry,cc=CC)

    def test_relative_include_support_is_not_established(self):
        (self.fixture.root/'dependency.h').write_text('/* real local dependency */\n')
        # Existing importer already rejects local quoted includes. Do not infer
        # transitive/private include support from the libc prototype successes.
        with self.assertRaises(HeptaError) as error:
            self.fixture.fixture('#include "dependency.h"\nchar echo_char(char x);','')
        self.assertIn('dependency.h',str(error.exception))
