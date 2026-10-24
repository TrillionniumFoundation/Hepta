"""An inactive header must not donate phantom record declarations."""
from pathlib import Path
import shlex
import shutil
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.c_import import import_header


class ActiveHeaderGuardTests(unittest.TestCase):
    def setUp(self):
        self.gcc = shutil.which('gcc')
        self.assertIsNotNone(self.gcc)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.header = self.root / 'api.h'

    def preincluded_compiler(self):
        # Reproduce a project's ordinary -include compiler configuration,
        # without relying on platform-private system record names.
        actual = self.root / 'actual.h'
        actual.write_text('#ifndef PROJECT_API_H\n#define PROJECT_API_H\n'
                          'struct Packet { int value; double weight; };\n#endif\n')
        wrapper = self.root / 'configured-cc'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(self.gcc) +
                           ' -include ' + shlex.quote(str(actual)) + ' "$@"\n')
        wrapper.chmod(0o700)
        return str(wrapper)

    def test_hidden_record_is_rejected_before_using_existing_tag(self):
        self.header.write_text('#ifndef PROJECT_API_H\n#define PROJECT_API_H\n'
                               'struct Packet { double value; };\n#endif\n')
        with self.assertRaises(HeptaError) as caught:
            import_header(self.header, cc=self.preincluded_compiler())
        self.assertEqual(caught.exception.diagnostic.code, 'E_C_IMPORT_PROBE')
        self.assertIn('include guard is already defined', caught.exception.diagnostic.message)

    def test_guard_defined_earlier_in_same_header_is_rejected(self):
        self.header.write_text('#define LOCAL_GUARD 1\n#ifndef LOCAL_GUARD\n'
                               '#define LOCAL_GUARD\nstruct Packet { double value; };\n#endif\n')
        with self.assertRaises(HeptaError) as caught:
            import_header(self.header, cc=self.preincluded_compiler())
        self.assertEqual(caught.exception.diagnostic.code, 'E_C_IMPORT_PREPROCESSOR')

    def test_hidden_alias_is_also_rejected(self):
        self.header.write_text('#ifndef PROJECT_API_H\n#define PROJECT_API_H\n'
                               'typedef double Counter;\n#endif\n')
        with self.assertRaises(HeptaError):
            import_header(self.header, cc=self.preincluded_compiler())

    def test_ordinary_guarded_record_with_padding_remains_supported(self):
        self.header.write_text('#ifndef PROJECT_API_H\n#define PROJECT_API_H\n'
                               'struct Packet { char tag; double weight; };\n#endif\n')
        result = import_header(self.header)
        self.assertIn('struct Packet', result.source)
        self.assertGreater(result.manifest['layouts']['Packet']['fields']['weight']['offset'], 0)
        self.assertEqual(result.manifest['functions'], [])

    def test_empty_guarded_header_remains_supported_when_guard_is_defined(self):
        self.header.write_text('#ifndef PROJECT_API_H\n#define PROJECT_API_H\n#endif\n')
        result = import_header(self.header, cc=self.preincluded_compiler())
        self.assertEqual(result.manifest['layouts'], {})
        self.assertEqual(result.manifest['functions'], [])


if __name__ == '__main__':
    unittest.main()
