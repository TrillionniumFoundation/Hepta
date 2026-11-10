"""The Linux campaign must retain rejected units and original Kbuild semantics."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch



class LinuxTranslationCampaignTests(unittest.TestCase):


    def test_first_lazy_migration_import_does_not_retain_temporary_capture_mock(self):
        # A clean interpreter is essential: earlier imports in the wider suite
        # can hide this bug. Execute the real relative-directory test first,
        # then inspect the restored production binding in that same process.
        script = '''
import sys, unittest
sys.path.insert(0, sys.argv[1])
assert 'hepta.c_migration_project' not in sys.modules
suite = unittest.defaultTestLoader.loadTestsFromName(
    'tests.test_hia_linux_translation.LinuxTranslationCampaignTests.test_original_relative_directory_resolves_against_original_database')
result = unittest.TextTestRunner(verbosity=2).run(suite)
assert result.wasSuccessful() and result.testsRun == 1 and not result.skipped
from hepta import c_migration_project, c_project
assert c_migration_project.capture_project is c_project.capture_project
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script,
            str(Path(__file__).resolve().parents[1])], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)




if __name__ == "__main__":
    unittest.main()
