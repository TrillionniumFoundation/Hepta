"""Explicit child environment snapshots do not change inherited legacy calls."""
from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import patch

from hepta import clang_capture as capture


@unittest.skipUnless(sys.platform == "linux", "explicit environment is qualified only on Linux")
class CaptureEnvironmentTests(unittest.TestCase):
    def test_invalid_or_unbounded_environment_is_rejected_before_launch(self):
        class CustomDictionary(dict):
            pass
        bad = [[], CustomDictionary(A="1"), {"": "1"}, {"A=B": "1"}, {"A\0": "1"},
               {"A": "1\0"}, {"A": True}, {1: "1"}, {"A": "\ud800"},
               {str(i): "v" for i in range(257)}, {"A": "x" * 131072}, {"A": "\U0001f600" * 32768}]
        with patch.object(capture.subprocess, "Popen") as launch:
            for environment in bad:
                with self.subTest(type=type(environment).__name__), self.assertRaises(capture.CaptureRejected) as error:
                    capture.run_bounded([sys.executable, "-c", "pass"], env=environment)
                self.assertEqual(error.exception.code, "E_CAPTURE_ENV")
            launch.assert_not_called()

    def test_explicit_environment_is_not_silently_ignored_by_other_backend(self):
        with patch.object(capture, "_DARWIN", True), patch.object(capture.subprocess, "Popen") as launch:
            with self.assertRaises(capture.CaptureRejected) as error:
                capture.run_bounded([sys.executable, "-c", "pass"], env={"LANG": "C"})
            self.assertEqual(error.exception.code, "E_CAPTURE_ENV")
            launch.assert_not_called()

    def test_default_inheritance_and_explicit_replacement_are_distinct(self):
        script = 'import os,json; print(json.dumps({k:os.environ.get(k) for k in ("HIA_CAPTURE_TEST","LANG")}))'
        with patch.dict(os.environ, {"HIA_CAPTURE_TEST": "inherited", "LANG": "parent"}):
            legacy = capture.run_bounded([sys.executable, "-I", "-c", script], timeout=3)
            explicit = capture.run_bounded([sys.executable, "-I", "-c", script], timeout=3,
                                          env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})
            self.assertEqual(os.environ["HIA_CAPTURE_TEST"], "inherited")
            self.assertEqual(os.environ["LANG"], "parent")
        self.assertEqual(json.loads(legacy.stdout), {"HIA_CAPTURE_TEST": "inherited", "LANG": "parent"})
        self.assertEqual(json.loads(explicit.stdout), {"HIA_CAPTURE_TEST": None, "LANG": "C"})

    def test_caller_mutation_at_launch_cannot_change_the_environment_snapshot(self):
        original = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "HIA_CAPTURE_TEST": "before"}
        real_launch = capture.subprocess.Popen
        def mutate_then_launch(*args, **kwargs):
            original["HIA_CAPTURE_TEST"] = "changed-after-validation"
            self.assertIsNot(kwargs["env"], original)
            return real_launch(*args, **kwargs)
        with patch.object(capture.subprocess, "Popen", side_effect=mutate_then_launch):
            result = capture.run_bounded([sys.executable, "-I", "-c", 'import os;print(os.environ["HIA_CAPTURE_TEST"])'],
                                         timeout=3, env=original)
        self.assertEqual(result.stdout, "before\n")
        self.assertEqual(original["HIA_CAPTURE_TEST"], "changed-after-validation")


if __name__ == "__main__":
    unittest.main()
