"""Check identity boundaries without compiling or contacting a live service."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import hia_entry_catalog as entry

class EntryCatalogTests(unittest.TestCase):
    def test_default_named_and_backend_selection_are_explicit(self):
        report = entry.describe()
        current, named = report["entries"]
        self.assertNotEqual(current["sources"]["hepta"], named["sources"]["hepta"])
        self.assertEqual(current["sources"]["runtime"], named["sources"]["runtime"])
        self.assertNotIn("--lock", current["entry_argv"])
        self.assertIn("--lock", named["entry_argv"])
        self.assertEqual(current["selfhost_profile"], "selfhost-core-linux-x86_64-v9")
        self.assertEqual(named["selfhost_profile"], "selfhost-core-linux-x86_64-v16")
        self.assertIsNone(report["online"])
        self.assertIsNone(report["development"])
        self.assertEqual(report["backend_selection"]["cli_build_default"], "llvm")
        for row in report["entries"]:
            self.assertIn("native", row["minimal_program"]["direct_build_flags"])
            self.assertFalse(row["proof"]["execution_authority_granted"])
    def test_changed_lock_and_helper_are_rejected(self):
        original = Path.read_bytes
        for path in ("releases/hia-current.json", "tools/hia_release.py"):
            with self.subTest(path=path):
                def changed(target):
                    raw = original(target)
                    return raw + b"\n" if target == entry.ROOT / path else raw
                with patch.object(Path, "read_bytes", changed), self.assertRaises(ValueError):
                    entry.describe()
    def test_online_match_requires_every_component(self):
        rows = entry.describe()["entries"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            data = {"installation": deepcopy(rows[0]["installation"])}
            path.write_text(json.dumps(data))
            self.assertEqual(entry.online(path, rows)["matches"], ["current"])
            data["installation"]["backend_sha256"] = rows[1]["installation"]["backend_sha256"]
            path.write_text(json.dumps(data))
            observed = entry.online(path, rows)
            self.assertEqual(observed["matches"], [])
            self.assertFalse(observed["live_probe_performed"])
    def test_missing_duplicate_and_nonhex_identities_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            bad = {"installation": dict.fromkeys(("worker_sha256", "backend_sha256", "catalog_sha256"), "g"*64)}
            for raw in ('{"installation":{}}', '{"installation":{},"installation":{}}', json.dumps(bad)):
                path.write_text(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    entry.online(path, [])
    def test_development_root_is_explicit_and_not_a_qualified_release(self):
        def git(*args, **kwargs):
            class Output:
                stdout = "observed-git-value\n"
            return Output()
        with patch.object(entry.subprocess, "run", side_effect=git), patch.object(entry, "read_json", return_value=(b"{}", {"profile":"dev-only"})):
            result = entry.development("/explicit/source")
        self.assertEqual(result["selfhost_profile"], "dev-only")
        self.assertFalse(result["release_lock_verified"])
        self.assertFalse(result["production_deployed"])

if __name__ == "__main__":
    unittest.main()
