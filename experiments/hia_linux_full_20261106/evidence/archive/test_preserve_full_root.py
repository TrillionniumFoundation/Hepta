import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("preserve_full_root.py")
spec = importlib.util.spec_from_file_location("preserve", SCRIPT)
preserve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preserve)


class PreservationTest(unittest.TestCase):
    def test_full_roundtrip_and_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "input"
            root.mkdir()
            (root / "empty").mkdir(mode=0o750)
            executable = root / "run.sh"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o751)
            os.link(executable, root / "existing_hardlink")
            os.symlink("run.sh", root / "symlink")
            (root / "long" / ("x" * 180)).mkdir(parents=True)
            (root / "long" / ("x" * 180) / "utf8-汉字\nfile").write_bytes(bytes(range(256)) * 100)
            marker = root / "FINAL.json"
            marker.write_text('{"status":"PASS"}\n')
            dependencies = base / "DEPENDENCIES.json"
            dependencies.write_text('{"offline_self_contained":false}\n')
            output = base / "archive"
            result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), "--output", str(output),
                                     "--freeze-marker", str(marker), "--expected-freeze-sha256", preserve.sha(marker),
                                     "--dependency-manifest", str(dependencies), "--fixture"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads((output / "RESULT.json").read_text())
            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(executable.stat().st_nlink, 2)
            self.assertFalse(list(output.glob("*.partial")))
            with gzip.open(output / "INVENTORY.jsonl.gz", "rt") as stream:
                rows = [json.loads(line) for line in stream]
            inventory = {row["member"]: row for row in rows}
            self.assertEqual(len(rows), receipt["source_totals"]["entries"])
            archive = Path(receipt["archive"]["path"])
            self.assertEqual(preserve.sha(archive), receipt["archive"]["sha256"])
            _, decoder, _ = preserve.compressor()
            corrupted_inventory = {name: dict(row) for name, row in inventory.items()}
            member = str(executable).lstrip("/")
            corrupted_inventory[member]["sha256"] = "0" * 64
            fail_output = base / "bad-verification"
            fail_output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "archive content mismatch"):
                preserve.verify_stream(archive, decoder, corrupted_inventory, fail_output)
            executable.write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "source metadata changed"):
                preserve.recheck(root, inventory)

    def test_special_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            pipe = Path(temporary) / "pipe"
            os.mkfifo(pipe)
            with self.assertRaisesRegex(RuntimeError, "unsupported special input"):
                preserve.file_stat(pipe)


if __name__ == "__main__":
    unittest.main()
