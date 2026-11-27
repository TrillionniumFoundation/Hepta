"""Whole-file proof that the hardware observer changes only the IRQ byte boundary oracle."""
from pathlib import Path
import hashlib
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HardwareOracleHistoryTests(unittest.TestCase):
    def test_complete_original_hardware_observer_is_preserved(self):
        fixture = json.loads((ROOT / "tests/fixtures/hia_kernel_irq_instruction_boundary_successor_v1.json").read_bytes())
        raw = (ROOT / fixture["path"]).read_bytes()
        self.assertEqual(len(raw), fixture["new"]["bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), fixture["new"]["sha256"])
        restored = raw.decode()
        for row in reversed(fixture["splices"]):
            self.assertEqual(restored.count(row["after"]), 1)
            restored = restored.replace(row["after"], row["before"])
        original = restored.encode()
        self.assertEqual(len(original), fixture["old"]["bytes"])
        self.assertEqual(hashlib.sha256(original).hexdigest(), fixture["old"]["sha256"])
        self.assertEqual(hashlib.sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest(), fixture["old"]["git_blob"])
        replay = original.decode()
        for row in fixture["splices"]:
            self.assertEqual(replay.count(row["before"]), 1)
            replay = replay.replace(row["before"], row["after"])
        self.assertEqual(replay.encode(), raw)


if __name__ == "__main__":
    unittest.main()
