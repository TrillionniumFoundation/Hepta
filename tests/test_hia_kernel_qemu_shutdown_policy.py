"""The original hardware oracle and guest bytes survive host shutdown policy."""
from hashlib import sha256, sha1
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/hia_kernel_qemu_shutdown_policy_successor_v1.json"


class KernelQemuShutdownPolicyTests(unittest.TestCase):
    def test_exact_original_oracle_and_timeout_bytes_are_preserved(self):
        document = json.loads(FIXTURE.read_bytes())
        self.assertEqual(document["schema"], "hepta.hia.kernel-qemu-shutdown-policy-successor.v1")
        self.assertEqual([r["path"] for r in document["records"]], [
            "tests/x86_privileged_qemu/run_hardware.py",
            "tests/test_hia_kernel_invlpg_qemu.py"])
        self.assertIs(document["guest_images_oracles_and_timeouts_changed"], False)
        for record in document["records"]:
            with self.subTest(path=record["path"]):
                actual = (ROOT / record["path"]).read_bytes()
                self.assertEqual({"bytes": len(actual), "sha256": sha256(actual).hexdigest()},
                                 record["current"])
                before = record["replace"]["old"].encode()
                after = record["replace"]["new"].encode()
                self.assertEqual(before, b'"-no-shutdown"')
                self.assertEqual(after, b'"-action", "shutdown=poweroff"')
                self.assertEqual(actual.count(after), 1)
                original = actual.replace(after, before)
                self.assertEqual(len(original), record["original"]["bytes"])
                self.assertEqual(sha256(original).hexdigest(), record["original"]["sha256"])
                self.assertEqual(sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest(),
                                 record["original"]["git_blob"])


if __name__ == "__main__":
    unittest.main()
