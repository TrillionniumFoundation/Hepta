"""Adversarial controls for the offline formal-installation capture gate."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "tools" / "check_hia_online_readback.py"
SPEC = importlib.util.spec_from_file_location("readback_checker", PATH)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def envelope(result, request="a", status="completed"):
    payload = {"contract_version": checker.VERSION, "request_id": "r-" + request * 64,
               "status": status, "result": result}
    return {"isError": False, "content": [{"type": "text", "text": raw(payload).decode()}],
            "structuredContent": payload}


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.pins = {key: str(i + 1) * 64 for i, key in enumerate(sorted(checker.PINS))}
        self.manifest = {"schema": "hepta.hia.agent.manifest.v1", "installation": self.pins,
                         "catalog_sha256": self.pins["catalog_sha256"]}
        self.ref = {"id": "a-" + "a" * 32, "uri": "hia://artifacts/" + "b" * 32,
                    "sha256": checker.sha256(raw(self.manifest))}
        self.describe = envelope({"catalog_sha256": self.pins["catalog_sha256"], "manifest": self.ref})
        self.read = envelope({"artifact": self.ref, "content": raw(self.manifest).decode(),
                              "encoding": "utf8", "next_cursor": None}, request="b")
        self.lock = {"schema": "hepta.hia.release-lock.v1", "installation": copy.deepcopy(self.pins),
                     "sources": {key: {"commit": "a" * 40, "tree": "b" * 40,
                                       "repository": "https://github.com/example/" + key}
                                 for key in ("hepta", "runtime")}}

    def check(self):
        lock = raw(self.lock)
        return checker.check_readback(lock, checker.sha256(lock), raw(self.describe), raw(self.read))

    def modify_read(self, update):
        result = copy.deepcopy(self.read["structuredContent"]["result"])
        update(result)
        self.read = envelope(result, request="b")

    def test_complete_three_part_match(self):
        self.assertTrue(self.check()["passed"])

    def test_backend_and_catalog_match_cannot_hide_worker_mismatch(self):
        self.lock["installation"]["worker_sha256"] = "f" * 64
        report = self.check()
        self.assertFalse(report["passed"])
        self.assertEqual(report["status"], "HOLD_INSTALLATION_MISMATCH")
        self.assertFalse(report["matches"]["worker_sha256"])

    def test_each_identity_is_required(self):
        for key in checker.PINS:
            with self.subTest(key=key):
                altered = copy.deepcopy(self.lock)
                del altered["installation"][key]
                data = raw(altered)
                with self.assertRaises(checker.InvalidCapture):
                    checker.check_readback(data, checker.sha256(data), raw(self.describe), raw(self.read))

    def test_wrong_public_lock_digest(self):
        with self.assertRaises(checker.InvalidCapture):
            checker.check_readback(raw(self.lock), "0" * 64, raw(self.describe), raw(self.read))

    def test_tampered_manifest_bytes(self):
        self.modify_read(lambda result: result.update(content=result["content"] + " "))
        with self.assertRaises(checker.InvalidCapture):
            self.check()

    def test_artifact_reference_rebinding(self):
        self.modify_read(lambda result: result["artifact"].update(id="a-" + "f" * 32))
        with self.assertRaises(checker.InvalidCapture):
            self.check()

    def test_incomplete_read_page(self):
        self.modify_read(lambda result: result.update(next_cursor="remaining"))
        with self.assertRaises(checker.InvalidCapture):
            self.check()

    def test_missing_page_completion(self):
        self.modify_read(lambda result: result.pop("next_cursor"))
        with self.assertRaises(checker.InvalidCapture):
            self.check()

    def test_nonterminal_and_rejected_results(self):
        result = self.read["structuredContent"]["result"]
        for status in ("accepted", "unknown", "rejected"):
            with self.subTest(status=status):
                self.read = envelope(result, request="b", status=status)
                with self.assertRaises(checker.InvalidCapture):
                    self.check()

    def test_connector_error(self):
        self.read["isError"] = True
        with self.assertRaises(checker.InvalidCapture):
            self.check()

    def test_text_structured_conflict(self):
        self.read["structuredContent"]["status"] = "unknown"
        with self.assertRaises(checker.InvalidCapture):
            self.check()

    def test_duplicate_keys(self):
        with self.assertRaises(checker.InvalidCapture):
            checker.decode(b'{"status":"completed","status":"unknown"}')

    def test_nonfinite_and_overflow_json(self):
        for data in (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}'):
            with self.subTest(data=data):
                with self.assertRaises(checker.InvalidCapture):
                    checker.decode(data)

    def test_wrong_discovery_catalog(self):
        result = copy.deepcopy(self.describe["structuredContent"]["result"])
        result["catalog_sha256"] = "f" * 64
        self.describe = envelope(result)
        with self.assertRaises(checker.InvalidCapture):
            self.check()


if __name__ == "__main__":
    unittest.main()
