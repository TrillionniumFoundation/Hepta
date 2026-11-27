"""Physical generation-index controls; synthetic bytes are never executed."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.hia_cold_compiler import compiler_from_cold_report, read_native_locations


class ColdCompilerLocationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-cold-location-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.cold = self.root / "cold.json"
        self.image = bytes.fromhex('554889e54883ec4048897dc0488975c8') + b'synthetic physical pin control'
        self.report = {"schema": "hepta.hia.selfhost-cold-replay.v2",
                       "generation_sha256": [sha256(self.image).hexdigest()] * 3}
        self.raw = json.dumps(self.report).encode()
        self.cold.write_bytes(self.raw)
        self.index = {"schema": "hepta.hia.native-cold-generation-index.v1",
                      "source_head": "1" * 40,
                      "native_report": {"path": str(self.cold), "bytes": len(self.raw),
                                        "sha256": sha256(self.raw).hexdigest()},
                      "generations": [], "location_index_only": True,
                      "hosted_qualification_claimed": False}
        for name in ("B1", "B2", "B3"):
            path = self.root / (name + ".flat")
            path.write_bytes(self.image)
            self.index["generations"].append({"name": name, "produced_image": str(path),
                "produced_bytes": len(self.image), "produced_sha256": sha256(self.image).hexdigest()})

    def read(self, index=None):
        return read_native_locations(self.cold, self.raw,
                                     json.dumps(self.index if index is None else index).encode())

    def test_three_original_images_are_read_with_no_hosted_report_synthesis(self):
        images = self.read()
        self.assertEqual(images, [(self.root / (name + ".flat"), self.image)
                                  for name in ("B1", "B2", "B3")])
        self.assertEqual(self.cold.read_bytes(), self.raw)
        self.assertNotIn("nested_report", json.loads(self.cold.read_bytes()))

    def test_index_cannot_qualify_an_unadmitted_report(self):
        index_path = self.cold.with_suffix(".generations.json")
        index_path.write_text(json.dumps(self.index))
        with patch("tools.build_hia_json_preflight.admit_cold_build",
                   side_effect=ValueError("complete actual cold report required")) as gate:
            with self.assertRaisesRegex(ValueError, "complete actual cold report required"):
                compiler_from_cold_report(self.cold)
        gate.assert_called_once_with(self.image, self.raw)

    def test_missing_or_false_authority_fields_are_rejected(self):
        for key in self.index:
            with self.subTest(missing=key):
                altered = deepcopy(self.index)
                del altered[key]
                with self.assertRaises(ValueError):
                    self.read(altered)
        for key, value in (("schema", "hepta.hia.selfhost-cold-replay.v1"),
                           ("location_index_only", 1), ("hosted_qualification_claimed", 0),
                           ("hosted_qualification_claimed", True), ("source_head", "HEAD"),
                           ("extra", False)):
            with self.subTest(field=key, value=value):
                altered = deepcopy(self.index)
                altered[key] = value
                with self.assertRaises(ValueError):
                    self.read(altered)

    def test_report_byte_binding_and_exact_path_are_required(self):
        for key, value in (("path", str(self.root / "other.json")),
                           ("bytes", True), ("bytes", len(self.raw) + 1),
                           ("sha256", "0" * 64)):
            with self.subTest(field=key):
                altered = deepcopy(self.index)
                altered["native_report"][key] = value
                with self.assertRaises(ValueError):
                    self.read(altered)

    def test_generation_omission_order_aliases_and_type_confusion_are_rejected(self):
        altered = deepcopy(self.index)
        altered["generations"].pop()
        with self.assertRaises(ValueError):
            self.read(altered)
        for key, value in (("name", "B2"), ("produced_bytes", True),
                           ("produced_bytes", len(self.image) + 1),
                           ("produced_sha256", "0" * 64),
                           ("produced_image", str(self.root / "B2.flat")),
                           ("produced_image", str(self.root) + "/../B1.flat")):
            with self.subTest(field=key, value=value):
                altered = deepcopy(self.index)
                altered["generations"][0][key] = value
                with self.assertRaises(ValueError):
                    self.read(altered)

    def test_physical_tamper_and_symlink_are_rejected_despite_index_claims(self):
        path = self.root / "B2.flat"
        path.write_bytes(self.image[:-1] + b"!")
        with self.assertRaises(ValueError):
            self.read()
        path.unlink()
        path.symlink_to("B1.flat")
        with self.assertRaises(ValueError):
            self.read()

    def test_duplicate_json_keys_cannot_override_failed_bindings(self):
        raw = json.dumps(self.index).encode()
        raw = raw[:-1] + b', "location_index_only": false}'
        with self.assertRaises(ValueError):
            read_native_locations(self.cold, self.raw, raw)

    def test_old_nested_report_hash_is_checked_before_admission(self):
        self.cold.write_text(json.dumps({"schema": "hepta.hia.selfhost-cold-replay.v1",
            "nested_report": str(self.root / "legacy.json"), "nested_report_sha256": "0" * 64}))
        (self.root / "legacy.json").write_text(json.dumps({"generations": self.index["generations"]}))
        with patch("tools.build_hia_json_preflight.admit_cold_build") as gate:
            with self.assertRaisesRegex(ValueError, "legacy nested cold report bytes differ"):
                compiler_from_cold_report(self.cold)
        gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
