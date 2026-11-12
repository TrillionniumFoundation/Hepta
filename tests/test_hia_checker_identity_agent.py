"""The ordinary retained-receipt consumer rejects changed native checkers."""
from hashlib import sha256
import importlib
import json
import os
from unittest.mock import patch

from hepta.hia_agent_store import AgentRejected, digest
from hepta.hia_checker_identity import checker_native_selection
from tests.test_hia_agent_native_tools import AgentToolCase
from tools.hia_agent_native_qualification import add_program
from tests.test_hia_checker_identity import INTEGRATED_OWNERS


class NativeCheckerReceiptIdentityTests(AgentToolCase):
    def verified(self):
        self.session.freeze({"schema": "hepta.hia.agent.workload.v1",
            "cases": [{"function": "transform", "arguments": [0]}],
            "warmup_iterations": 0, "repetitions": 1})
        candidate = self.session.import_program(add_program())
        result = self.session.verify(candidate)
        return candidate, result

    def test_proof_and_raw_evidence_bind_the_actual_checker_selection(self):
        candidate, result = self.verified()
        check = result["checks"][0]
        self.assertEqual(check["checker"]["native_selection_sha256"],
                         digest(checker_native_selection(held_owners=self.service._held_checker_owners())))
        evidence = self.session.read_json(check["evidence_artifact"])
        self.assertEqual(evidence["native_checker_selection"],
                         checker_native_selection(held_owners=self.service._held_checker_owners()))
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_ordinary_consumer_rejects_a_receipt_after_native_owner_selection_changes(self):
        from hepta.hia_json_preflight_native import SOURCE, SCHEMA
        candidate, result = self.verified()
        image = self.root / "bounded-identity-fixture.bin"
        image.write_bytes(bytes.fromhex("31c0c3"))
        manifest = self.root / "bounded-identity-fixture.json"
        manifest.write_text(json.dumps({"schema": SCHEMA,
            "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
            "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
            "compiler_sha256": "a" * 64}))
        with patch.dict(os.environ, {"HEPTA_HIA_JSON_PREFLIGHT_MANIFEST": str(manifest)}):
            with self.assertRaises(AgentRejected) as rejected:
                self.service._verification(result["verification_receipt"], self.session.context, candidate)
            self.assertEqual(rejected.exception.code, "E_HIA_PROOF_SCOPE")
        # A rejected consume does not destroy the original evidence. Restoring
        # its exact checker permits observation of that same original receipt.
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_a_legacy_unscoped_checker_cannot_pass_the_current_wire_contract(self):
        candidate, result = self.verified()
        record = self.session.read_json(result["verification_receipt"])
        del record["checks"][0]["checker"]["native_selection_sha256"]
        corrupted = self.service.store.json(record, "verification-receipt")
        with self.assertRaises(AgentRejected) as rejected:
            self.service._verification(corrupted, self.session.context, candidate)
        self.assertEqual(rejected.exception.code, "E_HIA_PROOF_SCOPE")

    def test_each_integrated_owner_revokes_an_existing_actual_core_receipt(self):
        from hepta.hia_checker_identity import NATIVE_OWNERS
        candidate, result = self.verified()
        for selector in INTEGRATED_OWNERS:
            module_name, _loader = NATIVE_OWNERS[selector]
            module = importlib.import_module('hepta.' + module_name)
            image = self.root / (module_name + '.bin')
            # A mapping-identity fixture, never executed by this scalar claim.
            image.write_bytes(bytes.fromhex('31c0c3'))
            manifest = self.root / (module_name + '.json')
            manifest.write_text(json.dumps({'schema': module.SCHEMA,
                'source_sha256': sha256(module.SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': 'a' * 64}))
            with self.subTest(selector=selector):
                with patch.dict(os.environ, {selector: str(manifest)}):
                    with self.assertRaises(AgentRejected) as rejected:
                        self.service._verification(result['verification_receipt'],
                                                   self.session.context, candidate)
                    self.assertEqual(rejected.exception.code, 'E_HIA_PROOF_SCOPE')
                self.service._verification(result['verification_receipt'], self.session.context, candidate)
