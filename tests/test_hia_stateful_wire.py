"""P7: immutable whole-queue wire, exact fences and no identity overwrite."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import (
    OwnedAdaptiveRuntime, _MAX_QUEUE_WIRE_BYTES, _QUEUE_WIRE_SCHEMA, _Work,
)
from tests.test_hia_stateful_queue_capture import fake_runtime


def runtime():
    owner = fake_runtime()
    owner._generation = 4
    return owner


def envelope(owner):
    return {"schema": _QUEUE_WIRE_SCHEMA,
            "owner_id": owner._owner_id, "generation": owner._generation,
            "revision": owner._revision,
            "items": [{"slot": 0, "delta": 2, "iterations": 3}]}


def wire(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class HIAImmutableQueueWireTests(unittest.TestCase):
    def test_valid_canonical_wire_binds_owner_and_exact_sha(self):
        owner = runtime()
        source = wire(envelope(owner))
        result = owner.submit_queue_wire(source)
        self.assertEqual(result["input_sha256"], sha256(source).hexdigest())
        self.assertEqual(result["owner_id"], owner._owner_id)
        self.assertEqual(result["generation"], 4)
        self.assertEqual(result["revision"], 0)
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertFalse(result["durable_crash_recovery"])
        token = result["token"]
        self.assertEqual(owner._queues[token]["items"], (_Work(0, 2, 3),))
        self.assertEqual(owner._queues[token]["intake_wire_sha256"], result["input_sha256"])
        self.assertGreater(owner._unamortized_preparation_ns, 0)

    def test_stale_generation_revision_and_foreign_owner_refuse(self):
        for key, value in (("generation", 3), ("generation", True),
                           ("revision", 1), ("revision", False),
                           ("owner_id", "a" * 32), ("owner_id", None)):
            owner = runtime()
            doc = envelope(owner)
            doc[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    AdaptiveRejected, "E_STATE_FENCE"):
                owner.submit_queue_wire(wire(doc))
            self.assertEqual(owner._queues, {})

    def test_malformed_oversize_and_noncanonical_intake_fail_closed(self):
        owner = runtime()
        valid = wire(envelope(owner))
        for bad in (bytearray(valid), valid.decode(), b"", b" " + valid,
                    json.dumps(envelope(owner), indent=2).encode(),
                    valid + b" ", b"\xff", b'{"items":[],"items":[]}',
                    b'{"schema":"hepta.hia.owner-queue-wire.v1","schema":"other"}',
                    b" " * (_MAX_QUEUE_WIRE_BYTES + 1)):
            with self.subTest(bad=repr(bad)[:60]), self.assertRaises(AdaptiveRejected):
                owner.submit_queue_wire(bad)
            self.assertEqual(owner._queues, {})
        with patch("hepta.hia_stateful.json.loads",
                   side_effect=AssertionError("unbounded wire passed early guard")):
            with self.assertRaisesRegex(AdaptiveRejected, "immutable"):
                owner.submit_queue_wire(b"A" * (_MAX_QUEUE_WIRE_BYTES + 1))

    def test_exact_envelope_and_resource_budget_refusals(self):
        for change in (
            lambda x: x.update(schema="hepta.hia.owner-queue-wire.v2"),
            lambda x: x.update(extra="unknown"),
            lambda x: x.pop("items"),
            lambda x: x.update(items=[]),
            lambda x: x.update(items=[{"slot": 0, "delta": 1, "iterations": 1}] * 129),
            lambda x: x.update(items=[{"slot": 0, "delta": 1, "iterations": 600000000},
                                      {"slot": 0, "delta": 1, "iterations": 600000000}]),
            lambda x: x.update(items=[{"slot": 0, "delta": True, "iterations": 1}]),
            lambda x: x.update(items=[{"slot": 0, "delta": 1, "iterations": 0}]),
            lambda x: x.update(items=[{"slot": 5, "delta": 1, "iterations": 1}]),
        ):
            owner = runtime()
            doc = deepcopy(envelope(owner))
            change(doc)
            with self.assertRaises(AdaptiveRejected):
                owner.submit_queue_wire(wire(doc))
            self.assertEqual(owner._queues, {})

    def test_collision_cannot_replace_an_already_retained_queue(self):
        owner = runtime()
        original = {"status": "completed", "sha256": "historical"}
        owner._queues["collision"] = original
        with patch("hepta.hia_stateful.secrets.token_hex", return_value="collision"):
            with self.assertRaisesRegex(AdaptiveRejected, "collision"):
                owner.submit_queue([{"slot": 0, "delta": 1, "iterations": 1}])
        self.assertIs(owner._queues["collision"], original)
        self.assertEqual(len(owner._queues), 1)


if __name__ == "__main__":
    unittest.main()
