#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Check retained formal-connector installation reads against one pinned lock.

This offline checker authenticates no endpoint and deploys nothing. It checks
the exact captured MCP envelopes, the describe/read artifact binding and the
complete three-part installation identity. Its PASS is a point-in-time readback
claim under the capture's stated provenance, not a runtime-binary attestation.
Only complete, one-page UTF-8 manifests are admitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 4 * 1024 * 1024
PINS = frozenset(("worker_sha256", "backend_sha256", "catalog_sha256"))
VERSION = "hepta.hia.agent-native.v1"


class InvalidCapture(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidCapture(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "bounded raw bytes required")

    def members(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result

    def nonfinite(_value):
        raise InvalidCapture("nonfinite JSON number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=members,
                           parse_constant=nonfinite)
        # Reject lone surrogates and overflowing JSON numbers too.
        json.dumps(value, allow_nan=False, ensure_ascii=False).encode("utf-8")
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InvalidCapture("invalid bounded JSON capture") from exc


def digest_value(value, length=64):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def pins(value):
    require(type(value) is dict and set(value) == PINS and
            all(digest_value(item) for item in value.values()),
            "exact worker, backend and catalog SHA256 identities required")
    return value


def descriptor(value):
    require(type(value) is dict and set(value) == {"id", "uri", "sha256"},
            "complete artifact reference required")
    require(type(value["id"]) is str and re.fullmatch(r"a-[0-9a-f]{32}", value["id"]) is not None,
            "invalid retained artifact id")
    require(type(value["uri"]) is str and
            re.fullmatch(r"hia://artifacts/[0-9a-f]{32}", value["uri"]) is not None,
            "invalid retained artifact URI")
    require(digest_value(value["sha256"]), "invalid retained artifact digest")
    return value


def completed_envelope(raw, label):
    wrapper = decode(raw)
    require(type(wrapper) is dict and wrapper.get("isError", False) is False,
            label + " connector result is an error")
    blocks = wrapper.get("content")
    require(type(blocks) is list and len(blocks) == 1 and
            type(blocks[0]) is dict and blocks[0].get("type") == "text" and
            type(blocks[0].get("text")) is str, label + " exact text envelope required")
    payload = decode(blocks[0]["text"].encode("utf-8"))
    structured = wrapper.get("structuredContent")
    require(structured is None or structured == payload,
            label + " text and structured envelopes disagree")
    require(type(payload) is dict and payload.get("contract_version") == VERSION and
            payload.get("status") == "completed" and
            type(payload.get("request_id")) is str and
            re.fullmatch(r"r-[0-9a-f]{64}", payload["request_id"]) is not None and
            type(payload.get("result")) is dict,
            label + " completed HIA result with request identity required")
    return payload


def check_readback(lock_raw, expected_lock_sha256, describe_raw, read_raw):
    require(digest_value(expected_lock_sha256) and sha256(lock_raw) == expected_lock_sha256,
            "public release-lock digest differs")
    lock = decode(lock_raw)
    require(type(lock) is dict and lock.get("schema") == "hepta.hia.release-lock.v1",
            "known release-lock schema required")
    expected = pins(lock.get("installation"))
    sources = lock.get("sources")
    require(type(sources) is dict and set(sources) == {"hepta", "runtime"},
            "both selected source identities required")
    for name in ("hepta", "runtime"):
        source = sources[name]
        require(type(source) is dict and digest_value(source.get("commit"), 40) and
                digest_value(source.get("tree"), 40) and
                type(source.get("repository")) is str,
                "source commit, tree and repository required")
    describe = completed_envelope(describe_raw, "describe")
    read = completed_envelope(read_raw, "read")
    discovered = describe["result"]
    content = read["result"]
    reference = descriptor(discovered.get("manifest"))
    require(descriptor(content.get("artifact")) == reference,
            "read artifact differs from the discovered manifest")
    require("next_cursor" in content and content["next_cursor"] is None,
            "complete one-page manifest required")
    require(content.get("encoding") == "utf8" and type(content.get("content")) is str,
            "UTF-8 manifest content required")
    manifest_raw = content["content"].encode("utf-8")
    require(sha256(manifest_raw) == reference["sha256"], "manifest content digest differs")
    manifest = decode(manifest_raw)
    require(type(manifest) is dict and manifest.get("schema") == "hepta.hia.agent.manifest.v1",
            "known installed manifest schema required")
    observed = pins(manifest.get("installation"))
    require(discovered.get("catalog_sha256") == manifest.get("catalog_sha256") ==
            observed["catalog_sha256"], "discovery, manifest and installation catalogs disagree")
    matches = {key: observed[key] == expected[key] for key in sorted(PINS)}
    passed = all(matches.values())
    return {
        "schema": "hepta.hia.online-release-readback.v1",
        "status": "PASS_CURRENT_INSTALLATION_READBACK" if passed else "HOLD_INSTALLATION_MISMATCH",
        "passed": passed,
        "scope": "captured formal connector worker/backend/catalog identity equals the pinned public lock",
        "release_lock_sha256": expected_lock_sha256,
        "selected_sources": sources,
        "capture_sha256": {"describe": sha256(describe_raw), "read": sha256(read_raw)},
        "request_ids": {"describe": describe["request_id"], "read": read["request_id"]},
        "manifest_artifact": reference,
        "expected_installation": expected,
        "observed_installation": observed,
        "matches": matches,
        "does_not_establish": ["capture provenance without the retained tool observation",
            "runtime executable identity or build provenance", "source-only loading at the live runtime",
            "a deployment action by the reader", "service uptime or later installation state",
            "whole-Core correctness, Agent adoption or NDU benefit"],
    }


def bounded_read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "capture file exceeds bound")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--lock-sha256", required=True)
    parser.add_argument("--describe", required=True)
    parser.add_argument("--read", required=True)
    args = parser.parse_args(argv)
    try:
        report = check_readback(bounded_read(args.lock), args.lock_sha256,
                                bounded_read(args.describe), bounded_read(args.read))
    except (OSError, InvalidCapture, UnicodeError) as exc:
        print(json.dumps({"schema": "hepta.hia.online-release-readback.v1", "passed": False,
                          "status": "HOLD_INVALID_CAPTURE", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
