#!/usr/bin/env python3
"""Replay the adf1 capture with the existing PR806 checker; no online calls."""
from pathlib import Path
import importlib.util
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("retained_readback_checker", ROOT / "tools/check_hia_online_readback.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

raw = checker.bounded_read(HERE / "live-installation-original.json")
checker.require(checker.sha256(raw) == "3e8b34564c97b65142e1d0a7144785a76ad573e965560e55ab1facf80d4867d7",
                "independent original capture changed")
capture = checker.decode(raw)
checker.require(capture["public_entry_commit"] == "b4080858698e1b0f26d87f185b847ff9e1133fd1",
                "historical entry mapping changed")
lock = checker.bounded_read(ROOT / "review-evidence/hia-online-readback-20261108-5e6c/evidence/public-release-lock-b408085.json")
envelope = lambda name: json.dumps(capture[name]["response"], sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode("utf-8")
report = checker.check_readback(lock, "1c4b747721bfc215549512287d62febbadfaf7bce3cd2b6baafeed3d67a10c18",
                               envelope("describe"), envelope("read"))
checker.require(report["passed"], "independent capture does not match the historical lock")
report["capture_bundle_sha256"] = checker.sha256(raw)
report["capture_recorded_at_utc"] = capture["recorded_at_utc"]
report["historical_entry_commit"] = capture["public_entry_commit"]
report["envelope_serialization"] = "canonical JSON of original response objects; original text payloads preserved"
report["source_mapping_scope"] = "source commits are read from the public lock; the live installation returns only worker/backend/catalog digests"
print(json.dumps(report, sort_keys=True, indent=2))
