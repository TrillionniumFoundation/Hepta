"""Retain the exact hosted workflow control and admit the current native archive.

The retained workflow is a complete historical regression fixture. Current
native failure handling is checked separately before that fixture is selected.
"""
from __future__ import annotations
import ast
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "tests/fixtures/hia_workflow_cold_history_20261128.json"
FIXTURE_SHA256 = "5ad45b5c7eb4d1a2f12af14e7d962093cc7a523e6268ee20412e4919e8e6a300"
ORIGINAL_COMMIT = "c5c16f10946579401e48c8d83819c6106b87e862"
ORIGINAL_BLOB = "cb4ea1eeb6835354f431694c86699be28101267c"
ARCHIVE_NAME = "Preserve actual cold failure and stage evidence"
NATIVE_COMMAND = '        run: python -B tools/replay_hia_native_cold.py --output "$RUNNER_TEMP/hia-cold.json"'
REQUIRED_PATHS = ("hia-cold.json", "hia-cold.native-cold/", "hia-cold.generations.json",
                  "hia-language.json", "hia-language.assertions.json",
                  "hia-language.evidence/", "hia-nominal-fixture/",
                  "hia-module-projects/", "hia-journal-callers.json")


def archive_block(source):
    lines = source.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "      - name: " + ARCHIVE_NAME]
    if len(starts) != 1:
        raise ValueError("actual native cold failure archive is missing or ambiguous")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("      - ")), len(lines))
    return lines, start, end


def admit_current_native_archive(source, entry_source):
    lines, start, end = archive_block(source)
    archive = lines[start:end]
    if "continue-on-error" in source:
        raise ValueError("native workflow must preserve first failure")
    if lines.count(NATIVE_COMMAND) != 1 or lines.index(NATIVE_COMMAND) >= start:
        raise ValueError("actual native cold command is missing, changed or after the archive")
    for required in ("        if: always()", "        uses: actions/upload-artifact@v4",
                     "          include-hidden-files: true", "          if-no-files-found: error"):
        if archive.count(required) != 1:
            raise ValueError("native cold failure archive boundary changed: " + required.strip())
    for name in REQUIRED_PATHS:
        if archive.count("            ${{ runner.temp }}/" + name) != 1:
            raise ValueError("native cold archive input changed: " + name)
    budgets = {}
    for node in ast.walk(ast.parse(entry_source)):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in (
                        "qualification_wall_limit_seconds", "cleanup_wall_limit_seconds"):
                    if key.value in budgets or not isinstance(value, ast.Constant):
                        raise ValueError("native cold budget is not an unambiguous literal")
                    budgets[key.value] = value.value
    if budgets != {"qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3}:
        raise ValueError("native cold original 180+3 budget changed")
    return {"scope": "current-native-workflow-failure-boundary",
            "archive_after_native_command": True, "original_budget": budgets,
            "always_archived": True, "archive_inputs": list(REQUIRED_PATHS),
            "whole_native_delivery_qualified": False}


def historical_workflow(root=ROOT, *, take=Path.read_bytes):
    path = Path(root) / FIXTURE
    try:
        raw = take(path)
    except FileNotFoundError as exc:
        raise ValueError("retained workflow authority is missing") from exc
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("retained workflow authority changed")
    record = json.loads(raw)
    if (record["schema"] != "hepta.hia.workflow-cold-history.v1"
            or record["commit"] != ORIGINAL_COMMIT or record["git_blob"] != ORIGINAL_BLOB
            or record["path"] != ".github/workflows/hia-core.yml"):
        raise ValueError("retained workflow source domain changed")
    original = zlib.decompress(base64.b64decode(record["zlib_base64"], validate=True))
    if (len(original) != record["bytes"] or sha256(original).hexdigest() != record["sha256"]
            or sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest() != ORIGINAL_BLOB):
        raise ValueError("complete retained workflow source differs")
    if take(path) != raw:
        raise ValueError("retained workflow authority changed at terminal readback")
    return original, record
