#!/usr/bin/env python3
"""Preserve exact original source obligations across the package-kind repair."""
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OLD = b'    if kind not in {"bin", "lib"}:\n'
NEW = b'    if not isinstance(kind, str) or kind not in {"bin", "lib"}:\n'
HOOK = b'    from tools.verify_package_kind_context_sources import verify\n    verify()\n'
ARCHIVES = {'parent_files.json': 'a296fa61875f62561fc5ac20006aef53f8bb54eb', 'package_integration_components.json': '25e79c25d6ca38f05cefc80f30614140c6f63a8d', 'versioned_package_context_sources.json': '215917907223312405043c093e1ddd45f8d571e1'}
ADDITIONS = {'tests/test_package_kind_schema.py': '607235c85cbf67f39a24e86621917f5d7841fb50', 'tests/test_versioned_package_kind.py': '2a325ce4ca90e050d7d388f5674b63985f9eca73', 'docs/PACKAGE_KIND_SCHEMA.md': '04375f9dc66536ebab32827b4ad3c7a75fa989e9', 'docs/VERSIONED_PACKAGE_KIND.md': 'e0f653e1f0e1c76e4dbdaf31e9a62f85102d962c', 'tools/qualify_package_kind_context.py': '23cdeb5c8a48582cb7271a7e1f2c192e6f17b11f', '.github/workflows/package-kind-context.yml': 'd25f956a77cad23fbf7ceb419703c9bc8599a925'}


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def require(condition, message):
    if not condition:
        raise SystemExit("Package-kind provenance: " + message)


def verify():
    require(not sys.flags.optimize, "Python assertions must remain enabled")
    archive = ROOT / "tools/package_kind_context_origins"
    originals = {}
    for name, expected in ARCHIVES.items():
        data = (archive / name).read_bytes()
        require(blob(data) == expected, "archived source changed: " + name)
        originals[name] = json.loads(data)
    parent = originals["parent_files.json"]
    require(len(parent) == 177, "expected all 177 parent paths")
    package = (ROOT / "hepta/packages.py").read_bytes()
    require(package.count(NEW) == 1 and OLD not in package, "expected exactly one original kind guard")
    runner = (ROOT / "tools/qualify_versioned_package_context.py").read_bytes()
    require(runner.count(HOOK) == 1, "expected exactly one mandatory provenance hook")
    for path, expected in parent.items():
        data = (ROOT / path).read_bytes()
        if path == "hepta/packages.py":
            data = data.replace(NEW, OLD, 1)
        elif path == "tools/qualify_versioned_package_context.py":
            data = data.replace(HOOK, b"", 1)
        elif path in ("tests/package_integration_components.json", "tools/versioned_package_context_sources.json"):
            # Checked below against complete archived originals with named slots only.
            continue
        require(blob(data) == expected, "parent source/inverse changed: " + path)
    for path, expected in ADDITIONS.items():
        require(blob((ROOT / path).read_bytes()) == expected, "qualification source changed: " + path)

    components = copy.deepcopy(originals["package_integration_components.json"])
    components["preserved"]["hepta/packages.py"]["git_blob"] = blob(package)
    components["preserved"]["hepta/packages.py"]["sha256"] = hashlib.sha256(package).hexdigest()
    expected_components = (json.dumps(components, indent=2, sort_keys=True) + "\n").encode()
    require((ROOT / "tests/package_integration_components.json").read_bytes() == expected_components,
            "component manifest differs beyond the two package identity slots")

    context = copy.deepcopy(originals["versioned_package_context_sources.json"])
    context["parent_files"]["hepta/packages.py"] = blob(package)
    context["parent_files"]["tests/package_integration_components.json"] = blob(expected_components)
    context["reviewed_files"]["tools/qualify_versioned_package_context.py"] = blob(runner)
    verifier = "tools/verify_package_kind_context_sources.py"
    context["reviewed_files"][verifier] = blob((ROOT / verifier).read_bytes())
    expected_context = (json.dumps(context, indent=2, sort_keys=True) + "\n").encode()
    require((ROOT / "tools/versioned_package_context_sources.json").read_bytes() == expected_context,
            "context manifest differs beyond three identity slots and the verifier pin")
    return {"parent": "10b8d29da50ea26ef3d26fb4219750915654d101", "parent_files": 177,
            "unchanged_parent_files": 173, "production_lines_changed": 1,
            "supplier": "537eb4ff1e41b79d7a84f8fa2a961a6c44b6012b"}


if __name__ == "__main__":
    print("PACKAGE_KIND_PROVENANCE_PASS " + json.dumps(verify(), sort_keys=True), flush=True)
