"""Ordinary source-built release of the complete, fixed HIA NDU evaluator.

The published JSON is the immutable historical leaf qualification contract.
Current construction evidence is separate; this route uses a native source-build
kit and never claims that it executed the historical bootstrap filter recipe.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct

CONTRACT = "docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json"
CONTRACT_SHA256 = "9d04ec9fab8a0f0ce2d467a951793fc92a890baae8cae985ab9cbfe7476b89a2"
POLICY = "source_ndu_evaluator.hepta"
PACKER = "ndu_evaluator_packer.hepta"
PRODUCT = "_hia_ndu_evaluator.elf"
CONTRACT_PRODUCT = "_hia_ndu_evaluator_build.json"
ROLES = ("transport", "evaluator", "number", "debug")


def checked_contract(raw):
    if type(raw) is not bytes or sha256(raw).hexdigest() != CONTRACT_SHA256:
        raise ValueError("NDU historical native qualification contract differs")
    return json.loads(raw)


def frame(images, contract):
    rows = {row["role"]: row for row in contract["build_inputs"]["modules"]}
    if set(images) != set(ROLES):
        raise ValueError("NDU constructor requires exactly four native images")
    parts = []
    for role in ROLES:
        raw = images[role]
        if (type(raw) is not bytes or len(raw) != rows[role]["flat_bytes"]
                or sha256(raw).hexdigest() != rows[role]["flat_sha256"]):
            raise ValueError("NDU compiled input differs: " + role)
        parts.append(raw)
    return b"HIANDP01" + struct.pack("<5Q", *map(len, parts), 0) + b"".join(parts)


def stage_ndu_evaluator(work, seed, compile_sources, call, compiler, publish):
    from tools.build_hia_native_store_release import release_sources

    builds = release_sources(seed, compile_sources, call)
    contract_raw = builds.capture_sources({Path(CONTRACT).name: CONTRACT})[Path(CONTRACT).name]
    contract = checked_contract(contract_raw)
    # Every historical dependency is a real native source capture, including
    # mechanical capsules and Unicode data; none is a Python runtime input.
    names = {str(index): name for index, name in enumerate(contract["source_files"])}
    captured = builds.capture_sources(names)
    for alias, name in names.items():
        if sha256(captured[alias]).hexdigest() != contract["source_files"][name]:
            raise ValueError("NDU native source differs: " + name)
    author, kit_images, _ = builds.kit_objects(POLICY, PACKER)
    if kit_images["selfhost.hepta"] != compiler:
        raise ValueError("NDU constructor kit has a different cold compiler")
    rows = {row["role"]: row for row in contract["build_inputs"]["modules"]}
    packer = kit_images["source_build_packer.hepta"]
    if (len(packer) != rows["packer"]["flat_bytes"]
            or sha256(packer).hexdigest() != rows["packer"]["flat_sha256"]):
        raise ValueError("NDU native packer differs from its original complete image")
    named = {role + ".hepta": rows[role]["source_path"] for role in ROLES}
    _, flats, _ = builds(named)
    wire = frame({role: flats[role + ".hepta"] for role in ROLES}, contract)
    first = call(author, "build", wire)
    second = call(author, "build", wire)
    if (first != second or len(first) != contract["binary_bytes"]
            or sha256(first).hexdigest() != contract["binary_sha256"]):
        raise ValueError("NDU source-built image differs from the qualified leaf")
    # Terminal physical captures must still equal the initial source bytes.
    if (builds.capture_sources(names) != captured
            or builds.capture_sources({Path(CONTRACT).name: CONTRACT})[Path(CONTRACT).name] != contract_raw):
        raise ValueError("NDU source changed during native construction")
    work = Path(work)
    for name, raw, expected in ((PRODUCT, first, contract["binary_sha256"]),
                                (CONTRACT_PRODUCT, contract_raw, CONTRACT_SHA256)):
        target = work / name
        with target.open("xb") as stream:
            stream.write(raw)
        publish(target, expected=expected)
