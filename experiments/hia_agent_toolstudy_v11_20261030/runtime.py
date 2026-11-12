"""Enforce exact b11669 archive members before accepting helper identities.

This binds local runtime files and symlink topology. The operating-system
loader, libraries outside this archive, kernel and hardware remain trusted;
this is not runtime mapping attestation or full software supply-chain proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from tools.provider_adapter.llama_cpp_engine import file_identity

MANIFEST = Path(__file__).resolve().parent / "provenance/RUNTIME_MEMBERS.json"
MANIFEST_SHA256 = "3bf3805e63245ac06d434c03f8d91e9815788ff00377acbd94e43f7bd3325f92"
ARCHIVE_SHA256 = "cf07c1c112d709bd67e522017471de57ed0ec8bea031d732c5422351c07f65ac"


def manifest():
    data = MANIFEST.read_bytes()
    if hashlib.sha256(data).hexdigest() != MANIFEST_SHA256:
        raise ValueError("E_TOOLSTUDY_V11_RUNTIME_MANIFEST")
    value = json.loads(data)
    if value["archive_sha256"] != ARCHIVE_SHA256 or value["archive_bytes"] != 17851611:
        raise ValueError("E_TOOLSTUDY_V11_RUNTIME_ARCHIVE")
    return value


def verify_runtime(binary, tokenizer):
    expected = {item["name"]: item for item in manifest()["members"]}
    server = Path(binary).resolve(strict=True)
    tokens = Path(tokenizer).resolve(strict=True)
    if server.name != "llama-server" or tokens.name != "llama-tokenize" or server.parent != tokens.parent:
        raise ValueError("E_TOOLSTUDY_V11_PINNED_RUNTIME_ROLES")
    directory = server.parent
    expected_companions = {name for name in expected if ".so" in name}
    actual_companions = {p.name for pattern in ("*.so*", "*.dll") for p in directory.glob(pattern)}
    if actual_companions != expected_companions:
        raise ValueError("E_TOOLSTUDY_V11_RUNTIME_COMPANION_SET")
    result = {}
    for name, item in sorted(expected.items()):
        path = directory / name
        if item["kind"] == "symlink":
            if not path.is_symlink() or os.readlink(path) != item["linkname"]:
                raise ValueError("E_TOOLSTUDY_V11_RUNTIME_SYMLINK: " + name)
        elif path.is_symlink() or not path.is_file():
            raise ValueError("E_TOOLSTUDY_V11_RUNTIME_FILE: " + name)
        if path.resolve(strict=True).parent != directory:
            raise ValueError("E_TOOLSTUDY_V11_RUNTIME_ESCAPE: " + name)
        identity = file_identity(path)
        if identity["bytes"] != item["payload_bytes"] or identity["sha256"] != item["payload_sha256"]:
            raise ValueError("E_TOOLSTUDY_V11_RUNTIME_BYTES: " + name)
        key = ("binary" if name == "llama-server" else "tokenizer" if name == "llama-tokenize"
               else "runtime_companion:" + str(path))
        result[key] = identity
    return result
