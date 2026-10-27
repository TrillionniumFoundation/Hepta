"""Strict structural checks shared by qualification report validators.

These checks bind retained observations; they do not authenticate an arbitrary
third-party report or replace actually executing its qualification producer.
"""
from functools import wraps
import hashlib
import json
import math


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_equal(left, right):
    # Python equality identifies True with 1 and 1 with 1.0; evidence schemas do
    # not. Canonical JSON also rejects non-finite numeric claims.
    return json.dumps(left, sort_keys=True, allow_nan=False, separators=(",", ":")) == json.dumps(right, sort_keys=True, allow_nan=False, separators=(",", ":"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def is_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def text(value):
    return isinstance(value, str) and bool(value) and len(value) <= 1024 * 1024


def normalized_errors(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (KeyError, TypeError, AttributeError, OverflowError, RecursionError) as error:
            raise ValueError("Malformed qualification report: " + str(error)) from error
    return checked


def native_build(native, backend, *, check_only, crate_type, source_sha256):
    require(isinstance(native, dict) and native.get("ok") is True and native.get("check_only") is check_only,
            "native build status or execution kind differs")
    require(native.get("status") == ("gcc_checked" if backend == "c" else "rustc_checked") and native.get("crate_type") == crate_type,
            "native compiler/backend profile differs")
    source_key = "source_sha256" if backend == "c" else "rust_sha256"
    require(is_sha(source_sha256) and native.get(source_key) == source_sha256, "native source identity missing/mismatched")
    require(is_sha(native.get("validation_artifact_sha256")), "native validation artifact identity missing")
    require(isinstance(native.get("diagnostics"), list) and not native["diagnostics"], "native build diagnostics not successful")
    require(text(native.get("target")), "native target identity missing")
    toolchain = native.get("toolchain", {})
    require(text(toolchain.get("path")) and text(toolchain.get("version")) and is_sha(toolchain.get("executable_sha256")),
            "native toolchain identity incomplete")
    flags = native.get("flags")
    require(isinstance(flags, list) and flags and all(text(x) for x in flags) and len(set(flags)) == len(flags), "native flags missing/duplicated")
    if backend == "c":
        require(native.get("backend") == "c11-gcc" and native.get("rustc_used") is False, "independent C backend changed")
    if not check_only:
        require(type(native.get("artifact_bytes")) is int and native["artifact_bytes"] > 0 and text(native.get("artifact")),
                "final native artifact missing/empty")
        require(is_sha(native.get("artifact_sha256")) and native["artifact_sha256"] == native["validation_artifact_sha256"],
                "final native artifact identities differ")


def command(entry):
    require(isinstance(entry, dict) and isinstance(entry.get("argv"), list) and entry["argv"]
            and all(text(x) for x in entry["argv"]), "missing executed command")
    require(type(entry.get("returncode")) is int, "command exit code must be an integer")
    require(type(entry.get("seconds")) in {int, float} and math.isfinite(entry["seconds"]) and entry["seconds"] >= 0,
            "command timing missing/nonfinite")
    require(isinstance(entry.get("stdout"), str) and isinstance(entry.get("stderr"), str), "command output missing")
