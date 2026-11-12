"""Small file and lifecycle checks for this one full-retained capsule draft.

This file is hosted control code. It does not alter a product owner, gate,
test population, or timeout. The draft policy deliberately cannot dispatch.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import urllib.parse


GUARDIAN_SHA256 = "d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023"
OWNER_SHA256 = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
PREPARER_SHA256 = "972dffc85f53093aa8d06f53a1a2154dc1731e7ad93c0ca39c93f0b03a91ffbc"
LIMITS = {
    "controller_seconds": 10800, "full_retained_seconds": 5400,
    "cold_seconds": 180, "cold_workers": 2, "cold_phases": 38,
    "cleanup_seconds": 3, "source_materialization_seconds": 900,
    "supply_seconds": 3600, "prerequisite_seconds": 900, "custody_seconds": 1800,
    "minimum_free_bytes": 8 << 30, "minimum_free_inodes": 100000,
}
PACKAGE_PINS = {"setuptools": "78.1.1", "wheel": "0.46.3",
                "z3-solver": "4.15.4.0", "jsonschema": "4.26.0"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def parent_fd(path):
    """Hold and recheck every actual parent; never traverse a link."""
    path = Path(path)
    require(path.is_absolute() and path.name not in ("", ".", "..")
            and ".." not in path.parts, "an absolute canonical path is required")
    descriptors, links = [], []
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(descriptor)
        for part in path.parent.parts[1:]:
            before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode), "non-directory parent")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            require((before.st_dev, before.st_ino, before.st_mode)
                    == (os.fstat(child).st_dev, os.fstat(child).st_ino, os.fstat(child).st_mode),
                    "parent changed before open")
            links.append((descriptor, part, child, (before.st_dev, before.st_ino, before.st_mode)))
            descriptors.append(child)
            descriptor = child

        def stable():
            for parent, name, child, expected in links:
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                opened = os.fstat(child)
                require((named.st_dev, named.st_ino, named.st_mode) == expected
                        == (opened.st_dev, opened.st_ino, opened.st_mode),
                        "parent namespace changed")
        stable()
        yield descriptor, path.name, stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def file_record(path, *, expected=None, body_limit=None):
    path = Path(path)
    chunks = [] if body_limit is not None else None
    with parent_fd(path) as (parent, name, stable):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
        if body_limit is not None:
            require(before.st_size <= body_limit, "control file exceeds its read bound")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        try:
            require(identity(os.fstat(descriptor)) == identity(before), "file changed before read")
            digest, count = sha256(), 0
            while block := os.read(descriptor, 1 << 20):
                count += len(block)
                require(count <= before.st_size, "file grew during read")
                digest.update(block)
                if chunks is not None:
                    chunks.append(block)
            require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before),
                    "file changed during read")
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    "named file changed during read")
            stable()
        finally:
            os.close(descriptor)
    record = {"path": str(path), "bytes": count, "sha256": digest.hexdigest(),
              "identity": list(identity(before))}
    if expected is not None:
        require(all(record[key] == expected[key] for key in ("bytes", "sha256")),
                "external file pin differs: " + str(path))
    return (record, b"".join(chunks)) if chunks is not None else record


def read_json(path, expected=None, limit=4 << 20):
    record, raw = file_record(path, expected=expected, body_limit=limit)
    value = json.loads(raw)
    require(type(value) is dict, "control JSON must be an object")
    return value, record


def create(path, raw, mode=0o600):
    with parent_fd(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(raw)
                output.flush()
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            stable()
            os.fsync(parent)
        finally:
            os.close(descriptor)
    return file_record(path, expected={"bytes": len(raw), "sha256": sha256(raw).hexdigest()})


def copy_original(source, destination, expected=None):
    """One independent, fully read-back copy; never truncate a diagnostic."""
    before = file_record(source, expected=expected)
    with parent_fd(source) as (parent, name, stable):
        original = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=parent)
        try:
            require(list(identity(os.fstat(original))) == before["identity"], "copy input changed before open")
            with parent_fd(destination) as (target_parent, target_name, target_stable):
                target = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=target_parent)
                try:
                    remaining = before["bytes"]
                    while remaining:
                        block = os.read(original, min(1 << 20, remaining))
                        require(block, "short diagnostic original")
                        remaining -= len(block)
                        offset = 0
                        while offset < len(block):
                            written = os.write(target, memoryview(block)[offset:])
                            require(written > 0, "short diagnostic copy")
                            offset += written
                    require(not os.read(original, 1), "diagnostic original grew during copy")
                    os.fsync(target)
                    target_stable()
                    os.fsync(target_parent)
                finally:
                    os.close(target)
            require(list(identity(os.fstat(original))) == before["identity"], "copy input changed during read")
            stable()
        finally:
            os.close(original)
    require(file_record(source) == before, "copy input named identity changed")
    copied = file_record(destination, expected=before)
    return {"original": before, "copy": copied}


def checkpoint(root, stem, value):
    """Each observation gets a new file; no original report is overwritten."""
    directory = Path(root) / "checkpoints"
    directory.mkdir(mode=0o700, exist_ok=True)
    index = len(list(directory.glob(stem + ".*.json")))
    return create(directory / f"{stem}.{index:04d}.json", wire(value))


def clean_environment(*, network=False):
    # HOME, USER, and LOGNAME retain their inherited meanings. No token enters
    # a product child or an original process-owner request.json.
    allowed = {"HOME", "USER", "LOGNAME", "SHELL", "PATH", "TZ", "TERM",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"}
    if network:
        allowed |= {"http_proxy", "https_proxy", "all_proxy", "no_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    result = {key: value for key, value in os.environ.items() if key in allowed}
    # This runs before any original guardian/workflow request can serialize the
    # returned environment. Keep configured proxy bytes unchanged; refuse a
    # credential-bearing value rather than deleting or bypassing the proxy.
    for key in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        if key not in result:
            continue
        value = result[key]
        require(type(value) is str and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value),
                "malformed proxy cannot enter retained capsule requests")
        if not value:
            continue
        # urllib also accepts a scheme-less host:port or user:pass@host:port.
        # Normalize only the validation view, never the inherited value.
        candidate = value if "://" in value or value.startswith("//") else "//" + value
        try:
            parsed = urllib.parse.urlsplit(candidate)
            parsed_port = parsed.port
            has_host = bool(parsed.hostname)
        except (ValueError, UnicodeError):
            raise ValueError("malformed proxy cannot enter retained capsule requests") from None
        require(has_host and parsed.username is None and parsed.password is None
                and not parsed.query and not parsed.fragment,
                "credential-bearing proxy cannot enter retained capsule requests")
    result.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", PYTHONNOUSERSITE="1",
                  LANG="C.UTF-8", LC_ALL="C.UTF-8", GIT_TERMINAL_PROMPT="0",
                  GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_GLOBAL="/dev/null",
                  GIT_CONFIG_SYSTEM="/dev/null", CARGO_BUILD_JOBS="2")
    return result


def closed_guardian(value, request):
    """A nonzero natural result can be closed; it still cannot qualify."""
    require(value.get("schema") == "hepta.hia.external-qualification-guardian.v1"
            and value.get("command") == request["command"]
            and value.get("cwd") == request["cwd"]
            and value.get("external_controller_seconds") == request["controller_seconds"]
            and value.get("lifecycle_implementation_sha256") == OWNER_SHA256
            and value.get("source_identities_before") == request["source_identities"],
            "guardian does not describe this exact request")
    lifecycle = value.get("lifecycle", {})
    cleanup = lifecycle.get("cleanup", {})
    # supervise() deliberately does not repeat argv/cwd in its inner receipt.
    # Those are bound by the original guardian's outer receipt and input pins.
    require(lifecycle.get("schema") == "hepta.hia.external-qualification-guardian.v1.lifecycle"
            and lifecycle.get("qualification_seconds") == request["controller_seconds"]
            and lifecycle.get("cleanup_seconds") == 3,
            "actual lifecycle schema/budgets differ")
    require(cleanup.get("complete") is True and cleanup.get("observed_echild") is True
            and cleanup.get("leader_reaped") is True and cleanup.get("remaining_direct_children") == []
            and cleanup.get("deadline_exceeded") is False and cleanup.get("errors") == [],
            "owner did not prove closed ECHILD")
    return lifecycle


def natural_guardian(value, request):
    lifecycle = closed_guardian(value, request)
    require(value.get("status") in {"EXTERNAL_OWNED_PROCESS_COMPLETED", "GUARDIAN_FULL_RETAINED_PASS"}
            and value.get("classification_error") is None
            and value.get("input_identity_preserved") is True
            and value.get("source_identities_after") == request["source_identities"]
            and lifecycle.get("status") == "OWNED_PROCESS_COMPLETED"
            and lifecycle.get("returncode") == 0
            and lifecycle.get("exit_observed_before_deadline") is True
            and lifecycle.get("timed_out") is False
            and lifecycle.get("subreaper_enabled") is True
            and lifecycle.get("qualification_started") is True
            and lifecycle.get("event_overflow") is False
            and lifecycle.get("interrupted_signals") == []
            and lifecycle.get("owner_error") is None,
            "owned operation did not finish naturally")
    events = lifecycle.get("events", [])
    names = [item.get("kind") for item in events]
    allowed = {"qualification_started", "owned_child_observed", "qualification_exit_observed",
               "owned_child_reaped"}
    pid = lifecycle.get("qualification_pid")
    require(type(pid) is int and pid > 0 and set(names) <= allowed
            and names.count("qualification_started") == names.count("qualification_exit_observed") == 1
            and any(item.get("kind") == "owned_child_reaped" and item.get("pid") == pid
                    and item.get("returncode") == 0 for item in events),
            "natural event ledger contains a kill/overflow or lacks the original leader events")
    return lifecycle
