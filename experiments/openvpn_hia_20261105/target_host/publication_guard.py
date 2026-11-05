#!/usr/bin/env python3
"""Fail-closed privacy gate for OpenVPN/HIA CI evidence publication.

An experiment can fail and still publish its nonsecret raw logs. This tool does
not determine experiment success; it only prevents artifact upload when public
material includes private keys, credentials, raw perf stacks or unsafe entries.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
PRIVATE_NAMES = {"id_rsa", "id_ecdsa", "id_ed25519", ".env", ".netrc", ".npmrc", ".pypirc"}
PRIVATE_SUFFIXES = {".key", ".p12", ".pfx"}
SECRETS = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    rb"|-----BEGIN OpenVPN Static key"
    rb"|\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}"
    rb"|(?i:aws_secret_access_key)\s*[:=]\s*[^\s]{16,}"
)


def inspect(public: Path) -> dict:
    if public.is_symlink() or not public.is_dir():
        raise ValueError("public evidence root missing, not a directory, or symlinked")
    root = public.resolve(strict=True)
    checked = 0
    total = 0
    for path in sorted(root.rglob("*")):
        item = path.lstat()
        rel = path.relative_to(root)
        if stat.S_ISLNK(item.st_mode) or not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)):
            raise ValueError(f"unsafe symlink or special artifact entry: {rel}")
        if path.resolve(strict=True) != root / rel:
            raise ValueError(f"unexpected artifact path resolution: {rel}")
        if stat.S_ISDIR(item.st_mode):
            continue
        name = path.name.lower()
        if name in PRIVATE_NAMES or path.suffix.lower() in PRIVATE_SUFFIXES or ".perf.data" in name:
            raise ValueError(f"private artifact filename: {rel}")
        if item.st_size > MAX_FILE_BYTES:
            raise ValueError(f"artifact file exceeds audit bound: {rel}")
        total += item.st_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("total evidence exceeds audit bound")
        # Read a bounded file in full so credentials crossing chunk boundaries
        # cannot escape the pattern check.
        raw = path.read_bytes()
        if len(raw) != item.st_size:
            raise ValueError(f"artifact changed during privacy check: {rel}")
        if SECRETS.search(raw):
            raise ValueError(f"private key or credential pattern in artifact: {rel}")
        checked += 1
    if checked == 0:
        raise ValueError("no public evidence files to publish")
    return {"schema": "hepta.openvpn-hia.publication-privacy.v1",
            "safe_to_upload": True, "files_scanned": checked, "bytes_scanned": total,
            "scope": "privacy and bounded artifact type check; not a target runtime pass"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", required=True, type=Path)
    parser.add_argument("--marker", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.marker.exists() or args.marker.is_symlink():
        print(json.dumps({"safe_to_upload": False, "reason": "publication marker must not pre-exist"}, sort_keys=True))
        return 1
    try:
        outcome = inspect(args.public)
        # A new marker outside the uploaded evidence tree is only written after
        # every file has passed. Never use it to assert the tunnel succeeded.
        marker = args.marker.absolute()
        if marker == args.public.resolve() or marker.is_relative_to(args.public.resolve()):
            raise ValueError("publication marker must be outside public evidence")
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(outcome, stream, sort_keys=True)
            stream.write("\n")
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"safe_to_upload": False, "reason": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
