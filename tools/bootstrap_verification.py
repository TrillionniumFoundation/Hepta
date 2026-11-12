#!/usr/bin/env python3
"""Install optional fixed Lean/QEMU verification tools from official archives.

Linux x86-64 only. The compiler itself does not depend on these tools.
Lean archive streaming needs the optional Python zstandard package.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD_BACKOFF_SECONDS = (1, 2, 4)
TRANSIENT_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})


class _TransientDownload(Exception):
    def __init__(self, cause):
        self.cause = cause
        super().__init__(str(cause))


def _transient_network_error(error):
    if isinstance(error, urllib.error.HTTPError):
        return error.code in TRANSIENT_HTTP_STATUS
    if isinstance(error, urllib.error.URLError):
        error = error.reason
    if isinstance(error, ssl.SSLError):
        return False
    return (isinstance(error, (TimeoutError, ConnectionResetError, ConnectionAbortedError))
            or isinstance(error, socket.gaierror) and error.errno == socket.EAI_AGAIN)


def _network_failure(error):
    # Only failures raised by urlopen/read enter this path. Filesystem,
    # extraction and digest errors must never acquire network retry semantics.
    if isinstance(error, urllib.error.HTTPError):
        error.close()
    if _transient_network_error(error):
        raise _TransientDownload(error) from error
    raise error


class _DownloadStream:
    def __init__(self, response):
        self.response = response

    def read(self, size=-1):
        try:
            return self.response.read(size)
        except Exception as error:
            _network_failure(error)


@contextmanager
def _download_response(url):
    try:
        response = urllib.request.urlopen(url, timeout=60)
    except Exception as error:
        _network_failure(error)
    with response:
        yield _DownloadStream(response)


def _retry_download(component, action):
    maximum = len(DOWNLOAD_BACKOFF_SECONDS) + 1
    for attempt in range(1, maximum + 1):
        print(json.dumps({"component": component, "event": "download_attempt",
                          "attempt": attempt, "maximum_attempts": maximum}), file=sys.stderr, flush=True)
        try:
            return action()
        except _TransientDownload as error:
            delay = DOWNLOAD_BACKOFF_SECONDS[attempt - 1] if attempt < maximum else None
            cause = error.cause
            print(json.dumps({"component": component, "event": "download_transient_failure",
                "attempt": attempt, "maximum_attempts": maximum, "error_type": type(cause).__name__,
                "http_status": cause.code if isinstance(cause, urllib.error.HTTPError) else None,
                "retry_after_seconds": delay, "exhausted": delay is None}), file=sys.stderr, flush=True)
            if delay is None:
                raise cause from error
            time.sleep(delay)


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def install_lean(parent):
    metadata = json.loads((ROOT / "formal/toolchain-lock.json").read_text())
    dependencies = (ROOT / "formal/proof-dependencies.txt").read_text().splitlines()
    selected = {"bin/lean", "lib/lean/libInit_shared.so", "lib/lean/libleanshared.so", "lib/lean/libleanshared_1.so"}
    selected |= {"lib/lean/" + path for path in dependencies}
    target = parent / "lean-4.19.0"
    if target.exists():
        if all((target / p).is_file() for p in selected) and sha(target / "bin/lean") == metadata["lean_binary_sha256"]:
            return str(target / "bin/lean")
        raise RuntimeError("Existing Lean directory is incomplete or differs; choose a fresh --directory")
    try:
        import zstandard
    except ImportError:
        raise RuntimeError("The optional Lean installer requires Python zstandard; the Hepta compiler does not") from None
    return _retry_download("lean", lambda: _install_lean_attempt(parent, target, metadata, selected, zstandard))


def _install_lean_attempt(parent, target, metadata, selected, zstandard):
    # A retry uses a fresh digest, selected-component inventory and staging
    # directory. Never concatenate a new response onto a partial archive.
    digest = hashlib.sha256()
    class Reader:
        def __init__(self, source): self.source = source
        def read(self, n=-1):
            data = self.source.read(n)
            digest.update(data)
            return data
    with tempfile.TemporaryDirectory(prefix=".lean-install-", dir=parent) as temp:
        staged = Path(temp) / "toolchain"
        staged.mkdir()
        found = set()
        with _download_response(metadata["url"]) as response:
            with zstandard.ZstdDecompressor().stream_reader(Reader(response)) as decoded:
                with tarfile.open(fileobj=decoded, mode="r|") as archive:
                    for member in archive:
                        parts = PurePosixPath(member.name).parts[1:]
                        rel = PurePosixPath(*parts).as_posix()
                        if not member.isfile() or rel not in selected or ".." in parts:
                            continue
                        destination = staged.joinpath(*parts)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as source, destination.open("wb") as out:
                            shutil.copyfileobj(source, out)
                        destination.chmod(0o755 if rel == "bin/lean" else 0o644)
                        found.add(rel)
                while decoded.read(1024 * 1024):
                    pass
        if digest.hexdigest() != metadata["archive_sha256"] or found != selected:
            raise RuntimeError("Lean archive identity or selected components did not match")
        if sha(staged / "bin/lean") != metadata["lean_binary_sha256"]:
            raise RuntimeError("Lean executable identity mismatch")
        os.replace(staged, target)
    return str(target / "bin/lean")


def install_qemu(parent):
    metadata = json.loads((ROOT / "formal/qemu-toolchain-lock.json").read_text())
    target = parent / "qemu-8.2.2"
    binary = target / "qemu-aarch64-static"
    if binary.is_file() and sha(binary) == metadata["binary_sha256"]:
        return str(binary)
    if target.exists():
        raise RuntimeError("Existing QEMU directory differs; choose a fresh --directory")
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("The QEMU installer requires dpkg-deb")
    return _retry_download("qemu", lambda: _install_qemu_attempt(parent, target, binary, metadata))


def _install_qemu_attempt(parent, target, binary, metadata):
    with tempfile.TemporaryDirectory(prefix=".qemu-install-", dir=parent) as temp:
        temp = Path(temp)
        package = temp / "qemu.deb"
        with _download_response(metadata["source"]) as response, package.open("wb") as out:
            shutil.copyfileobj(response, out)
        if sha(package) != metadata["package_sha256"]:
            raise RuntimeError("Ubuntu QEMU package checksum mismatch")
        staged = temp / "toolchain"
        staged.mkdir()
        proc = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(package)], stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
                for member in archive:
                    if member.isfile() and PurePosixPath(member.name).name == binary.name:
                        with archive.extractfile(member) as source, (staged / binary.name).open("wb") as out:
                            shutil.copyfileobj(source, out)
            if proc.wait() != 0 or sha(staged / binary.name) != metadata["binary_sha256"]:
                raise RuntimeError("QEMU extracted executable did not match")
        finally:
            proc.stdout.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        (staged / binary.name).chmod(0o755)
        os.replace(staged, target)
    return str(binary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=ROOT.parent / "toolchains")
    parser.add_argument("--lean-only", action="store_true")
    parser.add_argument("--qemu-only", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        parser.error("This fixed verification toolchain profile is Linux x86-64 only")
    if args.lean_only and args.qemu_only:
        parser.error("Choose at most one component-only option")
    args.directory.mkdir(parents=True, exist_ok=True)
    installed = {}
    if not args.qemu_only:
        installed["lean"] = install_lean(args.directory.resolve())
    if not args.lean_only:
        installed["qemu"] = install_qemu(args.directory.resolve())
    print(json.dumps(installed, indent=2))


if __name__ == "__main__":
    main()
