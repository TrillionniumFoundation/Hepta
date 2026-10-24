#!/usr/bin/env python3
"""Install optional fixed Lean/QEMU verification tools from official archives.

Linux x86-64 only. The compiler itself does not depend on these tools.
Lean archive streaming needs the optional Python zstandard package.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


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
        with urllib.request.urlopen(metadata["url"], timeout=60) as response:
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
    with tempfile.TemporaryDirectory(prefix=".qemu-install-", dir=parent) as temp:
        temp = Path(temp)
        package = temp / "qemu.deb"
        with urllib.request.urlopen(metadata["source"], timeout=60) as response, package.open("wb") as out:
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
