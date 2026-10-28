#!/usr/bin/env python3
"""Install verified Rust components into a task-specific prefix, without rustup."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
HOST = "x86_64-unknown-linux-gnu"


def verify_installed_package(package_root: Path, prefix: Path) -> dict:
    """Compare installed component bytes with the checksum-verified archive.

    Rust's install.sh can exit zero after a failed cp (observed on ENOSPC).
    Its exit code alone must never produce an installed-toolchain receipt.
    This verifies copied payloads, not arbitrary toolchain authenticity or
    subsequent filesystem changes.
    """
    package_root, prefix = Path(package_root).resolve(), Path(prefix).resolve()
    components = (package_root / "components").read_text().splitlines()
    if not components or len(set(components)) != len(components):
        raise RuntimeError("Missing or duplicate Rust component inventory")
    inventory = {}

    def relative(name):
        path = PurePosixPath(name)
        if not name or path.is_absolute() or any(x in {".", ".."} for x in name.split("/")):
            raise RuntimeError("Invalid Rust component path: " + name)
        return Path(*path.parts)

    def verify_file(source, rel):
        destination = prefix / rel
        if not destination.resolve(strict=False).is_relative_to(prefix):
            raise RuntimeError("Installed Rust payload escapes prefix: " + str(rel))
        if source.is_symlink():
            if not destination.is_symlink() or os.readlink(source) != os.readlink(destination):
                raise RuntimeError("Installed Rust symlink differs: " + str(rel))
            inventory[str(rel)] = {"kind": "symlink", "target": os.readlink(source)}
        elif source.is_file():
            if destination.is_symlink() or not destination.is_file():
                raise RuntimeError("Missing installed Rust file: " + str(rel))
            with source.open("rb") as stream:
                expected = hashlib.file_digest(stream, "sha256").hexdigest()
            with destination.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if source.stat().st_size != destination.stat().st_size or actual != expected:
                raise RuntimeError("Incomplete or modified installed Rust file: " + str(rel))
            if (source.stat().st_mode & 0o111) and not (destination.stat().st_mode & 0o111):
                raise RuntimeError("Installed Rust executable lost execute permissions: " + str(rel))
            inventory[str(rel)] = {"kind": "file", "bytes": source.stat().st_size, "sha256": actual}
        else:
            raise RuntimeError("Unsupported Rust payload file: " + str(rel))

    for component in components:
        rel_component = relative(component)
        if len(rel_component.parts) != 1:
            raise RuntimeError("Invalid component name")
        folder = package_root / rel_component
        entries = (folder / "manifest.in").read_text().splitlines()
        if not entries:
            raise RuntimeError("Empty Rust component manifest")
        for entry in entries:
            kind, separator, name = entry.partition(":")
            if not separator or kind not in {"file", "dir"}:
                raise RuntimeError("Unsupported Rust component manifest entry")
            rel = relative(name)
            source = folder / rel
            if kind == "file":
                verify_file(source, rel)
            else:
                if source.is_symlink() or not source.is_dir():
                    raise RuntimeError("Missing source component directory: " + name)
                destination = prefix / rel
                if destination.is_symlink() or not destination.is_dir():
                    raise RuntimeError("Missing installed component directory: " + name)
                for child in sorted(source.rglob("*")):
                    if child.is_symlink() or child.is_file():
                        verify_file(child, child.relative_to(folder))
    if not inventory:
        raise RuntimeError("Rust package installed no verified payloads")
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return {"components": components, "verified_payloads": len(inventory),
            "installed_payload_inventory_sha256": hashlib.sha256(encoded).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, default=ROOT.parent / "toolchains/rust-1.90.0")
    parser.add_argument("--targets", nargs="*", default=["aarch64-unknown-linux-gnu", "thumbv7em-none-eabi", "x86_64-pc-windows-msvc"])
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        parser.error("This verified installer bootstraps a Linux x86-64 host; use rustup 1.90.0 for other hosts")
    locked = json.loads((ROOT / "toolchain-lock.json").read_text())
    wanted = {"cargo-1.90.0-" + HOST, "rustc-1.90.0-" + HOST,
              "rust-std-1.90.0-" + HOST}
    wanted.update("rust-std-1.90.0-" + t for t in args.targets)
    selected = [r for r in locked if r["package"] in wanted]
    if {r["package"] for r in selected} != wanted:
        parser.error("Requested component is not present in the checksum lock")
    prefix = args.prefix.resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    verified = []
    for item in selected:
        with tempfile.TemporaryDirectory(prefix=".hepta-toolchain-", dir=prefix.parent) as td:
            td = Path(td)
            archive = td / (item["package"] + ".tar.xz")
            print("Downloading", item["package"], flush=True)
            with urllib.request.urlopen(item["url"], timeout=60) as src, archive.open("wb") as dst:
                while block := src.read(1024 * 1024):
                    dst.write(block)
            digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
            if digest != item["sha256"]:
                raise RuntimeError("Checksum mismatch: " + item["package"])
            with tarfile.open(archive) as package:
                package.extractall(td, filter="data")
            installer = td / item["package"] / "install.sh"
            subprocess.run(["sh", str(installer), "--prefix=" + str(prefix), "--disable-ldconfig"], check=True)
            receipt = verify_installed_package(td / item["package"], prefix)
            verified.append({"package": item["package"], **receipt})
    print(json.dumps({"rustc": str(prefix / "bin/rustc"), "components": selected,
                      "installation_verification": verified}, indent=2))


if __name__ == "__main__":
    main()
