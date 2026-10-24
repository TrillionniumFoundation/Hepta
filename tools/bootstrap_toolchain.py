#!/usr/bin/env python3
"""Install verified Rust components into a task-specific prefix, without rustup."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
HOST = "x86_64-unknown-linux-gnu"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, default=ROOT.parent / "toolchains/rust-1.90.0")
    parser.add_argument("--targets", nargs="*", default=["aarch64-unknown-linux-gnu", "thumbv7em-none-eabi", "x86_64-pc-windows-msvc"])
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        parser.error("This verified installer bootstraps a Linux x86-64 host; use rustup 1.90.0 for other hosts")
    locked = json.loads((ROOT / "toolchain-lock.json").read_text())
    wanted = {"rustc-1.90.0-" + HOST, "rust-std-1.90.0-" + HOST}
    wanted.update("rust-std-1.90.0-" + t for t in args.targets)
    selected = [r for r in locked if r["package"] in wanted]
    if {r["package"] for r in selected} != wanted:
        parser.error("Requested component is not present in the checksum lock")
    prefix = args.prefix.resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
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
    print(json.dumps({"rustc": str(prefix / "bin/rustc"), "components": selected}, indent=2))


if __name__ == "__main__":
    main()
