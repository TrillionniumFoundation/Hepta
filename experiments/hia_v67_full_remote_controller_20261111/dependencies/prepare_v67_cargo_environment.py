#!/usr/bin/env python3
"""New v67 private Cargo environment adapter for the unchanged 972d preparer.

Usage: python -B prepare_v67_cargo_environment.py EXACT_ORIGINAL_PREPARER.py
       --source ... --output NEW --temporary-root NEW --prereq-root ...
       --python ... --candidate-environment desktop-v67-input-hints.json

This is a NEW revision, not recovery of the old c127 adapter. The original
Preparation.run/save and original launcher are retained verbatim. Only the
private CARGO_HOME execution setting is added. All historical pins are inputs
to fresh observations; READY requires the original current prerequisites.
Cargo may write locks/index metadata in its private home. No cache-tree
immutability, cached dependency completeness, qualification or delivery PASS
is claimed by checking fixed crate archives. Build outputs remain fresh.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

CONFIG = {'original_preparer_sha256': '972dffc85f53093aa8d06f53a1a2154dc1731e7ad93c0ca39c93f0b03a91ffbc', 'hints_sha256': '90d86e3401194bbc42a25466f4caf3bfcb67d6e4a6ade2afc03e769b9bd9f4a6', 'hints': {'CLANG': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/clang', 'CLANGXX': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/clang++', 'HEPTA_DYNAMIC_POLICY_BINARY': '/home/qian-qi/hia-e26e-v64-prerequisites/targets/dynamic/release/hia-ndu-bridge', 'HEPTA_DYNAMIC_POLICY_MANIFEST': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/core-controls-ndu-dynamic-prerequisite-01/build-receipt.json', 'HEPTA_FINITE_NDU_IDENTITY': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/ndu-finite-build-01/identity.json', 'HEPTA_FINITE_NDU_UPSTREAM': '/home/qian-qi/hia-e26e-v64-prerequisites/finite-ndu-upstream', 'HEPTA_LLD': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/ld.lld', 'HEPTA_LLVM_READOBJ': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/llvm-readobj', 'HEPTA_NDU_BRIDGE': '/home/qian-qi/hia-e26e-v64-prerequisites/targets/ranking/debug/hia-ndu-bridge', 'HEPTA_NDU_BUILD': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/core-controls-ndu-original-prerequisite-01', 'HEPTA_NDU_STREAM_IDENTITY': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/ndu-stream-build-01/identity.json', 'HEPTA_NDU_STREAM_UPSTREAM': '/home/qian-qi/hia-e26e-v64-prerequisites/stream-ndu-upstream', 'HEPTA_NDU_UPSTREAM': '/home/qian-qi/hia-e26e-v64-prerequisites/ndu-upstream', 'HEPTA_PROFDATA': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/llvm-profdata', 'HEPTA_QEMU_AARCH64': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/qemu-8.2.2-complete/qemu-aarch64-static', 'HEPTA_QEMU_RISCV64': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/qemu-8.2.2-complete/qemu-riscv64-static', 'HEPTA_QEMU_X86_64': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/qemu-8.2.2-complete/qemu-x86_64-static', 'HEPTA_RAW_MODEL_BRIDGE': '/home/qian-qi/hia-e26e-v64-prerequisites/targets/raw/release/hia-ndu-bridge', 'HEPTA_RAW_MODEL_BUILD': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/core-retained-ndu-raw-model-prerequisite-01/build-receipt.json', 'HEPTA_RECURSIVE_NDU_IDENTITY': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/ndu-recursive-build-01/identity.json', 'HEPTA_RECURSIVE_NDU_UPSTREAM': '/home/qian-qi/hia-e26e-v64-prerequisites/recursive-ndu-upstream', 'HIA_KERNEL_OBJDUMP': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/llvm-objdump', 'LEAN': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/lean-4.19.0/bin/lean', 'PYTHON': '/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python', 'RUSTC': '/home/qian-qi/hia-e26e-v64-prerequisites/toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin/rustc'}, 'cargo_home': '/home/qian-qi/hia-e26e-v64-prerequisites/cargo-home', 'manifest': {'archives': 55, 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/cargo-cache-archives.json', 'sha256': '83efd48f22248a3381d084fff3551f4475c4d0c2e589acc737d3d03007a50c33'}, 'python': {'origin': 'separate original formal CPython tool completion READY; historical fixed-tools report interpreter is explicitly not reused', 'path': '/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python', 'sha256': 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'}, 'fixed_tools': [{'name': 'clang', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/clang', 'sha256': '92a0ff2751ad344b94c7d30f53c56a71a5edfb6f867e7269a573e0e3f663786a', 'check': 'clang'}, {'name': 'clang++', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/clang++', 'sha256': '92a0ff2751ad344b94c7d30f53c56a71a5edfb6f867e7269a573e0e3f663786a', 'check': 'clangxx'}, {'name': 'ld.lld', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/ld.lld', 'sha256': '4213c4392590fad303a8c36dc4819e46a3d344ee656ee6431204410f36a79d3d', 'check': 'lld'}, {'name': 'llvm-objdump', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/llvm-objdump', 'sha256': '6f37235acc7b6e93ca5f53f95bb1c11ef0daf3ee7ba323e1837d99201bcfe4a3', 'check': 'objdump'}, {'name': 'llvm-profdata', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/llvm-profdata', 'sha256': '2a2301fe80a8640d46b710424af810ae9b347078106c8357f7deebe5a6f3d696', 'check': 'profdata'}, {'name': 'llvm-readobj', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/llvm-readobj', 'sha256': '0dd030686b979a471be97b17b342f6ca51f6a610f8ac5d48bc6674a7da0e669e', 'check': 'readobj'}, {'name': 'lean', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/lean-4.19.0/bin/lean', 'sha256': '92c3d35b5bfaa5e0fea413a775d504cf46cd95e1345df61c2274f76779e7e023', 'check': 'lean'}, {'name': 'rustc', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin/rustc', 'sha256': 'e6abf55ab1859e7c990be77fd593f51661ea99fb2fde626ae9f4108aaa34e7fa', 'check': 'rustc'}, {'name': 'qemu-x86_64-static', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/qemu-8.2.2-complete/qemu-x86_64-static', 'sha256': '90181b5552cd1a0b60d8edcc9f1cf8e38647579ef697d3155e2b6150e8fbcee0', 'check': 'qemu_x86_64'}, {'name': 'qemu-riscv64-static', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/qemu-8.2.2-complete/qemu-riscv64-static', 'sha256': 'be89e201dc6112ef101617ab575c95119ad123f80ca2b51b6c36ef218ac9df65', 'check': 'qemu_riscv64'}, {'name': 'qemu-aarch64-static', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/verification-tools/qemu-8.2.2-complete/qemu-aarch64-static', 'sha256': 'e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e', 'check': 'qemu_aarch64'}, {'name': 'cargo', 'origin_report_sha256': '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin/cargo', 'sha256': '51de284e8bb0d03dcee595a0fb1cb3a952fe9e7e4b953a8b1467b7f71725b561', 'check': 'cargo'}], 'fixture_receipts': [{'origin_report_sha256': '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/core-controls-ndu-dynamic-prerequisite-01/build-receipt.json', 'profile': 'dynamic', 'sha256': '20ed7632c6b2b43e02a9b8aaa205c07d4aae93570c62540410202b9c21525c00'}, {'origin_report_sha256': '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/ndu-finite-build-01/identity.json', 'profile': 'finite', 'sha256': '05e3884762024b5c4822cbcb9aba05cd533149209882a24b8a8413896c308fe0'}, {'origin_report_sha256': '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/core-controls-ndu-original-prerequisite-01/build-receipt.json', 'profile': 'ranking', 'sha256': '348d6982eba62474d194e11d99e15800c4b123065be74cd5e5bfbf695f565d42'}, {'origin_report_sha256': '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/core-retained-ndu-raw-model-prerequisite-01/build-receipt.json', 'profile': 'raw', 'sha256': '773497a7b037403c42d18b887a61dbf4e0ca6194982391bd972ebaf7f34057c4'}, {'origin_report_sha256': '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/ndu-recursive-build-01/identity.json', 'profile': 'recursive', 'sha256': '750c553f273cd6bbd3c565423c2f0b19f97d0896c099e9d159abb8b1d4afee8c'}, {'origin_report_sha256': '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406', 'path': '/home/qian-qi/hia-e26e-v64-prerequisites/evidence/ndu-stream-build-01/identity.json', 'profile': 'stream', 'sha256': '7a25bfaf41244dc32291bd7fb547da85c5634b09b7035d7e420e1cac8736835f'}]}


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _owned_archive(path, expected, size=None):
    """Read one explicitly named owned regular archive, never follow links."""
    path = Path(path)
    cache = Path(CONFIG["cargo_home"]) / "registry/cache"
    if (not path.is_absolute() or not path.is_relative_to(cache)
            or path.suffix != ".crate" or path.resolve(strict=True) != path):
        raise ValueError("crate path must be a real absolute file inside private registry/cache")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("crate path has a symlink ancestor")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_size > 1 << 30):
            raise ValueError("crate archive must be owned, single-link and bounded")
        digest = sha256()
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or _identity(path.lstat()) != _identity(after):
            raise ValueError("crate identity changed during observation")
        if digest.hexdigest() != expected or (size is not None and before.st_size != size):
            raise ValueError("crate archive differs from its pinned manifest")
        return {"path": str(path), "sha256": digest.hexdigest(), "bytes": before.st_size,
                "device": before.st_dev, "inode": before.st_ino, "mode": before.st_mode,
                "uid": before.st_uid, "nlink": before.st_nlink}
    finally:
        os.close(fd)


def _archive_records(value):
    """Read the exact observed 83efd48f manifest grammar, no schema guesses."""
    if (type(value) is not dict or set(value) != {
            "archives", "offline_full_regression_not_yet_executed", "path", "schema"}
            or value["schema"] != "hia.private-cargo-cache-observation.v1"
            or value["path"] != CONFIG["cargo_home"]
            or value["offline_full_regression_not_yet_executed"] is not True
            or type(value["archives"]) is not dict
            or len(value["archives"]) != CONFIG["manifest"]["archives"]):
        raise ValueError("exact original manifest must enumerate all 55 archive records")
    result = []
    for path, digest in value["archives"].items():
        if (type(path) is not str or type(digest) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid original archive path/digest record")
        result.append((path, digest, None))
    return result


def adapted_class(original):
    class V67Preparation(original.Preparation):
        def __init__(self, args):
            super().__init__(args)
            self.env["CARGO_HOME"] = CONFIG["cargo_home"]
            self.tool_variables.add("CARGO_HOME")
            self.report["v67_adapter"] = {
                "revision": "new-private-cargo-v67-r1",
                "original_adapter_c127_recovered": False,
                "original_preparer_sha256": CONFIG["original_preparer_sha256"],
                "cargo_home": CONFIG["cargo_home"],
                "cache_metadata_may_change": True,
                "cache_tree_immutability_claimed": False,
                "offline_build_completeness_claimed": False,
                "original_run_and_save_unchanged": True,
                "archive_manifest_structure_observed_before_freeze": True,
                "original_manifest_read_payload_sha256": "1fa9aee4a34186db6676e149573ba7afed83671f9fb25972d417161a097a806c",
            }

        def pinned_inputs(self):
            if self.base != Path(CONFIG["cargo_home"]).parent:
                raise ValueError("private prerequisite root differs")
            if not self.args.candidate_environment:
                raise ValueError("explicit whitelist hints are required")
            hint = self.info(self.args.candidate_environment, bind=True)
            if hint["sha256"] != CONFIG["hints_sha256"] or self.hints != CONFIG["hints"]:
                raise ValueError("explicit whitelist hint bytes/settings differ")
            if str(self.args.python) != CONFIG["python"]["path"]:
                raise ValueError("formal sealed-memfd Python path differs")
            tool_rows = []
            for pin in [CONFIG["python"], *CONFIG["fixed_tools"]]:
                got = self.info(pin["path"], executable=True, bind=True)
                if got["sha256"] != pin["sha256"]:
                    raise ValueError("fixed executable changed: " + pin["path"])
                tool_rows.append(got)
            receipts = []
            for pin in CONFIG["fixture_receipts"]:
                got = self.info(pin["path"], bind=True)
                if got["sha256"] != pin["sha256"]:
                    raise ValueError("fixture receipt changed: " + pin["path"])
                receipts.append(dict(got, profile=pin["profile"]))
            self.report["v67_adapter"]["current_fixed_inputs"] = {
                "executables": tool_rows, "fixture_receipts": receipts, "hints": hint}
            home = Path(CONFIG["cargo_home"])
            if home.resolve(strict=True) != home or any(p.is_symlink() for p in (home, *home.parents)):
                raise ValueError("private CARGO_HOME has a symlink ancestor")
            identity = home.stat()
            if (not stat.S_ISDIR(identity.st_mode) or identity.st_uid != os.getuid()
                    or stat.S_IMODE(identity.st_mode) & 0o022):
                raise ValueError("private CARGO_HOME must be owned and not group/other writable")
            manifest_path = Path(CONFIG["manifest"]["path"])
            if (manifest_path.resolve(strict=True) != manifest_path
                    or any(p.is_symlink() for p in (manifest_path, *manifest_path.parents))):
                raise ValueError("original archive manifest path is not a real path")
            identity = manifest_path.lstat()
            if (not stat.S_ISREG(identity.st_mode) or identity.st_uid != os.getuid()
                    or identity.st_nlink != 1 or identity.st_size > 4 << 20):
                raise ValueError("original archive manifest must be owned, single-link and bounded")
            manifest = self.info(CONFIG["manifest"]["path"], bind=True)
            raw = Path(CONFIG["manifest"]["path"]).read_bytes()
            if (len(raw) > 4 << 20 or sha256(raw).hexdigest() != CONFIG["manifest"]["sha256"]
                    or manifest["sha256"] != CONFIG["manifest"]["sha256"]):
                raise ValueError("original archive manifest bytes differ")
            archives = []
            for path, digest, size in _archive_records(json.loads(raw)):
                row = _owned_archive(path, digest, size)
                self.bindings[path] = digest
                archives.append(row)
            self.report["v67_adapter"]["current_crate_archives"] = {
                "manifest": manifest, "count": len(archives), "archives": archives,
                "scope": "fixed archives only; locks, indexes and all other cache metadata are not asserted unchanged"}

        def selected_inputs(self):
            if self.python != CONFIG["python"]["path"]:
                raise ValueError("original preparer selected a different Python")
            for pin in CONFIG["fixed_tools"]:
                got = self.report["checks"].get(pin["check"], {})
                if (got.get("available") is not True or got.get("path") != pin["path"]
                        or got.get("sha256") != pin["sha256"]):
                    raise ValueError("original preparer selected a different fixed tool: " + pin["name"])
            for pin in CONFIG["fixture_receipts"]:
                got = self.report["checks"].get("ndu_" + pin["profile"], {})
                if (got.get("available") is not True or got.get("path") != pin["path"]
                        or got.get("sha256") != pin["sha256"]):
                    raise ValueError("original current fixture gate did not admit the fixed receipt: " + pin["profile"])
            if (self.env.get("CARGO_HOME") != CONFIG["cargo_home"]
                    or self.env.get("CARGO_NET_OFFLINE") != "true"
                    or self.env.get("CARGO_TARGET_DIR") != str(self.out / "cargo-target")):
                raise ValueError("private offline Cargo/fresh build output settings differ")

        def run(self):
            try:
                self.pinned_inputs()
            except Exception as error:
                self.report["v67_adapter"]["input_error"] = repr(error)
                self.missing("v67_fixed_inputs", "Current exact prerequisite inputs not admitted; original probes were not entered.")
                return
            super().run()
            try:
                self.selected_inputs()
            except Exception as error:
                self.report["v67_adapter"]["selection_error"] = repr(error)
                self.missing("v67_selected_inputs", "Original gates did not select all exact current inputs.")
    return V67Preparation


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: prepare_v67_cargo_environment.py EXACT_972D_PREPARER.py [original arguments]")
    path = Path(sys.argv[1]).resolve(strict=True)
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != CONFIG["original_preparer_sha256"]:
        raise SystemExit("original prerequisite preparer byte identity differs")
    module = types.ModuleType("hia_v67_exact_original_preparer")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    module.Preparation = adapted_class(module)
    sys.argv = [str(path), *sys.argv[2:]]
    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
