#!/usr/bin/env python3
"""Fresh v87 prerequisite supply; never a product or qualification PASS.

The caller must supervise this complete program with the unchanged 10800-second
guardian.  Its 3600-second supply allowance is inside that deadline.  Every
external supply command uses the pinned original workflow_process supervisor.
That supervisor proves only termination of its started POSIX process group;
the enclosing guardian establishes the complete workflow ECHILD condition.
The two APT commands additionally use the unchanged external guardian in a
root worker, within their original allowances, before any cache handoff.

All outputs are new.  Original archives, command streams, unsuccessful partial
downloads, actual source inventories and fresh builder receipts are retained.
The subsequent original 972d preparer must still perform every original probe.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import sys
import tarfile
import time
import tomllib
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile


SCHEMA = "hia.v87.full-prerequisite-supply.v1"
WORKFLOW_REL = "experiments/hia_native_successor_runner_20261111/workflow_process.py"
WORKFLOW_SHA = "f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80"
CARGO_ORIGINAL_SHA = "83efd48f22248a3381d084fff3551f4475c4d0c2e589acc737d3d03007a50c33"
HOST = "x86_64-unknown-linux-gnu"
UPSTREAM_URL = "https://github.com/TrillionniumFoundation/hepta-private-ci.git"
LLVM_KEY_URL = "https://apt.llvm.org/llvm-snapshot.gpg.key"
LLVM_FINGERPRINT = "6084F3CF814B57C1CF12EFD515CF4D18AF4F7421"
LLVM_KEY_DEST = "/usr/share/keyrings/hia-v87-llvm.asc"
LLVM_REPO_DEST = "/etc/apt/sources.list.d/hia-v87-llvm20.list"
LLVM_REPO = ("deb [arch=amd64 signed-by=" + LLVM_KEY_DEST + "] "
             "https://apt.llvm.org/noble/ llvm-toolchain-noble-20 main\n")
APT_PACKAGES = ("binutils", "gcc", "clang-20", "libclang-rt-20-dev", "strace",
                "llvm-20", "lld-20")
BOOST_NAME = "libboost1.83-dev_1.83.0-5ubuntu5_amd64.deb"
BOOST_URL = "https://archive.ubuntu.com/ubuntu/pool/universe/b/boost1.83/" + BOOST_NAME
BOOST_SHA = "c17abc5a40a074c3d959655191ebec1561fa25f14f4948f6788be49417d4b234"
BOOST_HEADER_SHA = "a547ee7eddf1b96695027922345b471feba8bcba79a8572399d282247c02e4ab"
QEMU_HASHES = {
    "qemu-aarch64-static": "e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e",
    "qemu-x86_64-static": "90181b5552cd1a0b60d8edcc9f1cf8e38647579ef697d3155e2b6150e8fbcee0",
    "qemu-riscv64-static": "be89e201dc6112ef101617ab575c95119ad123f80ca2b51b6c36ef218ac9df65",
}
UPSTREAM_COMMITS = {
    "ranking": "d3c2d760eca5065fc966820379c35c6e8d56e855",
    "raw_dynamic": "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d",
    "recursive": "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b",
    "finite": "4b6391e116949af0c7e59776baead67271856bdb",
    "stream": "c4a1bbed3a39beba43a6abf1a18b6f75c5725c21",
}
TOOL_PATHS = {
    "clang": "/usr/bin/clang-20", "clangxx": "/usr/bin/clang++-20",
    "lld": "/usr/bin/ld.lld-20", "objdump": "/usr/bin/llvm-objdump-20",
    "profdata": "/usr/bin/llvm-profdata-20", "readobj": "/usr/bin/llvm-readobj-20",
    "gcc": "/usr/bin/gcc", "strace": "/usr/bin/strace",
}
TOOL_HINTS = {
    "clang": ("CLANG", "HEPTA_CLANG", "HEPTA_NATIVE_CLANG", "HEPTA_TEST_CLANG", "HIA_TEST_CLANG20", "HIA_KERNEL_CLANG"),
    "clangxx": ("CLANGXX",), "lld": ("HEPTA_LLD",),
    "objdump": ("HIA_KERNEL_OBJDUMP",), "profdata": ("HEPTA_PROFDATA",),
    "readobj": ("HEPTA_LLVM_READOBJ",), "gcc": ("CC", "HEPTA_STB_GCC"),
    "qemu_aarch64": ("HEPTA_QEMU_AARCH64",), "qemu_x86_64": ("HEPTA_QEMU_X86_64",),
    "qemu_riscv64": ("HEPTA_QEMU_RISCV64",), "rustc": ("RUSTC", "HEPTA_RUSTC", "HIA_TEST_SOURCE_RUSTC"),
    "cargo": (), "lean": ("LEAN",), "strace": (),
}
HTTP_HOSTS = frozenset({"apt.llvm.org", "archive.ubuntu.com", "static.rust-lang.org",
    "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
    "static.crates.io", "pypi.org", "files.pythonhosted.org"})
ZSTD_WHEEL = "zstandard-0.25.0-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def parent_identity(s):
    # Directory timestamps legitimately change while a new sibling is written.
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid]


@contextmanager
def parent_fd(path):
    path = Path(path)
    require(path.is_absolute() and path.name not in ("", ".", "..") and ".." not in path.parts,
            "absolute canonical path required: " + str(path))
    descriptors, links = [], []
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(descriptor)
        for name in path.parent.parts[1:]:
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode), "non-directory parent: " + str(path))
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            require(parent_identity(before) == parent_identity(os.fstat(child)), "parent changed during open")
            links.append((descriptor, name, child, parent_identity(before)))
            descriptors.append(child)
            descriptor = child

        def stable():
            for parent, name, child, expected in links:
                require(parent_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == expected == parent_identity(os.fstat(child)), "parent chain changed")
        stable()
        yield descriptor, path.name, stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def file_record(path, *, limit=None, body=False, owner=None, single=False):
    path = Path(path)
    chunks = [] if body else None
    with parent_fd(path) as (parent, name, stable):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), "regular file required: " + str(path))
        require(limit is None or before.st_size <= limit, "file exceeds bound: " + str(path))
        require(owner is None or before.st_uid == owner, "file owner differs: " + str(path))
        require(not single or before.st_nlink == 1, "independent file required: " + str(path))
        descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        try:
            require(identity(os.fstat(descriptor)) == identity(before), "file changed at open")
            sha, git, count = hashlib.sha256(), hashlib.sha1(), 0
            git.update(b"blob " + str(before.st_size).encode() + b"\0")
            while block := os.read(descriptor, 1 << 20):
                count += len(block)
                require(count <= before.st_size, "file grew while reading")
                sha.update(block)
                git.update(block)
                if chunks is not None:
                    chunks.append(block)
            require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before),
                    "file changed during read")
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    "named file changed during read")
            stable()
        finally:
            os.close(descriptor)
    result = {"path": str(path), "bytes": count, "sha256": sha.hexdigest(),
              "git_blob": git.hexdigest(), "mode": stat.S_IMODE(before.st_mode), "identity": identity(before)}
    return (result, b"".join(chunks)) if body else result


def read_json(path, *, limit=16 << 20):
    record, raw = file_record(path, limit=limit, body=True)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs), record


def mkdir(path, mode=0o700):
    with parent_fd(path) as (parent, name, stable):
        os.mkdir(name, mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            require(os.fstat(descriptor).st_uid == os.getuid(), "new directory owner differs")
            stable()
            os.fsync(parent)
        finally:
            os.close(descriptor)
    return Path(path)


def directories(path, boundary):
    path, boundary = Path(path), Path(boundary)
    require(path.is_relative_to(boundary), "directory outside new output")
    current = boundary
    for name in path.relative_to(boundary).parts:
        current /= name
        try:
            with parent_fd(current) as (parent, leaf, stable):
                s = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(s.st_mode), "existing non-directory")
                stable()
        except FileNotFoundError:
            mkdir(current)


def create(path, raw, mode=0o600):
    with parent_fd(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             mode, dir_fd=parent)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, memoryview(raw)[offset:])
                require(written > 0, "short file write")
                offset += written
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            digest, count = hashlib.sha256(), 0
            while block := os.read(descriptor, 1 << 20):
                digest.update(block)
                count += len(block)
            require(count == len(raw) and digest.hexdigest() == hashlib.sha256(raw).hexdigest(),
                    "new file readback differs")
            stable()
            os.fsync(parent)
        finally:
            os.close(descriptor)
    return file_record(path, owner=os.getuid(), single=True)


def copy_file(source, destination, *, mode=None):
    before = file_record(source)
    with parent_fd(source) as (source_parent, source_name, source_stable):
        source_fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=source_parent)
        try:
            require(identity(os.fstat(source_fd)) == before["identity"], "copy source changed")
            with parent_fd(destination) as (parent, name, stable):
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=parent)
                try:
                    while block := os.read(source_fd, 1 << 20):
                        offset = 0
                        while offset < len(block):
                            written = os.write(target, block[offset:])
                            require(written > 0, "short copy")
                            offset += written
                    os.fchmod(target, before["mode"] if mode is None else mode)
                    os.fsync(target)
                    stable()
                    os.fsync(parent)
                finally:
                    os.close(target)
            require(identity(os.fstat(source_fd)) == before["identity"], "copy source changed after read")
            source_stable()
        finally:
            os.close(source_fd)
    after = file_record(destination, owner=os.getuid(), single=True)
    require((after["bytes"], after["sha256"]) == (before["bytes"], before["sha256"]), "copy bytes differ")
    require(file_record(source) == before, "copy source namespace changed")
    return after


def resolved_record(path):
    """Record a system/toolchain alias explicitly; do not apply data-file link rules to it."""
    path = Path(path).absolute()
    links = []
    for part in [*reversed(path.parents), path]:
        if part == Path("/"):
            continue
        s = part.lstat()
        if stat.S_ISLNK(s.st_mode):
            links.append({"path": str(part), "identity": identity(s), "target": os.readlink(part)})
    target = path.resolve(strict=True)
    record = file_record(target)
    require(record["identity"][3] in (0, os.getuid()) and not record["mode"] & 0o022,
            "mutable or foreign runtime executable: " + str(path) + " " + json.dumps(record))
    require(record["mode"] & 0o111, "tool is not executable: " + str(path))
    require(path.resolve(strict=True) == target, "runtime alias changed")
    for row in links:
        p = Path(row["path"])
        require(identity(p.lstat()) == row["identity"] and os.readlink(p) == row["target"], "runtime link changed")
    return {**record, "invocation_path": str(path), "resolved_path": str(target), "links": links}


def safe_relative(name):
    if name.startswith("./"):
        name = name[2:]
    p = PurePosixPath(name)
    require(name and not p.is_absolute() and all(x not in ("", ".", "..") for x in name.split("/")),
            "unsafe relative archive path")
    return p


def inventory(root, *, ignore_git=False):
    root = Path(root)
    rows = {}
    def walk(directory):
        with os.scandir(directory) as entries:
            names = sorted(e.name for e in entries)
        for name in names:
            if ignore_git and directory == root and name == ".git":
                continue
            path = directory / name
            rel = path.relative_to(root).as_posix()
            s = path.lstat()
            if stat.S_ISDIR(s.st_mode):
                walk(path)
            elif stat.S_ISREG(s.st_mode):
                row = file_record(path)
                rows[rel] = {key: row[key] for key in ("bytes", "sha256", "git_blob", "mode", "identity")}
                rows[rel]["kind"] = "file"
            elif stat.S_ISLNK(s.st_mode):
                target = os.readlink(path)
                raw = os.fsencode(target)
                require(identity(path.lstat()) == identity(s), "link changed during inventory")
                rows[rel] = {"kind": "symlink", "target": target, "mode": stat.S_IMODE(s.st_mode),
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
                    "identity": identity(s)}
            else:
                raise Refusal("special member in immutable input: " + rel)
    walk(root)
    return rows


def check_git_inventory(rows, raw_tree):
    expected = {}
    for item in raw_tree.split(b"\0"):
        if not item:
            continue
        meta, name = item.split(b"\t", 1)
        mode, kind, blob = meta.split()
        name = name.decode("utf-8", errors="strict")
        safe_relative(name)
        require(kind == b"blob" and mode in (b"100644", b"100755", b"120000") and name not in expected,
                "unsupported or duplicate Git leaf")
        expected[name] = (mode.decode(), blob.decode())
    require(set(rows) == set(expected), "physical namespace differs from exact Git leaf set")
    for name, (mode, blob) in expected.items():
        row = rows[name]
        actual_mode = "120000" if row["kind"] == "symlink" else ("100755" if row["mode"] & 0o111 else "100644")
        require(actual_mode == mode and row["git_blob"] == blob, "physical Git leaf differs: " + name)
    return len(expected)


def clean_env(*, network=False):
    allowed = {"HOME", "USER", "LOGNAME", "PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"}
    if network:
        allowed |= {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    for key in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        if env.get(key):
            proxy = urllib.parse.urlsplit(env[key])
            require(proxy.username is None and proxy.password is None and not proxy.query and not proxy.fragment,
                    "credential-bearing proxy cannot enter retained supply requests")
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", PYTHONNOUSERSITE="1",
        LANG="C.UTF-8", LC_ALL="C.UTF-8", GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="",
        GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null", GIT_CONFIG_NOSYSTEM="1",
        GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1", CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
    return env


def checked_module(name, path, expected_sha):
    row = file_record(path)
    require(row["sha256"] == expected_sha, "module input changed: " + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "module loader unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(file_record(path) == row, "module source changed during load")
    return module


def checked_url(url):
    value = urllib.parse.urlsplit(url)
    require(value.scheme == "https" and value.hostname in HTTP_HOSTS and value.port in (None, 443)
            and value.username is None and value.password is None and not value.fragment,
            "unapproved HTTPS download endpoint")
    return value


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        require(req.get_method() == "GET", "unexpected redirected method")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, *, expected_sha=None, expected_size=None, maximum, seconds=240,
             pin_origin="preexecution fixed source or historical raw manifest"):
    checked_url(url)
    destination = Path(destination)
    partial = destination.with_name(destination.name + ".partial")
    deadline = time.monotonic() + seconds
    opener = urllib.request.build_opener(OfficialRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers={"Accept-Encoding": "identity"}), timeout=30) as response:
            require(response.status == 200 and response.headers.get("Content-Encoding", "identity") in ("", "identity"),
                    "download status or encoding differs")
            final_url = response.geturl()
            checked_url(final_url)
            with parent_fd(partial) as (parent, name, stable):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
                try:
                    count, sha = 0, hashlib.sha256()
                    while True:
                        require(time.monotonic() < deadline, "download checked deadline exceeded")
                        block = response.read(min(1 << 20, maximum + 1 - count))
                        if not block:
                            break
                        count += len(block)
                        require(count <= maximum, "download size cap exceeded")
                        sha.update(block)
                        offset = 0
                        while offset < len(block):
                            written = os.write(fd, block[offset:])
                            require(written > 0, "short download write")
                            offset += written
                    require(expected_size is None or count == expected_size, "download size pin differs")
                    require(expected_sha is None or sha.hexdigest() == expected_sha, "download SHA pin differs")
                    os.fsync(fd)
                    stable()
                finally:
                    os.close(fd)
            before = file_record(partial, owner=os.getuid(), single=True)
            require(before["bytes"] == count and before["sha256"] == sha.hexdigest(), "download readback differs")
            with parent_fd(destination) as (parent, name, stable):
                os.link(partial.name, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.unlink(partial.name, dir_fd=parent)
                os.fsync(parent)
                stable()
            result = file_record(destination, owner=os.getuid(), single=True)
            require(result["sha256"] == before["sha256"] and result["bytes"] == before["bytes"], "published download differs")
            result.update(url=url, final_host=urllib.parse.urlsplit(final_url).hostname,
                          final_url_sha256=hashlib.sha256(final_url.encode()).hexdigest(),
                          expected_sha256=expected_sha, sha_origin=(pin_origin if expected_sha else "observed official response"))
            return result
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as error:
        # Redirect locations may contain temporary query credentials.  Keep
        # their hash/host above, never an exception string containing that URL.
        raise Refusal("official download transport failed: " + type(error).__name__
                      + " HTTP=" + str(getattr(error, "code", None))) from None


def extract_tar(archive, destination, *, max_bytes=6 << 30, max_members=120000):
    destination = mkdir(destination)
    seen, pending, total = set(), [], 0
    with tarfile.open(archive, "r:*") as package:
        for member in package:
            name = member.name.rstrip("/")
            if name in ("", ".", "./"):
                continue
            rel = safe_relative(name)
            key = rel.as_posix()
            require(key not in seen and len(seen) < max_members, "duplicate or excessive tar members")
            seen.add(key)
            path = destination.joinpath(*rel.parts)
            directories(path.parent, destination)
            require(not member.mode & 0o6000, "privileged archive member")
            if member.isdir():
                directories(path, destination)
            elif member.isfile():
                total += member.size
                require(total <= max_bytes and 0 <= member.size <= 512 << 20, "expanded tar cap exceeded")
                with package.extractfile(member) as stream:
                    raw = stream.read(member.size + 1)
                require(len(raw) == member.size, "tar member length differs")
                create(path, raw, 0o755 if member.mode & 0o111 else 0o644)
            elif member.issym() or member.islnk():
                pending.append((rel, member.linkname, member.issym()))
            else:
                raise Refusal("special tar member")
    for rel, target, symbolic in pending:
        path = destination.joinpath(*rel.parts)
        if symbolic:
            require(target and not os.path.isabs(target), "absolute archive link")
            resolved = Path(os.path.normpath(path.parent / target))
            require(resolved.is_relative_to(destination), "archive link escapes destination")
            with parent_fd(path) as (parent, name, stable):
                os.symlink(target, name, dir_fd=parent)
                stable()
        else:
            link = destination.joinpath(*safe_relative(target).parts)
            require(link.is_file() and not link.is_symlink(), "unavailable tar hardlink target")
            copy_file(link, path)
    return {"archive": file_record(archive), "root": str(destination), "members": len(seen),
            "expanded_regular_bytes": total, "files": inventory(destination)}


def extract_qemu(data_tar, destination):
    destination = mkdir(destination)
    found = set()
    with tarfile.open(data_tar, "r:") as package:
        for member in package:
            name = member.name.removeprefix("./")
            wanted = "usr/bin/" + PurePosixPath(name).name
            if wanted != name or PurePosixPath(name).name not in QEMU_HASHES:
                continue
            basename = PurePosixPath(name).name
            require(member.isfile() and basename not in found and member.size <= 64 << 20, "QEMU member differs")
            with package.extractfile(member) as stream:
                raw = stream.read(member.size + 1)
            require(len(raw) == member.size and hashlib.sha256(raw).hexdigest() == QEMU_HASHES[basename], "QEMU binary pin differs")
            create(destination / basename, raw, 0o755)
            found.add(basename)
    require(found == set(QEMU_HASHES), "QEMU package omitted a required binary")
    return {"root": str(destination), "files": inventory(destination)}


def extract_lean(archive_path, destination, source, support):
    # zstandard is installed into a fresh supply-only directory; it never
    # modifies or becomes part of the qualification venv.
    sys.path.insert(0, str(support))
    import zstandard
    require(zstandard.__version__ == "0.25.0", "supply decompressor version differs")
    require(Path(zstandard.__file__).resolve().is_relative_to(Path(support)), "foreign decompressor import")
    lock, _ = read_json(Path(source) / "formal/toolchain-lock.json")
    _, dependency_raw = file_record(Path(source) / "formal/proof-dependencies.txt", body=True, limit=1 << 20)
    selected = {"bin/lean", "lib/lean/libInit_shared.so", "lib/lean/libleanshared.so", "lib/lean/libleanshared_1.so"}
    selected |= {"lib/lean/" + line for line in dependency_raw.decode().splitlines()}
    for name in selected:
        safe_relative(name)
    require(file_record(archive_path)["sha256"] == lock["archive_sha256"], "Lean archive pin differs")
    destination = mkdir(destination)
    found = set()
    with open(archive_path, "rb") as compressed:
        with zstandard.ZstdDecompressor().stream_reader(compressed) as decoded:
            with tarfile.open(fileobj=decoded, mode="r|") as package:
                for member in package:
                    parts = PurePosixPath(member.name).parts
                    if len(parts) < 2:
                        continue
                    rel = PurePosixPath(*parts[1:]).as_posix()
                    if rel not in selected:
                        continue
                    require(member.isfile() and rel not in found and member.size <= 512 << 20, "Lean selected member differs")
                    target = destination.joinpath(*safe_relative(rel).parts)
                    directories(target.parent, destination)
                    with package.extractfile(member) as stream:
                        raw = stream.read(member.size + 1)
                    require(len(raw) == member.size, "short Lean member")
                    create(target, raw, 0o755 if rel == "bin/lean" else 0o644)
                    found.add(rel)
            while decoded.read(1 << 20):
                pass
    require(found == selected and file_record(destination / "bin/lean")["sha256"] == lock["lean_binary_sha256"],
            "Lean selected inventory or executable differs")
    return {"root": str(destination), "selected": sorted(selected), "files": inventory(destination)}


def cargo_vendor(original, output):
    original_value, original_record = read_json(original)
    require(original_record["sha256"] == CARGO_ORIGINAL_SHA and len(original_value["archives"]) == 55,
            "fixed original 55-crate manifest differs")
    output = Path(output)
    cache = output / "registry/cache/index.crates.io-1949cf8c6b5b557f"
    vendor = output / "vendor"
    directories(cache, output)
    mkdir(vendor)
    rows, archives = {}, {}
    for old_path, expected in sorted(original_value["archives"].items()):
        filename = Path(old_path).name
        match = re.fullmatch(r"([A-Za-z0-9_-]+)-(\d[^/]*)\.crate", filename)
        require(match is not None and re.fullmatch(r"[0-9a-f]{64}", expected), "malformed fixed crate entry")
        name, version = match.groups()
        archive = cache / filename
        row = download("https://static.crates.io/crates/" + name + "/" + filename,
                       archive, expected_sha=expected, maximum=32 << 20, seconds=90)
        create(output / "downloads" / (filename + ".json"), wire(row))
        unpack = output / "unpacked" / filename.removesuffix(".crate")
        extracted = extract_tar(archive, unpack, max_bytes=256 << 20, max_members=20000)
        package = unpack / filename.removesuffix(".crate")
        require(package.is_dir() and sorted(p.name for p in unpack.iterdir()) == [package.name], "crate root differs")
        _, manifest_raw = file_record(package / "Cargo.toml", body=True, limit=2 << 20)
        manifest = tomllib.loads(manifest_raw.decode())
        require(manifest["package"]["name"] == name and manifest["package"]["version"] == version,
                "crate Cargo.toml identity differs")
        require(all(v["kind"] == "file" for v in inventory(package).values()), "non-file in vendored crate")
        destination = vendor / package.name
        mkdir(destination)
        files = {}
        for relative, member in inventory(package).items():
            require(relative != ".cargo-checksum.json", "unexpected registry checksum member")
            target = destination / relative
            directories(target.parent, destination)
            copied = copy_file(package / relative, target)
            files[relative] = copied["sha256"]
        create(destination / ".cargo-checksum.json", wire({"files": files, "package": expected}), 0o644)
        archives[str(archive)] = expected
        rows[filename] = {"archive": row, "unpacked": extracted, "vendor_files": files}
    config = ('[source.crates-io]\nreplace-with = "hepta-fixed-vendor"\n'
              '[source.hepta-fixed-vendor]\ndirectory = ' + json.dumps(str(vendor)) + '\n[net]\noffline = true\n')
    create(output / "config.toml", config.encode(), 0o600)
    new_manifest = {"schema": "hia.private-cargo-cache-observation.v1", "path": str(output),
                    "archives": archives, "offline_full_regression_not_yet_executed": True}
    create(output / "cargo-cache-archives.json", wire(new_manifest))
    return {"cargo_home": str(output), "manifest": file_record(output / "cargo-cache-archives.json"),
            "archives": 55, "original_manifest": original_record, "crates": rows,
            "immutable_vendor": inventory(vendor), "config": file_record(output / "config.toml"),
            "mutable_cargo_metadata_claimed_unchanged": False}


def return_apt_cache_to_owner(cache, uid, gid, attempts):
    """Only the new, closed APT cache; never a system package or live lock."""
    require(os.getuid() == 0 and type(uid) is int and type(gid) is int and uid >= 0 and gid >= 0,
            "fixed privileged cache ownership operation required")
    cache = Path(cache)
    require(cache.name == "apt-cache" and cache.parent.stat().st_uid == uid,
            "cache is not below the original runner-owned supply root")

    def digest_fd(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            digest.update(block)
        return digest.hexdigest()

    count = 0
    with parent_fd(cache) as (parent, name, stable):
        root_stat = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(root_stat.st_mode), "APT cache root is not a directory")
        device = root_stat.st_dev

        def visit(parent_descriptor, member, relative):
            nonlocal count
            count += 1
            require(count <= 10000, "APT cache member bound exceeded")
            before = os.stat(member, dir_fd=parent_descriptor, follow_symlinks=False)
            row = {"relative": relative, "before": identity(before), "status": "ATTEMPT"}
            attempts.append(row)
            directory = stat.S_ISDIR(before.st_mode)
            require(before.st_dev == device and not before.st_mode & 0o6000
                    and (directory or stat.S_ISREG(before.st_mode) and before.st_nlink == 1),
                    "APT cache link, special file, mount or privileged mode refused")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if directory:
                flags |= os.O_DIRECTORY
            fd = os.open(member, flags, dir_fd=parent_descriptor)
            try:
                require(identity(os.fstat(fd)) == identity(before), "APT cache member changed during open")
                names = sorted(os.listdir(fd)) if directory else None
                if not directory:
                    require(before.st_size <= 4 << 30, "APT cache file exceeds supply observation bound")
                    row["sha256_before"] = digest_fd(fd)
                os.fchown(fd, uid, gid)
                wanted_mode = stat.S_IMODE(before.st_mode) | (0o700 if directory else 0o600)
                os.fchmod(fd, wanted_mode)
                if directory:
                    for child in names:
                        visit(fd, child, relative + "/" + child)
                    require(sorted(os.listdir(fd)) == names, "APT cache namespace changed")
                else:
                    row["sha256_after"] = digest_fd(fd)
                    require(row["sha256_after"] == row["sha256_before"], "APT cached bytes changed during ownership handoff")
                after = os.fstat(fd)
                require((after.st_dev, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns)
                        == (before.st_dev, before.st_ino, before.st_nlink, before.st_size, before.st_mtime_ns)
                        and after.st_uid == uid and after.st_gid == gid and stat.S_IMODE(after.st_mode) == wanted_mode,
                        "APT cache changed beyond explicit owner/mode handoff")
                require(identity(os.stat(member, dir_fd=parent_descriptor, follow_symlinks=False)) == identity(after),
                        "APT cache named identity changed")
                row.update(after=identity(after), status="OWNERSHIP_RETURNED_BYTES_UNCHANGED")
            finally:
                os.close(fd)
        visit(parent, name, ".")
        stable()
    return {"cache": str(cache), "uid": uid, "gid": gid, "members": count, "attempts": attempts,
            "scope": "only this fresh APT cache after observed process-group closure"}


# The original run_owned() retains its 180-second hard maximum. These are
# external supply steps, owned through the already frozen external guardian.
APT_GUARDIAN_SHA = "d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023"
APT_LIFECYCLE_SHA = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
APT_OWNER_NAMES = ("config.json", "root-process.json", "environment.json",
                   "guardian.json", "child.stdout.log", "child.stderr.log")
APT_OWNER_BINDING = {
    "guardian": {"path": "guardian.py", "bytes": 10257, "sha256": APT_GUARDIAN_SHA},
    "implementation": {"path": "process_owner_impl.py", "bytes": 17601, "sha256": APT_LIFECYCLE_SHA},
    "entry": "original external guardian.execute -> original lifecycle.supervise",
    "external_seconds": {"update": 600, "install": 900},
    "inner_reserve_seconds": 10, "cleanup_seconds": 3,
    "selfhost_run_owned_180_gate_modified": False,
}


def apt_executable_record(path, runner_uid):
    """The original runtime rule, evaluated against the requesting runner."""
    path = Path(path).absolute()
    links = []
    for part in [*reversed(path.parents), path]:
        if part == Path("/"):
            continue
        item = part.lstat()
        if stat.S_ISLNK(item.st_mode):
            links.append({"path": str(part), "identity": identity(item), "target": os.readlink(part)})
    target = path.resolve(strict=True)
    record = file_record(target)
    require(record["identity"][3] in (0, runner_uid) and not record["mode"] & 0o022
            and record["mode"] & 0o111, "APT runtime executable ownership or mode differs")
    require(path.resolve(strict=True) == target, "APT runtime alias changed")
    for row in links:
        name = Path(row["path"])
        require(identity(name.lstat()) == row["identity"] and os.readlink(name) == row["target"],
                "APT runtime alias identity changed")
    return {**record, "invocation_path": str(path), "resolved_path": str(target), "links": links}


def apt_environment(value, supply_root):
    """Reapply the original environment/proxy admission before root execution."""
    require(type(value) is dict and all(type(k) is str and type(v) is str for k, v in value.items()),
            "APT environment must be an exact string mapping")
    extra = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a",
             "TMPDIR": str(supply_root / "tmp"), "TMP": str(supply_root / "tmp"),
             "TEMP": str(supply_root / "tmp")}
    require(all(value.get(k) == v for k, v in extra.items()), "APT fixed environment differs")
    before = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(value)
        checked = clean_env(network=True)
        checked.update(extra)
        require(checked == value, "APT environment contains unadmitted variables")
    finally:
        os.environ.clear()
        os.environ.update(before)
    return dict(value)


def apt_context(request, request_path, request_sha):
    """Bind the two allowed APT operations to the already written outer request."""
    require(request["kind"] == "apt_owned" and type(request["data"]) is dict,
            "fixed APT worker request required")
    data = request["data"]
    require(set(data) == {"phase", "supply_root", "external_request", "uid", "gid", "apt", "sudo", "python"},
            "APT worker request fields differ")
    phase = data["phase"]
    require(type(phase) is str and phase in ("update", "install"), "only fixed APT update/install allowed")
    root = Path(data["supply_root"])
    require(root.is_absolute() and ".." not in root.parts and root.name not in ("", ".", ".."),
            "APT supply root must be canonical")
    root_stat = root.lstat()
    require(stat.S_ISDIR(root_stat.st_mode) and type(data["uid"]) is int and type(data["gid"]) is int
            and data["uid"] > 0 and data["gid"] >= 0
            and root_stat.st_uid == data["uid"] and root_stat.st_gid == data["gid"]
            and stat.S_IMODE(root_stat.st_mode) == 0o700,
            "APT supply root does not belong to the original runner")
    require(root.resolve(strict=True) == root, "APT supply root has a symlink ancestor")
    request_path = Path(request_path)
    label = "apt-" + phase
    require(request_path == root / "requests" / (label + ".worker.json")
            and Path(request["result"]) == root / "reports" / (label + ".result.json"),
            "APT worker request/result path differs")
    request_record = file_record(request_path, limit=262144, owner=data["uid"], single=True)
    require(request_record["sha256"] == request_sha, "APT worker request changed")
    external_path = Path(data["external_request"])
    require(external_path.parent == root / "requests"
            and re.fullmatch(r"[0-9]{3}-" + label + r"\.json", external_path.name),
            "APT external request path differs")
    external, external_record = read_json(external_path)
    require(file_record(external_path, limit=262144, owner=data["uid"], single=True) == external_record,
            "APT external request identity changed")
    script = Path(__file__).absolute()
    require(data["python"] == str(Path(sys.executable).absolute())
            and data["apt"] == "/usr/bin/apt-get" and data["sudo"] == "/usr/bin/sudo",
            "APT fixed executable paths differ")
    expected_command = [data["sudo"], "-n", "--", data["python"], "-I", "-B", str(script),
                        "--worker", str(request_path), request_sha]
    stem = external_path.stem
    require(set(external) == {"schema", "command", "cwd", "environment", "seconds", "stdout", "stderr", "receipt"}
            and external["schema"] == "hia.v87.supply-command.v1"
            and external["command"] == expected_command and external["cwd"] == str(root)
            and external["stdout"] == str(root / "logs" / (stem + ".stdout"))
            and external["stderr"] == str(root / "logs" / (stem + ".stderr"))
            and external["receipt"] == str(root / "logs" / (stem + ".receipt.json")),
            "APT original external request does not bind this worker")
    seconds = external["seconds"]
    require(type(seconds) is int and 10 < seconds <= APT_OWNER_BINDING["external_seconds"][phase],
            "APT original external allowance is insufficient or enlarged")
    environment = apt_environment(external["environment"], root)
    configuration, configuration_record = read_json(request["configuration"])
    require(configuration_record["sha256"] == request["configuration_sha256"]
            and configuration["privileged_apt_owner"] == APT_OWNER_BINDING,
            "APT guardian configuration binding differs")
    pinned = {str(script): request["script_sha256"],
              str(request_path): request_sha, str(external_path): external_record["sha256"],
              str(Path(request["configuration"])): configuration_record["sha256"]}
    source = Path(request["source"])
    for name, expected in configuration["source_pins"].items():
        row = file_record(source / name)
        require(row["bytes"] == expected["bytes"] and row["sha256"] == expected["sha256"],
                "APT fixed source input differs: " + name)
        pinned[str(source / name)] = expected["sha256"]
    for key in ("guardian", "implementation"):
        pin = APT_OWNER_BINDING[key]
        path = script.parent / pin["path"]
        row = file_record(path, single=True)
        require(row["bytes"] == pin["bytes"] and row["sha256"] == pin["sha256"],
                "APT original guardian/lifecycle bytes differ")
        pinned[str(path.resolve(strict=True))] = pin["sha256"]
    executable_records = {}
    for name in ("apt", "sudo", "python"):
        row = apt_executable_record(data[name], data["uid"])
        executable_records[name] = row
        pinned[row["path"]] = row["sha256"]
    command = [data["apt"], "update"] if phase == "update" else [data["apt"], "-o",
        "Dir::Cache::archives=" + str(root / "apt-cache"), "-o",
        "APT::Keep-Downloaded-Packages=true", "install", "-y", *APT_PACKAGES]
    return {"phase": phase, "root": root, "uid": data["uid"], "gid": data["gid"],
            "evidence": root / "evidence" / ("apt-owned-" + phase),
            "command": command, "environment": environment,
            "outer_seconds": seconds, "inner_seconds": seconds - 10,
            "external_request": external_record, "external_request_value": external,
            "worker_request": request_record, "executables": executable_records,
            "pinned_inputs": pinned,
            "guardian": script.parent / "guardian.py",
            "implementation": script.parent / "process_owner_impl.py"}


def apt_guardian_state(value, config, root_process):
    """Separate closed ownership from successful, unsignalled APT completion."""
    require(type(value) is dict and value.get("schema") == "hepta.hia.external-qualification-guardian.v1"
            and value.get("command") == config["command"] and value.get("cwd") == config["cwd"]
            and value.get("external_controller_seconds") == config["controller_seconds"]
            and value.get("lifecycle_implementation_sha256") == APT_LIFECYCLE_SHA
            and value.get("lifecycle_entry") == "supervise; distinct external schema and deadline"
            and value.get("cold_180_second_gate_modified") is False
            and value.get("source_identities_before") == config["source_identities"]
            and value.get("source_identities_after") == config["source_identities"]
            and value.get("input_identity_preserved") is True
            and value.get("qualification") is None
            and value.get("whole_native_delivery_qualified") is False,
            "APT guardian does not bind the current external request and original inputs")
    require(type(root_process) is dict and set(root_process) == {"uid", "euid", "gid", "egid", "pid", "ppid", "pgid", "sid"}
            and all(type(root_process[k]) is int for k in root_process)
            and root_process["uid"] == root_process["euid"] == 0
            and root_process["gid"] >= 0 and root_process["egid"] >= 0
            and all(root_process[k] > 0 for k in ("pid", "ppid", "pgid", "sid")),
            "APT lifecycle was not owned by the root worker")
    life = value.get("lifecycle", {})
    require(type(life) is dict and life.get("schema") == "hepta.hia.external-qualification-guardian.v1.lifecycle"
            and life.get("supervisor_pid") == root_process["pid"]
            and life.get("parent_pid") == root_process["ppid"]
            and life.get("qualification_seconds") == config["controller_seconds"]
            and life.get("cleanup_seconds") == 3,
            "APT actual lifecycle identity or original budgets differ")
    cleanup = life.get("cleanup", {})
    require(type(cleanup) is dict, "APT lifecycle cleanup must be an object")
    closed = (life.get("subreaper_enabled") is True and life.get("qualification_started") is True
              and type(life.get("qualification_pid")) is int and life["qualification_pid"] > 0
              and life.get("event_overflow") is False and cleanup.get("attempted") is True
              and cleanup.get("complete") is True and cleanup.get("observed_echild") is True
              and cleanup.get("leader_reaped") is True and cleanup.get("remaining_direct_children") == []
              and cleanup.get("errors") == [] and cleanup.get("deadline_exceeded") is False)
    events = life.get("events", [])
    event_shape = (type(events) is list and all(type(e) is dict and type(e.get("monotonic_ns")) is int for e in events))
    qpid = life.get("qualification_pid")
    starts = [e for e in events if e.get("kind") == "qualification_started"] if event_shape else []
    exits = [e for e in events if e.get("kind") == "qualification_exit_observed"] if event_shape else []
    reaps = [e for e in events if e.get("kind") == "owned_child_reaped" and e.get("pid") == qpid] if event_shape else []
    observed = [e for e in events if e.get("kind") == "owned_child_observed" and e.get("pid") == qpid] if event_shape else []
    natural_events = (event_shape and len(starts) == len(exits) == len(reaps) == len(observed) == 1
        and starts[0].get("pid") == exits[0].get("pid") == qpid
        and exits[0].get("si_status") == reaps[0].get("returncode") == 0
        and observed[0].get("ppid") == root_process["pid"]
        and type(observed[0].get("start_ticks")) is int
        and observed[0]["start_ticks"] == reaps[0].get("start_ticks")
        and all(a["monotonic_ns"] <= b["monotonic_ns"] for a, b in zip(events, events[1:])))
    natural = (closed and natural_events and value.get("status") == "EXTERNAL_OWNED_PROCESS_COMPLETED"
               and life.get("status") == "OWNED_PROCESS_COMPLETED" and life.get("returncode") == 0
               and life.get("timed_out") is False and life.get("exit_observed_before_deadline") is True
               and life.get("interrupted_signals") == [] and life.get("owner_error") is None
               and not any(e.get("kind") == "owned_child_sigkill" for e in events))
    return {"closed": closed, "natural": natural, "returncode": life.get("returncode"),
            "lifecycle_status": life.get("status"), "guardian_status": value.get("status"),
            "qualification_seconds": config["controller_seconds"], "cleanup_seconds": 3}


def read_apt_owner_evidence(context):
    directory = context["evidence"]
    directory_before = directory.lstat()
    require(stat.S_ISDIR(directory_before.st_mode) and stat.S_IMODE(directory_before.st_mode) == 0o700
            and directory_before.st_uid in (0, context["uid"]), "APT owner evidence directory differs")
    require(sorted(p.name for p in directory.iterdir()) == sorted(APT_OWNER_NAMES),
            "APT owner fixed evidence inventory differs")
    values, records = {}, {}
    for name in APT_OWNER_NAMES:
        if name.endswith(".json"):
            values[name], records[name] = read_json(directory / name, limit=4 << 20)
            require(file_record(directory / name, limit=4 << 20, single=True) == records[name],
                    "APT original JSON identity changed")
    config, root_process, environment = (values[n] for n in ("config.json", "root-process.json", "environment.json"))
    expected_inputs = dict(context["pinned_inputs"])
    expected_inputs[str(directory / "root-process.json")] = records["root-process.json"]["sha256"]
    expected_inputs[str(directory / "environment.json")] = records["environment.json"]["sha256"]
    require(config == {"schema": "hia-external-guardian-request.v1", "command": context["command"],
                       "cwd": str(context["root"]), "controller_seconds": context["inner_seconds"],
                       "source_identities": expected_inputs}
            and environment == context["environment"], "APT owner config/environment differs")
    state = apt_guardian_state(values["guardian.json"], config, root_process)
    require(state["closed"] is True, "APT children are not closed; child streams must remain unread")
    for name in ("child.stdout.log", "child.stderr.log"):
        records[name] = file_record(directory / name, single=True)
    require(values["guardian.json"].get("logs") == {
        str(directory / name): records[name]["sha256"] for name in ("child.stdout.log", "child.stderr.log")},
        "APT complete child stream hashes differ")
    require(identity(directory.lstat()) == identity(directory_before)
            and sorted(p.name for p in directory.iterdir()) == sorted(APT_OWNER_NAMES),
            "APT owner evidence namespace changed during read")
    return {"state": state, "originals": records, "root_process": root_process,
            "config": config, "environment_sha256": records["environment.json"]["sha256"]}


def read_apt_outer_evidence(context):
    """The original group receipt must bind this request before child reads."""
    request = context["external_request_value"]
    value, receipt = read_json(request["receipt"], limit=4 << 20)
    cleanup = value.get("cleanup", {})
    require(value.get("schema") == "hepta.hia.external-workflow-process.v1"
            and value.get("command") == request["command"] and value.get("cwd") == request["cwd"]
            and value.get("workflow_seconds") == context["outer_seconds"]
            and value.get("selfhost_qualification_gate_modified") is False
            and type(value.get("returncode")) is int and type(cleanup) is dict
            and cleanup.get("complete") is True and cleanup.get("errors") == []
            and cleanup.get("full_process_tree_claimed") is False
            and cleanup.get("scope") == "started POSIX process group only",
            "APT original outer process group is not identity-bound and closed")
    streams = {key: file_record(request[key], single=True) for key in ("stdout", "stderr")}
    require(value.get("logs") == {request[key]: row["sha256"] for key, row in streams.items()},
            "APT root-worker stream identities differ")
    require(file_record(request["receipt"], limit=4 << 20, single=True) == receipt,
            "APT outer original receipt changed")
    return {"value": value, "receipt": receipt, "streams": streams}


def return_apt_owner_evidence(context, accepted, attempts):
    """Only six closed guardian files; preserve every byte and original mtime."""
    require(os.getuid() == os.geteuid() == 0 and accepted["state"]["closed"] is True,
            "closed root APT owner required before evidence handoff")
    directory = context["evidence"]
    with parent_fd(directory) as (parent, name, stable):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0
                and stat.S_IMODE(before.st_mode) == 0o700, "fresh private root evidence directory required")
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            require(identity(os.fstat(descriptor)) == identity(before)
                    and sorted(os.listdir(descriptor)) == sorted(APT_OWNER_NAMES), "APT evidence directory changed")
            for child in APT_OWNER_NAMES:
                first = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
                expected = accepted["originals"][child]
                require(stat.S_ISREG(first.st_mode) and first.st_uid == 0 and first.st_nlink == 1
                        and first.st_dev == before.st_dev and identity(first) == expected["identity"]
                        and not first.st_mode & 0o6000, "APT evidence member identity differs")
                fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
                row = {"name": child, "before": identity(first), "sha256": expected["sha256"], "status": "ATTEMPT"}
                attempts.append(row)
                try:
                    require(identity(os.fstat(fd)) == identity(first), "APT evidence changed at held open")
                    os.fchown(fd, context["uid"], context["gid"])
                    os.fchmod(fd, stat.S_IMODE(first.st_mode) | 0o600)
                    digest = hashlib.sha256(); count = 0
                    while block := os.read(fd, 1 << 20):
                        digest.update(block); count += len(block)
                    after = os.fstat(fd)
                    require(count == first.st_size and digest.hexdigest() == expected["sha256"]
                            and (after.st_dev, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns)
                            == (first.st_dev, first.st_ino, first.st_nlink, first.st_size, first.st_mtime_ns)
                            and after.st_uid == context["uid"] and after.st_gid == context["gid"]
                            and identity(os.stat(child, dir_fd=descriptor, follow_symlinks=False)) == identity(after),
                            "APT evidence changed beyond its explicit ownership handoff")
                    row.update(status="OWNERSHIP_RETURNED_BYTES_UNCHANGED", after=identity(after))
                finally:
                    os.close(fd)
            require(sorted(os.listdir(descriptor)) == sorted(APT_OWNER_NAMES), "APT evidence namespace changed")
            os.fchown(descriptor, context["uid"], context["gid"])
            os.fchmod(descriptor, 0o700)
            after = os.fstat(descriptor)
            require(after.st_dev == before.st_dev and after.st_ino == before.st_ino
                    and after.st_uid == context["uid"] and after.st_gid == context["gid"]
                    and stat.S_IMODE(after.st_mode) == 0o700
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(after),
                    "APT evidence root handoff differs")
            stable()
        finally:
            os.close(descriptor)
    reread = read_apt_owner_evidence(context)
    require(reread["state"] == accepted["state"] and all(
        reread["originals"][n]["sha256"] == accepted["originals"][n]["sha256"]
        and reread["originals"][n]["bytes"] == accepted["originals"][n]["bytes"] for n in APT_OWNER_NAMES),
        "APT evidence independent post-handoff read differs")
    return reread


def apt_owned_worker(request, request_path, request_sha, report):
    require(os.getuid() == os.geteuid() == 0, "APT external guardian must run with actual root ownership")
    context = apt_context(request, request_path, request_sha)
    directory = mkdir(context["evidence"])
    report["result"] = {"phase": context["phase"], "closed": False, "natural": False,
        "external_seconds": context["outer_seconds"], "inner_seconds": context["inner_seconds"],
        "cleanup_seconds": 3, "evidence": str(directory), "ownership_attempts": [],
        "cache_ownership_here": False, "cache_handoff_remains_separate_original_180_step": True}
    process = {"pid": os.getpid(), "ppid": os.getppid(), "uid": os.getuid(), "euid": os.geteuid(),
               "gid": os.getgid(), "egid": os.getegid(), "pgid": os.getpgid(0), "sid": os.getsid(0)}
    process_record = create(directory / "root-process.json", wire(process))
    env_record = create(directory / "environment.json", wire(context["environment"]))
    identities = dict(context["pinned_inputs"])
    identities[process_record["path"]] = process_record["sha256"]
    identities[env_record["path"]] = env_record["sha256"]
    config = {"schema": "hia-external-guardian-request.v1", "command": context["command"],
              "cwd": str(context["root"]), "controller_seconds": context["inner_seconds"],
              "source_identities": identities}
    config_record = create(directory / "config.json", wire(config))
    report["result"]["config_original"] = config_record
    guardian = checked_module("_v87_root_apt_external_guardian", context["guardian"], APT_GUARDIAN_SHA)
    before_environment = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(context["environment"])
        # A fresh --worker process holds root and becomes the subreaper. The
        # existing external guardian owns APT, including adopted sessions.
        code = guardian.execute(config, directory, context["implementation"])
    finally:
        os.environ.clear()
        os.environ.update(before_environment)
    require(file_record(directory / "config.json") == config_record, "APT guardian config changed")
    accepted = read_apt_owner_evidence(context)
    report["result"].update(accepted["state"], guardian_exit=code,
        original_root_evidence=accepted, root_process=process)
    require(accepted["state"]["closed"] is True, "APT root children are not proven reaped; no evidence/cache handoff")
    handed = return_apt_owner_evidence(context, accepted, report["result"]["ownership_attempts"])
    report["result"]["runner_owned_evidence"] = handed
    report["result"]["evidence_handoff_complete"] = True
    require(code == 0 and accepted["state"]["natural"] is True,
            "APT external owner closed with nonzero, timeout, signal or cleanup kill")
    return report["result"]


def worker_main(request_path, expected_request_sha):
    request, request_record = read_json(request_path)
    require(request_record["sha256"] == expected_request_sha, "worker request pin differs")
    output = Path(request["result"])
    report = {"schema": "hia.v87.supply-worker.v1", "status": "HOLD", "kind": request["kind"],
              "started_ns": time.time_ns(), "qualification_executed": False}
    try:
        require(file_record(Path(__file__).absolute())["sha256"] == request["script_sha256"], "worker script changed")
        configuration, config_record = read_json(request["configuration"])
        require(config_record["sha256"] == request["configuration_sha256"], "worker configuration changed")
        source = Path(request["source"])
        for name, expected in configuration["source_pins"].items():
            row = file_record(source / name)
            require(row["sha256"] == expected["sha256"] and row["bytes"] == expected["bytes"], "worker source pin differs: " + name)
        data, kind = request["data"], request["kind"]
        if kind == "download":
            value = download(**data)
        elif kind == "extract_tar":
            value = extract_tar(**data)
        elif kind == "extract_qemu":
            value = extract_qemu(**data)
        elif kind == "extract_lean":
            value = extract_lean(**data)
        elif kind == "cargo_vendor":
            value = cargo_vendor(**data)
        elif kind == "verify_rust":
            module = checked_module("_v87_original_rust_verifier", source / "tools/bootstrap_toolchain.py",
                                    configuration["source_pins"]["tools/bootstrap_toolchain.py"]["sha256"])
            value = module.verify_installed_package(Path(data["package_root"]), Path(data["prefix"]))
            value["installed"] = inventory(data["prefix"])
        elif kind == "build_adapter":
            module = checked_module("_v87_original_ndu_builder", source / "tools/build_hia_ndu_bridge.py",
                                    configuration["source_pins"]["tools/build_hia_ndu_bridge.py"]["sha256"])
            value = module.build(Path(data["checkout"]), Path(data["output"]), cargo=data["cargo"],
                                 adapter=source / data["adapter"], release=data["release"])
        elif kind == "apt_inputs":
            require(os.getuid() == 0 and data["key_destination"] == LLVM_KEY_DEST
                    and data["repo_destination"] == LLVM_REPO_DEST, "fixed privileged APT input operation required")
            key_record, key = file_record(data["key_source"], body=True, limit=1 << 20)
            require(key_record["sha256"] == data["key_sha256"], "APT key changed")
            create(LLVM_KEY_DEST, key, 0o644)
            create(LLVM_REPO_DEST, LLVM_REPO.encode(), 0o644)
            value = {"key": file_record(LLVM_KEY_DEST), "repository": file_record(LLVM_REPO_DEST)}
        elif kind == "apt_owned":
            value = apt_owned_worker(request, request_path, expected_request_sha, report)
        elif kind == "apt_cache_owner":
            require(Path(data["cache"]) == output.parent.parent / "apt-cache", "different cache operation root")
            report["ownership_attempts"] = []
            value = return_apt_cache_to_owner(data["cache"], data["uid"], data["gid"], report["ownership_attempts"])
        else:
            raise Refusal("unknown fixed supply operation")
        for name, expected in configuration["source_pins"].items():
            row = file_record(source / name)
            require(row["sha256"] == expected["sha256"] and row["bytes"] == expected["bytes"], "worker source changed: " + name)
        require(file_record(Path(__file__).absolute())["sha256"] == request["script_sha256"], "worker script changed at end")
        report.update(status="SUPPLY_OPERATION_COMPLETED", result=value)
        code = 0
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
        code = 2
    report["finished_ns"] = time.time_ns()
    # Root signing/cache metadata and closed APT ownership originals are
    # retained evidence. The original runner must be able to read the report.
    public_root_result = os.getuid() == 0 and request["kind"] in {"apt_inputs", "apt_cache_owner", "apt_owned"}
    create(output, wire(report), 0o644 if public_root_result else 0o600)
    print(json.dumps({"status": report["status"], "kind": report["kind"], "report": str(output)}), flush=True)
    return code


class Supply:
    def __init__(self, args):
        self.output_created = False
        self.args = args
        self.source, self.output = Path(args.source).absolute(), Path(args.output).absolute()
        self.script, self.configuration = Path(__file__).absolute(), Path(args.configuration).absolute()
        require(not self.output.is_relative_to(self.source), "supply output must be outside source")
        self.plan, self.plan_record = read_json(self.configuration)
        self.self_record = file_record(self.script)
        require(self.plan["schema"] == "hia.v87.full-prerequisite-supply-plan.v1", "wrong supply plan")
        require(self.plan["dispatchable"] is True, "draft supply plan cannot execute")
        require(self.plan.get("privileged_apt_owner") == APT_OWNER_BINDING,
                "original external APT owner binding differs")
        require(self.plan["supply_seconds"] == 3600 and self.plan["outer_seconds"] == 10800, "supply budget differs")
        require(self.plan["control"] == {"bytes": self.self_record["bytes"], "sha256": self.self_record["sha256"]}, "supply control pin differs")
        require(re.fullmatch(r"[0-9a-f]{40}", self.plan["source"]["head"]) and self.plan["source"]["head"] != "0" * 40
                and re.fullmatch(r"[0-9a-f]{40}", self.plan["source"]["tree"]) and self.plan["source"]["tree"] != "0" * 40,
                "final nonzero source identity must be frozen before execution")
        require(sys.version_info[:3] == (3, 14, 4) and sys.prefix != sys.base_prefix,
                "the actual qualification CPython 3.14.4 venv is required")
        require(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "wrong supply platform")
        require(Path(args.python).absolute() == Path(sys.executable).absolute(), "different supply interpreter")
        self.python = str(Path(args.python).absolute())
        mkdir(self.output)
        self.output_created = True
        for name in ("logs", "requests", "reports", "downloads", "extracted", "evidence", "verification-tools",
                     "toolchains-rustup", "fixtures", "targets", "upstream", "gpg-home", "apt-cache", "python-support", "tmp"):
            mkdir(self.output / name)
        mkdir(self.output / "toolchains-rustup/toolchains")
        mkdir(self.output / "apt-cache/partial", 0o755)
        self.started = time.monotonic()
        self.deadline = self.started + 3590
        self.pending_group = False
        self.steps, self.bindings, self.immutable, self.upstreams = [], {}, {}, {}
        self.env = clean_env()
        self.network_env = clean_env(network=True)
        for env in (self.env, self.network_env):
            env.update(TMPDIR=str(self.output / "tmp"), TMP=str(self.output / "tmp"), TEMP=str(self.output / "tmp"))
        self.report = {"schema": SCHEMA, "status": "HOLD", "source": dict(self.plan["source"]),
                       "prerequisite_root": str(self.output), "started_ns": time.time_ns(), "steps": self.steps,
                       "qualification_executed": False, "old_receipts_relabelled": False,
                       "new_supply_allowance_seconds": 3600, "enclosing_guardian_seconds": 10800,
                       "full_process_tree_cleanup_claimed_by_supply": False,
                       "configuration": self.plan_record, "script": self.self_record}
        self.workflow = None
        self.git = None

    def executable(self, name):
        value = shutil.which(name, path=self.env.get("PATH"))
        require(value is not None, "required bootstrap utility missing: " + name)
        row = resolved_record(value)
        self.bindings[row["path"]] = row["sha256"]
        return str(Path(value).absolute())

    def save(self, name, value):
        return create(self.output / "reports" / name, wire(value))

    def step(self, label, command, *, cwd=None, env=None, seconds=120):
        require(re.fullmatch(r"[a-z0-9-]+", label), "unsafe step label")
        remaining = self.deadline - time.monotonic()
        require(remaining > 1, "supply deadline exhausted before next step")
        allowance = min(seconds, int(remaining))
        number = len(self.steps) + 1
        stem = f"{number:03d}-{label}"
        stdout = self.output / "logs" / (stem + ".stdout")
        stderr = self.output / "logs" / (stem + ".stderr")
        receipt = self.output / "logs" / (stem + ".receipt.json")
        chosen_env = self.env if env is None else env
        chosen_cwd = self.output if cwd is None else Path(cwd)
        request = {"schema": "hia.v87.supply-command.v1", "command": [str(x) for x in command],
                   "cwd": str(chosen_cwd), "environment": chosen_env, "seconds": allowance,
                   "stdout": str(stdout), "stderr": str(stderr), "receipt": str(receipt)}
        request_record = create(self.output / "requests" / (stem + ".json"), wire(request))
        row = {"label": label, "request": request_record, "request_value": request,
               "observed_process_group_closed": False}
        self.steps.append(row)
        self.pending_group = True
        returned = self.workflow.run_workflow_step(request["command"], cwd=chosen_cwd, env=chosen_env,
                stdout_path=stdout, stderr_path=stderr, receipt_path=receipt, seconds=allowance)
        closed = (returned.get("cleanup", {}).get("complete") is True and
                  returned.get("cleanup", {}).get("errors") == [] and type(returned.get("returncode")) is int)
        self.pending_group = not closed
        row["observed_process_group_closed"] = closed
        require(closed, "supply process group did not close; output is not finalized")
        raw_receipt, receipt_record = read_json(receipt)
        stdout_record, stderr_record = file_record(stdout), file_record(stderr)
        row.update(receipt=receipt_record, returned=returned, stdout=stdout_record, stderr=stderr_record)
        require(raw_receipt == returned and returned["schema"] == "hepta.hia.external-workflow-process.v1"
                and returned["command"] == request["command"] and returned["cwd"] == request["cwd"]
                and returned["workflow_seconds"] == allowance
                and returned["logs"] == {str(stdout): stdout_record["sha256"], str(stderr): stderr_record["sha256"]},
                "actual command receipt binding differs")
        self.save(stem + ".completed.json", row)
        require(returned["status"] == "WORKFLOW_STEP_COMPLETED" and returned["returncode"] == 0
                and returned["timed_out"] is False and returned["cleanup"]["signalled"] == []
                and returned["selfhost_qualification_gate_modified"] is False,
                "supply command held: " + label)
        return stdout

    def operation(self, label, kind, data, *, seconds=240, env=None, privileged=False):
        result_path = self.output / "reports" / (label + ".result.json")
        request_path = self.output / "requests" / (label + ".worker.json")
        request = {"kind": kind, "data": data, "result": str(result_path), "source": str(self.source),
                   "script_sha256": self.self_record["sha256"], "configuration": str(self.configuration),
                   "configuration_sha256": self.plan_record["sha256"]}
        request_record = create(request_path, wire(request))
        self.bindings[request_record["path"]] = request_record["sha256"]
        command = [self.python, "-I", "-B", str(self.script), "--worker", str(request_path), request_record["sha256"]]
        if privileged:
            command = [self.executable("sudo"), "-n", "--", *command]
        self.step(label, command, env=env, seconds=seconds)
        value, record = read_json(result_path, limit=128 << 20)
        require(value["schema"] == "hia.v87.supply-worker.v1" and value["kind"] == kind
                and value["status"] == "SUPPLY_OPERATION_COMPLETED", "worker result not complete")
        self.bindings[str(result_path)] = record["sha256"]
        return value["result"]

    def get(self, label, url, *, sha=None, size=None, maximum=1 << 30, seconds=240, filename=None,
            pin_origin="preexecution fixed source or historical raw manifest"):
        path = self.output / "downloads" / (filename or label)
        result = self.operation(label, "download", {"url": url, "destination": str(path),
            "expected_sha": sha, "expected_size": size, "maximum": maximum, "seconds": seconds, "pin_origin": pin_origin},
            seconds=seconds + 5, env=self.network_env)
        self.bindings[str(path)] = result["sha256"]
        return path

    def exact_source(self, label, path, *, expected_head=None, expected_tree=None):
        path = Path(path)
        head_out = self.step(label + "-head", [self.git, "-C", str(path), "rev-parse", "HEAD"], seconds=30)
        tree_out = self.step(label + "-tree", [self.git, "-C", str(path), "rev-parse", "HEAD^{tree}"], seconds=30)
        leaf_out = self.step(label + "-leaves", [self.git, "-C", str(path), "ls-tree", "-r", "-z", "HEAD"], seconds=60)
        _, raw_head = file_record(head_out, body=True, limit=1024)
        _, raw_tree = file_record(tree_out, body=True, limit=1024)
        _, raw_leaves = file_record(leaf_out, body=True, limit=64 << 20)
        head, tree = raw_head.decode().strip(), raw_tree.decode().strip()
        require(expected_head is None or head == expected_head, "source head differs")
        require(expected_tree is None or tree == expected_tree, "source tree differs")
        before = inventory(path, ignore_git=True)
        count = check_git_inventory(before, raw_leaves)
        require(inventory(path, ignore_git=True) == before, "source changed during full read")
        value = {"head": head, "tree": tree, "root": str(path), "leaves": count,
                 "files": before, "full_physical_read": True}
        receipt = self.save(label + ".snapshot.json", value)
        return value, receipt

    def apt_owned_step(self, phase, apt, sudo, environment):
        require(phase in ("update", "install") and apt == "/usr/bin/apt-get" and sudo == "/usr/bin/sudo",
                "only the two fixed APT supply commands are permitted")
        label = "apt-" + phase
        request_path = self.output / "requests" / (label + ".worker.json")
        external_path = self.output / "requests" / (f"{len(self.steps) + 1:03d}-" + label + ".json")
        result_path = self.output / "reports" / (label + ".result.json")
        row = {"phase": phase, "status": "HOLD", "root_owner_closed": False,
               "outer_group_closed": False, "cache_handoff_authorized": False}
        self.report.setdefault("apt_root_owners", {})[phase] = row
        original_error = None
        returned = None
        try:
            returned = self.operation(label, "apt_owned", {
                "phase": phase, "supply_root": str(self.output), "external_request": str(external_path),
                "uid": os.getuid(), "gid": os.getgid(), "apt": apt, "sudo": sudo, "python": self.python},
                privileged=True, seconds=APT_OWNER_BINDING["external_seconds"][phase], env=environment)
        except BaseException as error:
            original_error = error
            row["primary_error"] = {"type": type(error).__name__, "message": str(error),
                                    "traceback": traceback.format_exc()}
            raise
        finally:
            # A POSIX group alone is no longer the admission for APT outputs.
            # Any missing inner proof prevents the original finally cache step.
            outer_reported_closed = not self.pending_group
            self.pending_group = True
            try:
                require(outer_reported_closed and self.steps and self.steps[-1]["label"] == label
                        and self.steps[-1]["observed_process_group_closed"] is True,
                        "APT outer group is not closed; do not read child outputs")
                request, request_record = read_json(request_path, limit=262144)
                context = apt_context(request, request_path, request_record["sha256"])
                outer = read_apt_outer_evidence(context)
                require(outer["value"] == self.steps[-1].get("returned"),
                        "APT original outer receipt differs from its actual return")
                row["outer_group_closed"] = True
                row["outer_evidence"] = outer
                value, result_record = read_json(result_path, limit=16 << 20)
                require(file_record(result_path, limit=16 << 20, owner=0, single=True) == result_record
                        and result_record["mode"] == 0o644
                        and value.get("schema") == "hia.v87.supply-worker.v1"
                        and value.get("kind") == "apt_owned" and value.get("qualification_executed") is False,
                        "APT root worker result identity differs")
                detail = value.get("result", {})
                require(type(detail) is dict and detail.get("phase") == phase
                        and detail.get("external_seconds") == context["outer_seconds"]
                        and detail.get("inner_seconds") == context["inner_seconds"]
                        and detail.get("cleanup_seconds") == 3
                        and detail.get("evidence") == str(context["evidence"])
                        and detail.get("closed") is True and detail.get("evidence_handoff_complete") is True
                        and detail.get("cache_ownership_here") is False
                        and detail.get("cache_handoff_remains_separate_original_180_step") is True,
                        "APT root closure/evidence handoff is incomplete")
                current = read_apt_owner_evidence(context)
                require(context["evidence"].lstat().st_uid == os.getuid()
                        and detail.get("runner_owned_evidence") == current
                        and detail.get("root_process") == current["root_process"]
                        and all(detail.get(k) == v for k, v in current["state"].items()),
                        "APT actual owner evidence differs from the root worker original")
                original = detail.get("original_root_evidence", {})
                require(original.get("state") == current["state"]
                        and original.get("root_process") == current["root_process"]
                        and original.get("config") == current["config"]
                        and original.get("environment_sha256") == current["environment_sha256"]
                        and set(original.get("originals", {})) == set(APT_OWNER_NAMES),
                        "APT root original metadata does not bind its handoff")
                attempts = detail.get("ownership_attempts", [])
                require(type(attempts) is list and len(attempts) == len(APT_OWNER_NAMES),
                        "APT fixed ownership handoff denominator differs")
                for name, attempt in zip(APT_OWNER_NAMES, attempts):
                    before, after = original["originals"][name], current["originals"][name]
                    old, new = before["identity"], after["identity"]
                    require(before["path"] == after["path"] == str(context["evidence"] / name)
                            and before["bytes"] == after["bytes"] and before["sha256"] == after["sha256"]
                            and old[3] == 0 and new[3] == os.getuid() and new[4] == os.getgid()
                            and old[5] == new[5] == 1 and new[2] == old[2] | 0o600
                            and all(old[i] == new[i] for i in (0, 1, 5, 6, 7))
                            and attempt == {"name": name, "before": old, "after": new,
                                "sha256": before["sha256"], "status": "OWNERSHIP_RETURNED_BYTES_UNCHANGED"},
                            "APT evidence handoff changed bytes or another physical identity")
                    self.bindings[after["path"]] = after["sha256"]
                self.bindings[result_record["path"]] = result_record["sha256"]
                self.bindings.update(context["pinned_inputs"])
                row.update(root_owner_closed=True, cache_handoff_authorized=True,
                    root_worker_result=result_record, owner_state=current["state"],
                    current_evidence=current, original_root_evidence=original,
                    status="APT_ROOT_CLOSED_SUPPLY_HELD")
                # Closure is useful even if APT failed; it never promotes that
                # failure to success. The original command exception survives.
                self.pending_group = False
                if original_error is None:
                    require(value.get("status") == "SUPPLY_OPERATION_COMPLETED"
                            and current["state"]["natural"] is True and detail.get("guardian_exit") == 0
                            and returned == detail, "APT did not naturally complete under the root owner")
                    row["status"] = "APT_ROOT_OWNED_COMMAND_COMPLETED"
            except BaseException as error:
                row["evidence_error"] = {"type": type(error).__name__, "message": str(error),
                                         "traceback": traceback.format_exc()}
                if original_error is None:
                    raise
        return returned


    def apt_supply(self):
        before = self.step("apt-packages-before", [self.executable("dpkg-query"), "-W", "-f=${Package}\t${Version}\t${Status}\n"], seconds=30)
        key = self.get("llvm-signing-key", LLVM_KEY_URL, maximum=1 << 20, seconds=60, filename="llvm-snapshot.gpg.key")
        shown = self.step("llvm-key-fingerprint", [self.executable("gpg"), "--homedir", str(self.output / "gpg-home"),
             "--batch", "--show-keys", "--with-colons", str(key)], seconds=30)
        _, raw = file_record(shown, body=True, limit=1 << 20)
        fingerprints = [line.split(":")[9] for line in raw.decode().splitlines() if line.startswith("fpr:")]
        require(fingerprints and fingerprints[0] == LLVM_FINGERPRINT, "LLVM signing key fingerprint differs")
        self.operation("install-fixed-apt-inputs", "apt_inputs", {"key_source": str(key),
            "key_sha256": file_record(key)["sha256"], "key_destination": LLVM_KEY_DEST,
            "repo_destination": LLVM_REPO_DEST}, privileged=True, seconds=30)
        sudo, apt = self.executable("sudo"), self.executable("apt-get")
        env = dict(self.network_env, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="a")
        try:
            self.apt_owned_step("update", apt, sudo, env)
            self.apt_owned_step("install", apt, sudo, env)
        finally:
            primary_error = sys.exc_info()[1]
            try:
                if not self.pending_group:
                    self.report["apt_cache_ownership"] = self.operation("apt-cache-owner", "apt_cache_owner",
                        {"cache": str(self.output / "apt-cache"), "uid": os.getuid(), "gid": os.getgid()},
                        privileged=True, seconds=180)
                else:
                    self.report["apt_cache_ownership"] = {"status": "HOLD",
                        "reason": "APT outer group and inner root ECHILD not both proven; no cache read or ownership change"}
            except BaseException as error:
                self.report["apt_cache_ownership_error"] = {"type": type(error).__name__, "message": str(error),
                    "traceback": traceback.format_exc()}
                if primary_error is None:
                    raise
        after = self.step("apt-packages-after", [self.executable("dpkg-query"), "-W", "-f=${Package}\t${Version}\t${Status}\n"], seconds=30)
        debs = {p.name: file_record(p) for p in sorted((self.output / "apt-cache").glob("*.deb"))}
        self.report["apt"] = {"packages": list(APT_PACKAGES), "before": file_record(before), "after": file_record(after),
            "key": file_record(LLVM_KEY_DEST), "repository": file_record(LLVM_REPO_DEST), "downloaded_debs": debs,
            "version_source": "actual APT signed repository resolution; not pre-frozen binary hashes",
            "privileged_interference_excluded_from_guardian_claim": True}
        for row in (self.report["apt"]["key"], self.report["apt"]["repository"]):
            self.bindings[row["path"]] = row["sha256"]
        for row in debs.values():
            self.bindings[row["path"]] = row["sha256"]
        for name, path in TOOL_PATHS.items():
            row = resolved_record(path)
            self.bindings[row["path"]] = row["sha256"]
        self.save("apt-supply.json", self.report["apt"])

    def python_support(self):
        metadata = self.get("zstandard-pypi-metadata", "https://pypi.org/pypi/zstandard/0.25.0/json",
                            maximum=4 << 20, seconds=60, filename="zstandard-0.25.0.pypi.json")
        value, _ = read_json(metadata)
        require(value["info"]["name"] == "zstandard" and value["info"]["version"] == "0.25.0", "zstandard metadata differs")
        chosen = [x for x in value["urls"] if x.get("packagetype") == "bdist_wheel"
                  and x["filename"] == ZSTD_WHEEL and not x.get("yanked")]
        require(len(chosen) == 1, "expected one official CPython 3.14 x86_64 zstandard wheel")
        item = chosen[0]
        require(urllib.parse.urlsplit(item["url"]).hostname == "files.pythonhosted.org"
                and Path(urllib.parse.urlsplit(item["url"]).path).name == ZSTD_WHEEL, "unexpected PyPI file URL")
        wheel = self.get("zstandard-wheel", item["url"], sha=item["digests"]["sha256"], size=item["size"],
                         maximum=32 << 20, filename=item["filename"],
                         pin_origin="official PyPI 0.25.0 metadata observed during this supply")
        self.step("zstandard-install", [self.python, "-I", "-B", "-m", "pip", "--isolated", "install", "--no-index",
            "--no-deps", "--no-compile", "--target", str(self.output / "python-support"), str(wheel)], seconds=120)
        self.immutable["python-support"] = inventory(self.output / "python-support")
        self.report["supply_python_dependency"] = {"name": "zstandard", "version": "0.25.0", "wheel": file_record(wheel),
            "metadata": file_record(metadata), "directory": str(self.output / "python-support"),
            "qualification_venv_modified": False, "sha_origin": "actual official PyPI version metadata in this supply"}

    def verification_tools(self):
        lean_lock, _ = read_json(self.source / "formal/toolchain-lock.json")
        lean = self.get("lean-archive", lean_lock["url"], sha=lean_lock["archive_sha256"],
                        maximum=1 << 30, seconds=300, filename="lean-4.19.0-linux.tar.zst")
        result = self.operation("lean-extract", "extract_lean", {"archive_path": str(lean),
            "destination": str(self.output / "verification-tools/lean-4.19.0"), "source": str(self.source),
            "support": str(self.output / "python-support")}, seconds=300)
        self.immutable["lean"] = result["files"]
        qemu_lock, _ = read_json(self.source / "formal/qemu-toolchain-lock.json")
        qemu = self.get("qemu-archive", qemu_lock["source"], sha=qemu_lock["package_sha256"],
                        maximum=128 << 20, filename="qemu-user-static.deb")
        tar = self.step("qemu-data-tar", [self.executable("dpkg-deb"), "--fsys-tarfile", str(qemu)], seconds=120)
        result = self.operation("qemu-extract", "extract_qemu", {"data_tar": str(tar),
            "destination": str(self.output / "verification-tools/qemu-8.2.2")}, seconds=120)
        self.immutable["qemu"] = result["files"]
        boost = self.get("boost-archive", BOOST_URL, sha=BOOST_SHA, size=10731924,
                         maximum=16 << 20, filename=BOOST_NAME)
        tar = self.step("boost-data-tar", [self.executable("dpkg-deb"), "--fsys-tarfile", str(boost)], seconds=120)
        self.operation("boost-extract", "extract_tar", {"archive": str(tar),
            "destination": str(self.output / "toolchains-boost183"), "max_bytes": 256 << 20}, seconds=120)
        copy_file(boost, self.output / "toolchains-boost183" / BOOST_NAME, mode=0o644)
        header = file_record(self.output / "toolchains-boost183/usr/include/boost/version.hpp")
        require(header["sha256"] == BOOST_HEADER_SHA, "Boost 1.83 header pin differs")
        create(self.output / "evidence/qualification-boost183-01.json", wire({
            "schema": "hia.v87.fresh-boost-supply.v1", "package": BOOST_NAME, "sha256": BOOST_SHA,
            "source": BOOST_URL, "version_header": header, "qualification_executed": False}))
        self.immutable["boost"] = inventory(self.output / "toolchains-boost183")

    def rust190(self):
        lock, _ = read_json(self.source / "toolchain-lock.json")
        require(type(lock) is list and len(lock) == 6, "original Rust six-package lock differs")
        prefix = self.output / "toolchains-rustup/toolchains" / ("1.90.0-" + HOST)
        for index, item in enumerate(lock):
            require(item["package"].startswith(("rustc-1.90.0-", "cargo-1.90.0-", "rust-std-1.90.0-"))
                    and item["url"] == "https://static.rust-lang.org/dist/" + item["package"] + ".tar.xz", "unexpected Rust lock entry")
            label = "rust190-" + str(index)
            archive = self.get(label + "-download", item["url"], sha=item["sha256"], maximum=256 << 20,
                               filename=item["package"] + ".tar.xz")
            extracted = self.output / "extracted" / label
            self.operation(label + "-extract", "extract_tar", {"archive": str(archive), "destination": str(extracted)}, seconds=180)
            package = extracted / item["package"]
            self.step(label + "-install", [self.executable("sh"), str(package / "install.sh"), "--prefix=" + str(prefix),
                                          "--disable-ldconfig"], seconds=180)
            self.operation(label + "-verify", "verify_rust", {"package_root": str(package), "prefix": str(prefix)}, seconds=120)
        self.immutable["rust190"] = inventory(prefix)
        return prefix

    def rust195(self):
        metadata = self.get("rust195-channel", "https://static.rust-lang.org/dist/channel-rust-1.95.0.toml",
                            maximum=2 << 20, filename="channel-rust-1.95.0.toml")
        checksum = self.get("rust195-channel-checksum", "https://static.rust-lang.org/dist/channel-rust-1.95.0.toml.sha256",
                            maximum=4096, filename="channel-rust-1.95.0.toml.sha256")
        _, checksum_raw = file_record(checksum, body=True, limit=4096)
        declared = checksum_raw.decode("ascii").split()[0]
        metadata_row, metadata_raw = file_record(metadata, body=True, limit=2 << 20)
        require(re.fullmatch(r"[0-9a-f]{64}", declared) and metadata_row["sha256"] == declared,
                "actual Rust 1.95 official channel checksum differs")
        channel = tomllib.loads(metadata_raw.decode())
        require(channel.get("manifest-version") == "2" and str(channel["pkg"]["rust"]["version"]).startswith("1.95.0 "),
                "unexpected Rust 1.95 channel identity/grammar")
        packages = []
        for name in ("rustc", "cargo", "rust-std"):
            package = channel["pkg"][name]
            target = package["target"][HOST]
            # Cargo's distribution metadata can use its source-package 0.x
            # version. The exact archive basename/hash and actual cargo --version
            # below bind the public 1.95.0 tool; do not reject that metadata grammar.
            require(target["available"] is True, "Rust 1.95 package is unavailable")
            url, sha = target["xz_url"], target["xz_hash"]
            require(urllib.parse.urlsplit(url).hostname == "static.rust-lang.org"
                    and Path(urllib.parse.urlsplit(url).path).name == name + "-1.95.0-" + HOST + ".tar.xz",
                    "Rust 1.95 component URL differs")
            archive = self.get("rust195-" + name + "-download", url, sha=sha, maximum=256 << 20,
                               filename=name + "-1.95.0-" + HOST + ".tar.xz",
                               pin_origin="official Rust 1.95.0 channel metadata observed during this supply")
            extracted = self.output / "extracted" / ("rust195-" + name)
            self.operation("rust195-" + name + "-extract", "extract_tar", {"archive": str(archive), "destination": str(extracted)}, seconds=180)
            packages.append((name, extracted / (name + "-1.95.0-" + HOST), archive))
        rustup = self.executable("rustup")
        rustup_record = resolved_record(rustup)
        self.step("rustup-version", [rustup, "--version"], seconds=30)
        env = dict(self.network_env, RUSTUP_HOME=str(self.output / "rustup195"),
                   CARGO_HOME=str(self.output / "rustup195-cargo"),
                   RUSTUP_DIST_SERVER="https://static.rust-lang.org",
                   RUSTUP_UPDATE_ROOT="https://static.rust-lang.org/rustup")
        # The exact feedback entry is preserved.  No earlier Rust 1.95 receipt
        # or version string is substituted for the resulting binary bytes.
        self.step("rust195-install", [rustup, "toolchain", "install", "1.95.0", "--profile", "minimal"], env=env, seconds=1200)
        cargo_out = self.step("rust195-which", [rustup, "which", "--toolchain", "1.95.0", "cargo"], env=env, seconds=30)
        _, raw = file_record(cargo_out, body=True, limit=4096)
        cargo = Path(raw.decode().strip())
        prefix = self.output / "rustup195/toolchains" / ("1.95.0-" + HOST)
        require(cargo == prefix / "bin/cargo", "Rustup 1.95 returned a different private prefix")
        for name, package, archive in packages:
            self.operation("rust195-" + name + "-verify", "verify_rust", {"package_root": str(package), "prefix": str(prefix)}, seconds=120)
        for name in ("cargo", "rustc"):
            log = self.step("rust195-" + name + "-version", [str(prefix / "bin" / name), "--version"], seconds=30)
            _, raw_version = file_record(log, body=True, limit=65536)
            require(raw_version.decode().startswith(name + " 1.95.0 "), "actual Rust 1.95 tool version differs")
        require(resolved_record(rustup) == rustup_record, "Rustup executable changed")
        self.immutable["rust195"] = inventory(prefix)
        self.report["rust195_provenance"] = {"rustup": rustup_record, "metadata": metadata_row,
            "metadata_checksum": file_record(checksum), "archives": [file_record(p[2]) for p in packages],
            "actual_installed_payloads_compared": True, "historical_archive_digest_claimed": False,
            "source": "official version-specific distribution metadata observed during this supply"}
        return prefix

    def upstream_supply(self):
        repository = self.output / "upstream/repository"
        self.step("upstream-init", [self.git, "init", "--bare", str(repository)], seconds=30)
        for name, commit in UPSTREAM_COMMITS.items():
            self.step("upstream-fetch-" + name.replace("_", "-"), [self.git, "-c", "credential.helper=", "-c", "protocol.version=2",
                "-c", "core.hooksPath=/dev/null", "-C", str(repository), "fetch", "--no-tags", "--depth=1", UPSTREAM_URL, commit],
                env=self.network_env, seconds=600)
            checkout = self.output / "upstream" / name
            self.step("upstream-checkout-" + name.replace("_", "-"), [self.git, "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
                "-C", str(repository), "worktree", "add", "--detach", str(checkout), commit], seconds=120)
            snapshot, receipt = self.exact_source("upstream-" + name.replace("_", "-"), checkout, expected_head=commit)
            self.upstreams[name] = snapshot
            self.bindings[receipt["path"]] = receipt["sha256"]
        return {name: Path(value["root"]) for name, value in self.upstreams.items()}

    def builders(self, rust190, rust195, upstreams, cargo_home):
        receipts = []
        for profile, adapter, source_key, release in (
                ("ranking", "hia-ndu-bridge", "ranking", False),
                ("raw", "hia-ndu-raw-model", "raw_dynamic", True),
                ("dynamic", "hia-ndu-dynamic-model", "raw_dynamic", True)):
            pin, _ = read_json(self.source / "rust" / adapter / "upstream.json")
            require(pin["repository"] == UPSTREAM_URL and pin["commit"] == UPSTREAM_COMMITS[source_key], "adapter upstream pin differs")
            env = dict(self.env, CARGO_HOME=str(cargo_home), CARGO_NET_OFFLINE="true", RUSTC=str(rust190 / "bin/rustc"),
                       CARGO_TARGET_DIR=str(self.output / "targets" / profile),
                       PATH=str(rust190 / "bin") + os.pathsep + self.env.get("PATH", ""))
            self.operation("ndu-" + profile, "build_adapter", {"checkout": str(upstreams[source_key]),
                "output": str(self.output / "fixtures" / profile), "cargo": str(rust190 / "bin/cargo"),
                "adapter": "rust/" + adapter, "release": release}, env=env, seconds=900)
            path = self.output / "fixtures" / profile / "build-receipt.json"
            value, record = read_json(path)
            require(value["schema"] == "hepta.hia.ndu-build.v1" and value["original_rust_sources_unchanged"] is True
                    and value["all_original_non_manifest_inputs_unchanged"] is True and value["build_inputs_unchanged"] is True
                    and value["builder_sha256"] == self.plan["source_pins"]["tools/build_hia_ndu_bridge.py"]["sha256"],
                    "fresh adapter build receipt differs")
            binary = file_record(value["binary"])
            require(binary["sha256"] == value["binary_sha256"], "adapter binary differs from receipt")
            receipts.append({"profile": profile, **record, "binary": binary})
        for profile in ("recursive", "finite", "stream"):
            rust = rust195 if profile == "finite" else rust190
            env = dict(self.env, CARGO_HOME=str(cargo_home), CARGO_NET_OFFLINE="true", RUSTC=str(rust / "bin/rustc"),
                       PATH=str(rust / "bin") + os.pathsep + self.env.get("PATH", ""))
            command = [self.python, "-I", "-B", str(self.source / "tools/build_hia_recursive_ndu_bridge.py"),
                "--ndu-source", str(upstreams[profile]), "--output", str(self.output / "fixtures" / profile),
                "--target-dir", str(self.output / "targets" / profile), "--cargo", str(rust / "bin/cargo"),
                "--rustc", str(rust / "bin/rustc"), "--cargo-home", str(cargo_home),
                "--expected-source", UPSTREAM_COMMITS[profile], "--offline"]
            self.step("ndu-" + profile, command, env=env, seconds=900)
            path = self.output / "fixtures" / profile / "identity.json"
            value, record = read_json(path)
            require(value["schema"] == "hepta.hia.ndu.build.v1" and value["identity"]["source_commit"] == UPSTREAM_COMMITS[profile]
                    and value["identity"]["authority"] == "DENY_ALL" and value["identity"]["safety_certificate"] is False
                    and value["build_tools"]["builder_sha256"] == self.plan["source_pins"]["tools/build_hia_recursive_ndu_bridge.py"]["sha256"],
                    "fresh recursive-profile identity differs")
            binary, compiled = file_record(value["binary"]), file_record(value["compiled_binary"])
            require(binary["sha256"] == compiled["sha256"] == value["binary_sha256"] == value["compiled_binary_sha256"],
                    "recursive-profile binary differs")
            receipts.append({"profile": profile, **record, "binary": binary})
        require([x["profile"] for x in receipts] == ["ranking", "raw", "dynamic", "recursive", "finite", "stream"], "six-fixture denominator differs")
        return receipts

    def observe_tools(self, rust190):
        paths = dict(TOOL_PATHS)
        paths.update(rustc=str(rust190 / "bin/rustc"), cargo=str(rust190 / "bin/cargo"),
            lean=str(self.output / "verification-tools/lean-4.19.0/bin/lean"))
        for name in ("aarch64", "x86_64", "riscv64"):
            paths["qemu_" + name] = str(self.output / "verification-tools/qemu-8.2.2" / ("qemu-" + name + "-static"))
        require(set(paths) == set(TOOL_HINTS), "14-tool denominator differs")
        results = []
        for name, path in paths.items():
            before = resolved_record(path)
            log = self.step("probe-" + name.replace("_", "-"), [path, "--version"], seconds=30)
            _, raw = file_record(log, body=True, limit=2 << 20)
            text = raw.decode("utf-8", errors="strict")
            if name in ("clang", "clangxx"):
                require(re.search(r"clang version 20\.", text), "Clang version differs")
            elif name == "lld":
                require(re.search(r"LLD 20\.", text), "LLD version differs")
            elif name in ("objdump", "profdata", "readobj"):
                require(re.search(r"LLVM version 20\.", text), "LLVM utility version differs")
            elif name in ("cargo", "rustc"):
                require(text.startswith(name + " 1.90.0 "), "Rust 1.90 version differs")
            require(resolved_record(path) == before, "tool changed during version probe")
            results.append({"check": name, "path": path, "bytes": before["bytes"], "sha256": before["sha256"],
                            "actual_file": before, "version": text, "stdout": file_record(log)})
            self.bindings[before["path"]] = before["sha256"]
        return results

    def final_hints(self, tools, receipts, upstreams):
        hints = {"PYTHON": self.python}
        for row in tools:
            for key in TOOL_HINTS[row["check"]]:
                hints[key] = row["path"]
        by_profile = {x["profile"]: x for x in receipts}
        hints.update(HEPTA_NDU_BUILD=str(Path(by_profile["ranking"]["path"]).parent),
            HEPTA_NDU_BRIDGE=by_profile["ranking"]["binary"]["path"], HEPTA_NDU_UPSTREAM=str(upstreams["ranking"]),
            HEPTA_RAW_MODEL_BUILD=by_profile["raw"]["path"], HEPTA_RAW_MODEL_BRIDGE=by_profile["raw"]["binary"]["path"],
            HEPTA_DYNAMIC_POLICY_MANIFEST=by_profile["dynamic"]["path"], HEPTA_DYNAMIC_POLICY_BINARY=by_profile["dynamic"]["binary"]["path"])
        for profile, prefix in (("recursive", "HEPTA_RECURSIVE_NDU"), ("finite", "HEPTA_FINITE_NDU"), ("stream", "HEPTA_NDU_STREAM")):
            hints[prefix + "_IDENTITY"] = by_profile[profile]["path"]
            hints[prefix + "_BRIDGE"] = by_profile[profile]["binary"]["path"]
            hints[prefix + "_UPSTREAM"] = str(upstreams[profile])
        return hints

    def run(self):
        source_before = None
        try:
            self.workflow = checked_module("_v87_original_workflow", self.source / WORKFLOW_REL, WORKFLOW_SHA)
            self.git = self.executable("git")
            filesystem = os.statvfs(self.output)
            require(filesystem.f_bavail * filesystem.f_frsize >= 8 << 30 and filesystem.f_favail >= 100000,
                    "initial supply storage below unchanged preparation minimum")
            for relative, expected in self.plan["source_pins"].items():
                row = file_record(self.source / relative)
                require(row["sha256"] == expected["sha256"] and row["bytes"] == expected["bytes"], "source input pin differs: " + relative)
            self.report["python"] = {key: resolved_record(self.python)[key] for key in ("bytes", "sha256")}
            self.report["python"]["path"] = self.python
            source_before, before_record = self.exact_source("source-before", self.source,
                expected_head=self.plan["source"]["head"], expected_tree=self.plan["source"]["tree"])
            require(source_before["leaves"] == self.plan["source_leaf_count"], "source leaf denominator differs")
            self.report["source_before"] = before_record
            self.apt_supply()
            self.python_support()
            self.verification_tools()
            rust190 = self.rust190()
            rust195 = self.rust195()
            cargo_home = mkdir(self.output / "cargo-home")
            mkdir(cargo_home / "downloads")
            mkdir(cargo_home / "unpacked")
            cargo_original = self.script.parent / "cargo-cache-archives.original.json"
            cargo = self.operation("cargo-fixed-55", "cargo_vendor", {"original": str(cargo_original), "output": str(cargo_home)},
                                   seconds=600, env=self.network_env)
            self.report["cargo_before"] = self.save("cargo-before.json", cargo)
            upstreams = self.upstream_supply()
            tools_before = self.observe_tools(rust190)
            self.report["fixed_tools"] = tools_before
            receipts = self.builders(rust190, rust195, upstreams, cargo_home)
            self.report["fixture_receipts"] = [{key: x[key] for key in ("profile", "path", "bytes", "sha256")} for x in receipts]
            for row in receipts:
                self.bindings[row["path"]] = row["sha256"]
                self.bindings[row["binary"]["path"]] = row["binary"]["sha256"]
            require(inventory(cargo_home / "vendor") == cargo["immutable_vendor"]
                    and file_record(cargo_home / "config.toml") == cargo["config"], "fixed offline vendor changed")
            for relative, row in cargo["immutable_vendor"].items():
                require(row["kind"] == "file", "unexpected non-file in fixed Cargo vendor")
                self.bindings[str(cargo_home / "vendor" / relative)] = row["sha256"]
            self.bindings[cargo["config"]["path"]] = cargo["config"]["sha256"]
            manifest, manifest_record = read_json(cargo_home / "cargo-cache-archives.json")
            require(manifest_record == cargo["manifest"] and len(manifest["archives"]) == 55, "fresh cache manifest changed")
            for path, sha in manifest["archives"].items():
                row = file_record(path)
                require(row["sha256"] == sha, "fixed crate archive changed")
                self.bindings[path] = sha
            self.report["cargo_after"] = self.save("cargo-after.json", {"archives": {p: file_record(p) for p in manifest["archives"]},
                "vendor": inventory(cargo_home / "vendor"), "config": file_record(cargo_home / "config.toml"),
                "whole_cargo_home_unchanged_claimed": False})
            for name, snapshot in self.upstreams.items():
                after, record = self.exact_source("upstream-after-" + name.replace("_", "-"), snapshot["root"],
                                                 expected_head=snapshot["head"], expected_tree=snapshot["tree"])
                require(after == snapshot, "upstream physical source changed")
                self.bindings[record["path"]] = record["sha256"]
            immutable_paths = {"python-support": self.output / "python-support", "lean": self.output / "verification-tools/lean-4.19.0",
                "qemu": self.output / "verification-tools/qemu-8.2.2", "boost": self.output / "toolchains-boost183",
                "rust190": rust190, "rust195": rust195}
            for name, snapshot in self.immutable.items():
                require(inventory(immutable_paths[name]) == snapshot, "supplied immutable payload changed: " + name)
                for relative, row in snapshot.items():
                    if row["kind"] == "file":
                        self.bindings[str(immutable_paths[name] / relative)] = row["sha256"]
            self.report["immutable_payloads"] = self.save("immutable-payloads.json", {
                "before": self.immutable, "after": {name: inventory(path) for name, path in immutable_paths.items()}})
            for row in tools_before:
                require(resolved_record(row["path"]) == row["actual_file"], "fixed tool changed after fixture builds")
            hints = self.final_hints(tools_before, receipts, upstreams)
            hints_record = create(self.output / "desktop-v87-input-hints.json", wire(hints))
            self.bindings[hints_record["path"]] = hints_record["sha256"]
            self.report.update(hints_path=hints_record["path"], hints_sha256=hints_record["sha256"],
                cargo_home=str(cargo_home), cargo_manifest={"path": manifest_record["path"], "bytes": manifest_record["bytes"],
                    "sha256": manifest_record["sha256"], "archives": 55},
                source_and_supplied_inputs_stable_pending_final_source_read=True)
            self.report["status"] = "INPUTS_BUILT_PENDING_ORIGINAL_PREPARATION"
        except BaseException as error:
            self.report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
            self.report["status"] = "HOLD"
        finally:
            if not self.pending_group:
                try:
                    if source_before is not None:
                        after, record = self.exact_source("source-after", self.source,
                            expected_head=source_before["head"], expected_tree=source_before["tree"])
                        self.report["source_after"] = record
                        require(after == source_before, "complete original source changed during supply")
                    for path, digest in self.bindings.items():
                        require(file_record(path)["sha256"] == digest, "bound supply input changed: " + path)
                    require(file_record(self.script) == self.self_record and file_record(self.configuration) == self.plan_record,
                            "supply controller/configuration changed")
                    self.report["input_bindings"] = dict(self.bindings)
                    self.report["final_readback_complete"] = True
                except BaseException as error:
                    self.report["final_readback_error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
                    self.report["status"] = "HOLD"
            else:
                self.report.update(status="HOLD", final_readback_complete=False,
                    final_readback_omission="started process group or required APT root owner not proven closed; original guardian must establish terminal state")
            self.report["finished_ns"] = time.time_ns()
            self.report["wall_seconds"] = time.monotonic() - self.started
            create(self.output / "SUPPLY.json", wire(self.report))
            print(json.dumps({"schema": SCHEMA, "status": self.report["status"], "report": str(self.output / "SUPPLY.json")}), flush=True)
        return 0 if self.report["status"] == "INPUTS_BUILT_PENDING_ORIGINAL_PREPARATION" else 2


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        return worker_main(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--configuration", type=Path, required=True)
    args = parser.parse_args()
    supply = Supply.__new__(Supply)
    try:
        supply.__init__(args)
    except BaseException as error:
        report = {"schema": SCHEMA, "status": "HOLD", "stage": "INITIALIZATION",
                  "qualification_executed": False, "supply_commands_started": False,
                  "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}}
        if getattr(supply, "output_created", False):
            try:
                create(supply.output / "SUPPLY.json", wire(report))
            except BaseException:
                report["initialization_report_write_error"] = traceback.format_exc()
        print(json.dumps(report, sort_keys=True), flush=True)
        return 2
    return supply.run()


if __name__ == "__main__":
    raise SystemExit(main())
