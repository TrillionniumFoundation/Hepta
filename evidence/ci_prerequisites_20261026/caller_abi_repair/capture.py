#!/usr/bin/env python3
"""Capture fixed Git objects and encode already completed caller probes once."""
import argparse
import base64
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile

BASE = "44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314"
ATTEMPTS = {"composed_5b1eb709": ("composed", "5b1eb7096062a9b8619aadbeafa06d7bc9c568cb"),
            "owned_a1ade3cc": ("owned", "a1ade3cc2bf4a3b3eabd87f82ba6c8c515215e49")}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def capture(repo, raw, output):
    bindings = []
    def bind(commit, name, member):
        data = git(repo, "show", commit + ":" + name)
        path = raw / member
        if path.exists():
            assert path.read_bytes() == data
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        bindings.append({"commit": commit, "git_path": name, "archive_path": member,
                         "bytes": len(data), "sha256": sha(data), "git_blob_sha1": blob})
    for label, (kind, commit) in ATTEMPTS.items():
        report = json.loads((raw / label / "probe/report.json").read_bytes())
        assert report["source_before"] == report["source_after"]
        assert report["source_before"]["commit"] == commit and report["baseline_commit"] == BASE
        captured = set()
        for name, identity in report["source_before"]["files"].items():
            member = label + "/probe/inputs/" + name.replace("/", "__")
            bind(commit, name, member)
            assert bindings[-1]["bytes"] == identity["bytes"] and bindings[-1]["sha256"] == identity["sha256"]
            captured.add(name)
        harness = "examples/cpp/" + kind + "_migration/harness.c"
        qualifier = "tools/qualify_cpp_" + kind + "_llvm.py"
        bind(BASE, harness, label + "/probe/legacy/harness.c")
        bind(BASE, qualifier, label + "/probe/inputs/legacy-qualifier.py")
        bind(commit, harness, label + "/probe/fixed/harness.c")
        for name in git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit).decode().splitlines():
            if name not in captured:
                bind(commit, name, label + "/source/" + name)
        (raw / label / "commit.diff").write_bytes(git(repo, "show", "--format=raw", "--no-ext-diff", "--no-color", "--no-renames", "--binary", commit))
    commits = {}
    for commit in sorted({row["commit"] for row in bindings}):
        body = git(repo, "cat-file", "commit", commit)
        root = body.splitlines()[0].decode().split()[1]
        paths = {"": root}
        for record in git(repo, "ls-tree", "-d", "-r", "-z", commit).split(b"\0"):
            if record:
                header, name = record.split(b"\t", 1)
                paths[name.decode()] = header.decode().split()[2]
        ancestors = {""}
        for row in bindings:
            if row["commit"] != commit:
                continue
            path = PurePosixPath(row["git_path"]).parent
            while str(path) != ".":
                ancestors.add(str(path)); path = path.parent
        commits[commit] = {"root_tree": root, "commit_object_base64": base64.b64encode(body).decode(),
            "tree_objects_base64": {oid: base64.b64encode(git(repo, "cat-file", "tree", oid)).decode()
                                    for oid in sorted({paths[name] for name in ancestors})}}
    save(output / "source-proof.json", {"schema": "hepta.caller-abi.git-proof.v1", "commits": commits, "bindings": bindings})
    buffer = io.BytesIO(); members = []
    with tarfile.open(fileobj=buffer, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(raw.rglob("*")):
            if path.is_dir():
                continue
            assert path.is_file() and not path.is_symlink()
            data = path.read_bytes(); name = path.relative_to(raw).as_posix()
            mode = stat.S_IMODE(path.stat().st_mode)
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = mode
            info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
            members.append({"path": name, "bytes": len(data), "sha256": sha(data), "mode": mode})
    tar = buffer.getvalue()
    packed = lzma.compress(tar, format=lzma.FORMAT_XZ, preset=6)
    encoded = base64.b64encode(packed) + b"\n"
    assert len(encoded) <= 3_500_000
    name = "caller-originals.tar.xz.b64"
    with (output / name).open("xb") as stream:
        stream.write(encoded)
    manifest = {"schema": "hepta.caller-abi.archive.v1", "archive": name, "encoding": "base64",
        "compression": "xz-preset-6-default-dictionary", "encoded_bytes": len(encoded), "encoded_sha256": sha(encoded),
        "decoded_bytes": len(packed), "decoded_sha256": sha(packed), "tar_bytes": len(tar), "tar_sha256": sha(tar),
        "member_count": len(members), "uncompressed_bytes": sum(row["bytes"] for row in members), "members": members}
    save(output / "archive.manifest.json", manifest)
    return {"members": len(members), "raw_bytes": manifest["uncompressed_bytes"], "encoded_bytes": len(encoded),
            "git_commits": len(commits), "git_source_bindings": len(bindings)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(capture(args.repo, args.raw, args.output), indent=2, sort_keys=True))
