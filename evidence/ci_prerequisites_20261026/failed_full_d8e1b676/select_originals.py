"""Select exact run artifacts against immutable Git; no native execution."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--zip", type=Path, required=True)
parser.add_argument("--provider", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--raw-output", type=Path, required=True)
args = parser.parse_args()
provider = json.loads(args.provider.read_text())
artifact, = provider["artifact_metadata"]["artifacts"]
commit = artifact["workflow_run"]["head_sha"]
require(provider["source_commit"] == commit, "provider source differs")
require(not args.output.exists() and not args.raw_output.exists(), "output already exists")
raw_zip = args.zip.read_bytes()
require(len(raw_zip) == artifact["size_in_bytes"] and "sha256:" + sha(raw_zip) == artifact["digest"],
        "provider ZIP digest mismatch")
tree = subprocess.check_output(["git", "ls-tree", "-r", "-z", commit, "--", "artifacts/", "evidence/"], cwd=args.repo)
tracked = {}
for record in tree.split(b"\0"):
    if record:
        info, name = record.split(b"\t", 1)
        mode, kind, blob = info.decode().split()
        require(kind == "blob", "nonblob tracked artifact")
        tracked[name.decode()] = blob
args.output.mkdir(parents=True)
args.raw_output.mkdir(parents=True)
members = []
seen = set()
with zipfile.ZipFile(args.zip) as archive:
    for info in archive.infolist():
        if info.is_dir():
            continue
        name = PurePosixPath(info.filename)
        require(not name.is_absolute() and ".." not in name.parts and "\\" not in info.filename and "\0" not in info.filename
                and str(name) == info.filename and info.filename not in seen, "unsafe/duplicate member")
        seen.add(info.filename)
        kind = name.parts[0]
        require(kind in {"artifacts", "evidence"}, "unexpected root")
        mode = info.external_attr >> 16
        require(stat.S_IFMT(mode) in {0, stat.S_IFREG}, "nonordinary ZIP member")
        item = {"path": info.filename, "bytes": info.file_size, "zip_external_attr": info.external_attr, "kind": kind}
        require(0 <= info.file_size <= 128 * 1024 * 1024, "ZIP member size bound")
        raw = archive.read(info)
        require(len(raw) == info.file_size, "ZIP member size differs")
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        source_blob = tracked.get(info.filename)
        classification = "added_by_run" if source_blob is None else "unchanged_from_source" if blob == source_blob else "changed_by_run"
        item.update(sha256=sha(raw), git_blob_sha1=blob, source_git_blob_sha1=source_blob, classification=classification)
        if classification != "unchanged_from_source":
            dest = args.raw_output / info.filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            dest.chmod(stat.S_IMODE(mode) or 0o644)
            if raw.startswith(b"\x7fELF"):
                item["native_format"] = "ELF"
        members.append(item)
save(args.output / "provider-observation.json", provider)
save(args.output / "zip-identity.json", {
    "artifact_id": artifact["id"], "bytes": len(raw_zip), "sha256": sha(raw_zip),
    "provider_digest": artifact["digest"], "digest_matches": True, "source_commit": commit,
    "public_url": f"https://github.com/TrillionniumFoundation/Hepta/actions/runs/{artifact['workflow_run']['id']}/artifacts/{artifact['id']}"})
save(args.output / "zip-inventory.json", {"source_commit": commit, "members": members})
selected = [item for item in members if item.get("classification") in {"added_by_run", "changed_by_run"}]
native = [item for item in selected if item.get("native_format") == "ELF"]
print(json.dumps({"source_commit": commit, "zip_files": len(members),
    "classes": dict(Counter(item["kind"] + "/" + item["classification"] for item in members)),
    "selected_files": len(selected), "selected_bytes": sum(i["bytes"] for i in selected),
    "elf_files": len(native), "elf_bytes": sum(i["bytes"] for i in native)}, indent=2))
