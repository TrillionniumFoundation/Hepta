"""Read an original Actions ZIP and every typed-custody member without extraction.

This program never imports Hepta, invokes a product or changes an original file.
Artifact custody and product success are separate findings. Missing product
outputs remain missing; a HOLD is not repaired by this reader.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
import traceback
import zipfile


CANDIDATE = "ba714f34b8dcb248c779bb5fc0b9538d9151c685"
TREE = "3489d2047956c1481b2e0593e2fbd32cf273cc70"
WORKFLOW_HEAD = "f9a08b4fea10d6a81c52f0345817b7c78359ac72"
BRANCH = "codex/hia-bounded-read-v80-native-installed-r1-run-20261112-e26e"
MANIFEST_NAME = ".BOUND-CUSTODY-MANIFEST.json"


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode()
                                         + b"\0" + raw).hexdigest()}


def safe_name(name, *, directory=False, root=False):
    require(type(name) is str and "\0" not in name and "\\" not in name,
            "invalid archive name")
    if root and name == ".":
        return name
    if directory:
        name = name.rstrip("/")
    require(name and not name.startswith("/")
            and all(p not in ("", ".", "..") for p in name.split("/"))
            and str(PurePosixPath(name)) == name, "non-canonical archive name")
    return name


def json_bytes(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON field")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def save(root, name, value):
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    path = root / name
    with path.open("xb") as output:
        output.write(data)
    require(path.read_bytes() == data, "saved audit differs")
    return {"path": str(path), **pin(data)}


class Originals:
    """An in-memory view of exact artifact members, never an extracted tree."""
    def __init__(self, raw):
        self.raw = raw
        self.zip_rows = []
        self.zip_bytes = {}
        self.typed_rows = []
        self.typed_bytes = {}
        self.typed_manifest = None
        self.tar_pin = None

    def read_zip(self):
        with zipfile.ZipFile(io.BytesIO(self.raw)) as archive:
            require(archive.comment == b"", "unexpected outer ZIP comment")
            seen, total = set(), 0
            for item in archive.infolist():
                name = safe_name(item.filename, directory=item.is_dir())
                require(name not in seen, "duplicate normalized outer ZIP member")
                seen.add(name)
                mode = item.external_attr >> 16
                require(not item.flag_bits & 1 and not stat.S_ISLNK(mode)
                        and (item.is_dir() or stat.S_IFMT(mode) in (0, stat.S_IFREG)),
                        "encrypted/special outer ZIP member")
                total += item.file_size
                require(len(seen) <= 8192 and total <= 512 << 20,
                        "outer ZIP observation budget exceeded")
                raw = archive.read(item)  # Reads all bytes and checks the stored CRC.
                require(len(raw) == item.file_size, "ZIP member extent differs")
                if item.is_dir():
                    require(raw == b"", "ZIP directory body")
                else:
                    self.zip_bytes[name] = raw
                self.zip_rows.append({"path": name, "directory": item.is_dir(),
                    "mode": mode, "create_system": item.create_system,
                    "CRC": item.CRC, "compressed_bytes": item.compress_size,
                    "compression": item.compress_type, **pin(raw)})
        files = set(self.zip_bytes)
        for name in files:
            require(all("/".join(name.split("/")[:i]) not in files
                        for i in range(1, len(name.split("/")))), "ZIP file/parent collision")
        return {"schema": "hepta.hia.independent-original-ZIP-readback.v1",
                "archive": pin(self.raw), "members": self.zip_rows,
                "all_members_read_with_CRC": True, "regular_members": len(files),
                "decoded_bytes": sum(x["bytes"] for x in self.zip_rows),
                "nothing_extracted_or_executed": True}

    def public(self, basename, *, required=True):
        matches = [name for name in self.zip_bytes
                   if name == basename or name.endswith("/public/" + basename)
                   or name == "public/" + basename]
        if not matches and not required:
            return None
        require(len(matches) == 1, "one actual public original required: " + basename)
        return self.zip_bytes[matches[0]]

    def read_typed(self):
        raw = self.public("owned-originals.tar", required=False)
        if raw is None:
            return {"status": "MISSING_TYPED_ARCHIVE", "product_status_changed": False}
        require(len(raw) <= 160 << 20, "typed archive exceeds producer bound")
        self.tar_pin = pin(raw)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            require(len(members) <= 4097, "typed member bound")
            names = [safe_name(m.name, directory=m.isdir()) for m in members]
            require(len(names) == len(set(names)) and MANIFEST_NAME in names,
                    "typed member duplication or missing original manifest")
            manifest_member = next(m for m in members if m.name == MANIFEST_NAME)
            require(manifest_member.isfile() and manifest_member.size <= 16 << 20,
                    "typed manifest type/extent")
            manifest_raw = archive.extractfile(manifest_member).read()
            manifest = json_bytes(manifest_raw)
            require(manifest["schema"] == "hepta.hia.bounded-read-typed-owned-custody.v1"
                    and manifest["all_regular_bytes_preserved"] is True
                    and manifest["symlinks_and_FIFO_are_typed_metadata"] is True
                    and manifest["direct_extraction_authorized"] is False,
                    "typed original manifest schema/scope")
            rows = manifest["originals"]
            expected = {}
            for row in rows:
                name = safe_name(row["path"], root=True)
                require(name not in expected and name != MANIFEST_NAME,
                        "duplicate or reserved original row")
                identity = row["identity"]
                require(type(identity) is list and len(identity) == 9
                        and all(type(x) is int for x in identity), "original identity shape")
                expected[name] = row
            require(expected.get(".", {}).get("kind") == "directory", "root metadata absent")
            represented = {name for name, row in expected.items() if name != "."
                           and (row["kind"] in ("regular", "directory", "symlink")
                                or stat.S_ISFIFO(row["identity"][2]))}
            require(set(names) == represented | {MANIFEST_NAME}, "complete typed namespace differs")
            total = 0
            for member in members:
                if member.name == MANIFEST_NAME:
                    continue
                row = expected[member.name]
                identity = row["identity"]
                require(member.mode == stat.S_IMODE(identity[2])
                        and member.uid == identity[3] and member.gid == identity[4]
                        and member.mtime == identity[7] // 1000000000,
                        "typed member mode/uid/gid/mtime differs: " + member.name)
                require(member.uname == member.gname == "", "unexpected typed user/group name")
                if row["kind"] == "regular":
                    require(member.isfile() and stat.S_ISREG(identity[2])
                            and member.size == row["bytes"] == identity[6],
                            "typed regular type/extent differs")
                    body = archive.extractfile(member).read()
                    require(pin(body) == {k: row[k] for k in pin(body)},
                            "actual typed regular bytes differ: " + member.name)
                    total += len(body)
                    require(total <= 128 << 20, "typed regular-byte producer bound")
                    self.typed_bytes[member.name] = body
                elif row["kind"] == "directory":
                    require(member.isdir() and stat.S_ISDIR(identity[2]) and member.size == 0,
                            "typed directory differs")
                elif row["kind"] == "symlink":
                    require(member.issym() and stat.S_ISLNK(identity[2])
                            and member.linkname == row["target"] and member.size == 0,
                            "typed symlink differs")
                else:
                    require(member.isfifo() and stat.S_ISFIFO(identity[2]) and member.size == 0,
                            "typed FIFO differs")
                self.typed_rows.append(row)
            self.typed_manifest = manifest
        receipt_raw = self.public("CUSTODY.json")
        receipt = json_bytes(receipt_raw)
        require(receipt["schema"] == "hepta.hia.bounded-read-typed-custody-receipt.v1"
                and receipt["status"] == "EXACT_TYPED_ORIGINALS_RETAINED_NOT_PRODUCT_PASS"
                and receipt["closed_current_outer_ECHILD"] is True
                and receipt["no_product_execution"] is True
                and receipt["no_special_member_open_or_follow"] is True,
                "actual typed custody receipt scope differs")
        require(receipt["archive"]["bytes"] == len(raw)
                and receipt["archive"]["sha256"] == self.tar_pin["sha256"]
                and receipt["manifest"] == pin(manifest_raw)
                and receipt["members"] == len(members)
                and receipt["original_members"] == len(rows)
                and receipt["regular_original_bytes"] == total,
                "actual typed custody receipt byte binding differs")
        public_pairs = {"setup.json": "setup.json", "context.json": "context.json",
                        "guardian-request.json": "guard/request.json",
                        "guardian.json": "guard/guardian.json",
                        "TERMINAL-ORIGINALS.json": "TERMINAL-ORIGINALS.json",
                        "EVIDENCE-INVENTORY.json": "EVIDENCE-INVENTORY.json"}
        for public, original in public_pairs.items():
            value = self.public(public, required=False)
            if value is not None:
                require(value == self.typed_bytes[original], "public original copy differs")
        return {"schema": "hepta.hia.independent-typed-custody-readback.v1",
                "status": "ALL_PRESENT_TYPED_ORIGINALS_READBACK_PASS_NOT_PRODUCT_PASS",
                "archive": self.tar_pin, "manifest": pin(manifest_raw),
                "receipt": pin(receipt_raw), "original_rows": rows,
                "actual_members": len(members), "regular_files": len(self.typed_bytes),
                "regular_bytes": total, "no_extraction_or_special_open": True,
                "runtime_identity_fields": "Original manifest values only, not claimed as local stat identities."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--artifact-metadata", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    report = {"schema": "hepta.hia.bounded-read-v80-original-archive-audit.v1",
              "status": "HOLD", "run_id": args.run_id, "artifact_id": args.artifact_id,
              "source_commit": CANDIDATE, "source_tree": TREE,
              "workflow_head": WORKFLOW_HEAD, "product_status": "NOT_YET_OBSERVED",
              "new_product_execution": False, "errors": []}
    try:
        metadata_raw = args.artifact_metadata.read_bytes()
        metadata = json_bytes(metadata_raw)
        raw = args.archive.read_bytes()
        require(metadata["id"] == args.artifact_id and metadata["workflow_run"]["id"] == args.run_id
                and metadata["workflow_run"]["head_sha"] == WORKFLOW_HEAD
                and metadata["workflow_run"]["head_branch"] == BRANCH
                and metadata["size_in_bytes"] == len(raw)
                and metadata["digest"] == "sha256:" + pin(raw)["sha256"],
                "official artifact external seal/operation differs")
        report["external_seal"] = {"actual": pin(raw), "metadata": pin(metadata_raw)}
        originals = Originals(raw)
        report["ZIP"] = save(args.output, "ZIP-INVENTORY.json", originals.read_zip())
        report["typed"] = save(args.output, "TYPED-INVENTORY.json", originals.read_typed())
        final = originals.public("FINAL.json", required=False)
        if final is not None:
            value = json_bytes(final)
            report["original_final"] = pin(final)
            report["product_status"] = value.get("status", "MISSING_STATUS")
            report["original_final_errors"] = value.get("errors")
        report["status"] = ("COMPLETE_ARCHIVE_READBACK_NOT_A_PRODUCT_PASS"
                            if originals.typed_manifest else "OUTER_ARCHIVE_READBACK_TYPED_CUSTODY_MISSING")
        require(args.archive.read_bytes() == raw
                and args.artifact_metadata.read_bytes() == metadata_raw, "original inputs changed")
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error),
                                 "traceback": traceback.format_exc()})
    save(args.output, "ARCHIVE-AUDIT.json", report)
    print(json.dumps({"status": report["status"], "product_status": report["product_status"],
                      "errors": report["errors"]}))
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
