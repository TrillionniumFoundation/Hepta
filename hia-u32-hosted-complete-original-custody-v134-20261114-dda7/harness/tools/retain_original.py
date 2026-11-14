"""Read and losslessly transport one fixed, completed Actions artifact.

Only standard-library code executes. No product checkout, import, build,
qualification, workflow retry, or mutation of the original run is performed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

REPO = "TrillionniumFoundation/Hepta"
ORIGINAL_RUN = 43579403463
ORIGINAL_HEAD = "de4afa1f7f4cb1fc2d5284965f7f2a7c55632d2a"
ARTIFACT_ID = 14108215158
ARTIFACT_NAME = "u32-frozen-r2-full-43579403463-1"
ORIGINAL_BYTES = 1270286664
ORIGINAL_SHA = "f318593523cc6294e9507aae9ef351d64231a2ead829d325e2e563a96176fb02"
PART_BYTES = 128 << 20
MAX_PARTS = 10
BLOCK = 1 << 20
FREE_FLOOR = 128 << 20
FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def require(value, message):
    if not value:
        raise ValueError(message)


def stamp(value):
    return {key: getattr(value, key) for key in FIELDS}


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def dump(path, value):
    write_new(path, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode())


def safe_name(name):
    require(type(name) is str and name and not name.startswith("/") and "\\" not in name,
            "unsafe ZIP or logical path")
    value = PurePosixPath(name)
    require(".." not in value.parts and value.as_posix() == name.rstrip("/"), "noncanonical path")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(token, reports, *, redirect):
    url = f"https://api.github.com/repos/{REPO}/actions/artifacts/{ARTIFACT_ID}"
    label = "redirect" if redirect else "metadata"
    if redirect:
        url += "/zip"
    dump(reports / (label + ".REQUEST.json"), {
        "url": url, "method": "GET", "credential_scope": "fixed_GitHub_API_only",
        "credential_value_recorded": False, "redirects_followed": False, "automatic_retries": 0})
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "Accept-Encoding": "identity",
        "User-Agent": "hepta-completed-u32-artifact-custodian"})
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=60)
    except urllib.error.HTTPError as error:
        if redirect and error.code == 302:
            location = error.headers.get("Location")
            require(type(location) is str, "missing original artifact Location")
            parsed = urllib.parse.urlsplit(location)
            require(parsed.scheme == "https" and parsed.hostname is not None
                    and parsed.username is None and parsed.password is None
                    and parsed.port in (None, 443) and not parsed.fragment
                    and (parsed.hostname.endswith(".blob.core.windows.net")
                         or parsed.hostname.endswith(".githubusercontent.com")),
                    "unrecognized artifact storage origin")
            dump(reports / "redirect.RESPONSE.json", {
                "status": 302, "provider_origin": parsed.scheme + "://" + parsed.netloc,
                "provider_path": parsed.path, "query_redacted": bool(parsed.query),
                "complete_URL_sha256": hashlib.sha256(location.encode()).hexdigest(),
                "authorization_forwarded": False})
            error.close()
            return location
        raw = error.read(BLOCK + 1)
        write_new(reports / (label + ".ERROR.body"), raw)
        dump(reports / (label + ".ERROR.json"), {"status": error.code,
             "captured_bytes": len(raw), "possibly_truncated": len(raw) > BLOCK})
        error.close()
        raise RuntimeError("fixed original artifact API request failed") from None
    with response:
        require(not redirect and response.status == 200, "unexpected artifact API protocol")
        raw = response.read(BLOCK + 1)
        write_new(reports / "metadata.RESPONSE.json", raw)
        require(len(raw) <= BLOCK, "artifact metadata exceeded capture bound")
    value = json.loads(raw)
    require(value["id"] == ARTIFACT_ID and value["name"] == ARTIFACT_NAME
            and value["size_in_bytes"] == ORIGINAL_BYTES
            and value["digest"] == "sha256:" + ORIGINAL_SHA and value["expired"] is False
            and value["workflow_run"]["id"] == ORIGINAL_RUN
            and value["workflow_run"]["head_sha"] == ORIGINAL_HEAD,
            "original artifact identity differs")
    return value


def receive(location, root, reports):
    free = shutil.disk_usage(root).free
    require(free >= ORIGINAL_BYTES * 2 + (384 << 20) + FREE_FLOOR,
            "custody-only storage floor not met")
    dump(reports / "TRANSFER-INTENT.json", {"expected_bytes": ORIGINAL_BYTES,
         "expected_sha256": ORIGINAL_SHA, "free_bytes_before": free,
         "provider_authorization": False, "provider_redirects": False, "automatic_retries": 0})
    path = root / "original.zip.partial"
    digest = hashlib.sha256()
    git = hashlib.sha1(b"blob " + str(ORIGINAL_BYTES).encode() + b"\0")
    total = 0
    request = urllib.request.Request(location, headers={"Accept-Encoding": "identity"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        require(response.status == 200, "provider returned a partial or redirected response")
        require(response.headers.get("Content-Encoding") in (None, "identity"), "encoded provider transfer")
        length = response.headers.get("Content-Length")
        require(length is None or int(length) == ORIGINAL_BYTES, "provider Content-Length differs")
        dump(reports / "PROVIDER-HEADERS.json", {key: response.headers.get(key) for key in
             ("Content-Length", "Content-Encoding", "Content-Type", "ETag")})
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        with os.fdopen(fd, "wb") as output:
            while True:
                block = response.read(min(BLOCK, ORIGINAL_BYTES + 1 - total))
                if not block:
                    break
                total += len(block)
                require(total <= ORIGINAL_BYTES, "original transfer grew beyond its fixed extent")
                output.write(block)
                digest.update(block)
                git.update(block)
            output.flush()
            os.fsync(output.fileno())
    require(total == ORIGINAL_BYTES and digest.hexdigest() == ORIGINAL_SHA, "original ZIP full hash differs")
    target = root / "original.zip"
    require(not target.exists(), "custody target already exists")
    path.rename(target)
    result = {"bytes": total, "sha256": digest.hexdigest(), "git_blob": git.hexdigest(),
              "stat": stamp(target.stat()), "status": "EXACT_ORIGINAL_ZIP_RECEIVED"}
    dump(reports / "TRANSFER.json", result)
    return target, result


def verify_zip(path, reports):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "original ZIP is not a regular file")
    digest = hashlib.sha256()
    git = hashlib.sha1(b"blob " + str(ORIGINAL_BYTES).encode() + b"\0")
    total = 0
    rows = []
    write_new(reports / "ZIP-MEMBER-STREAM.jsonl", b"")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as raw:
        require(stamp(os.fstat(raw.fileno())) == stamp(before), "original ZIP changed before readback")
        while block := raw.read(BLOCK):
            total += len(block)
            require(total <= ORIGINAL_BYTES, "stored ZIP grew")
            digest.update(block)
            git.update(block)
        require(total == ORIGINAL_BYTES and digest.hexdigest() == ORIGINAL_SHA, "stored ZIP full readback differs")
        raw.seek(0)
        with zipfile.ZipFile(raw) as archive:
            infos = archive.infolist()
            require(len(infos) <= 100000, "unexpected member count")
            require(sum(info.file_size for info in infos) <= 8 << 30, "unexpected total logical member extent")
            names = set()
            for ordinal, info in enumerate(infos):
                safe_name(info.filename)
                require(info.filename not in names and not (info.flag_bits & 1), "duplicate/encrypted ZIP member")
                names.add(info.filename)
                size, crc = 0, 0
                member_sha = hashlib.sha256()
                member_git = hashlib.sha1(b"blob " + str(info.file_size).encode() + b"\0")
                with archive.open(info) as member:
                    while block := member.read(BLOCK):
                        size += len(block)
                        require(size <= info.file_size, "ZIP member grew beyond declared extent")
                        crc = zlib.crc32(block, crc)
                        member_sha.update(block)
                        member_git.update(block)
                require(size == info.file_size and crc & 0xffffffff == info.CRC, "complete ZIP CRC differs")
                rows.append({"ordinal": ordinal, "path": info.filename, "bytes": size,
                    "sha256": member_sha.hexdigest(), "git_blob": member_git.hexdigest(),
                    "crc32": f"{info.CRC:08x}", "compressed_bytes": info.compress_size,
                    "compression": info.compress_type, "external_attr": info.external_attr,
                    "create_system": info.create_system, "flag_bits": info.flag_bits,
                    "date_time": list(info.date_time), "is_directory": info.is_dir()})
                with (reports / "ZIP-MEMBER-STREAM.jsonl").open("ab") as journal:
                    journal.write((json.dumps(rows[-1], sort_keys=True) + "\n").encode())
                    journal.flush()
            dump(reports / "ZIP-MEMBERS.json", rows)
            selected = export_original_reports(archive, rows, reports)
        require(stamp(os.fstat(raw.fileno())) == stamp(before), "original ZIP descriptor changed")
    require(stamp(path.lstat()) == stamp(before), "original ZIP pathname changed")
    result = {"status": "FULL_ORIGINAL_ZIP_SHA_AND_EVERY_MEMBER_CRC_VERIFIED",
              "bytes": total, "sha256": digest.hexdigest(), "git_blob": git.hexdigest(),
              "members": len(rows), "logical_bytes": sum(row["bytes"] for row in rows),
              "original_directories_only_if_present_in_ZIP": True,
              "wrapper_mode_is_not_original_logical_POSIX_mode": True, "selected": selected}
    dump(reports / "ZIP-READBACK.json", result)
    return result


def export_original_reports(archive, members, reports):
    by_name = {row["path"]: row for row in members}
    manifests = [name for name in by_name if PurePosixPath(name).name == "NODE-MANIFEST.json"]
    require(len(manifests) == 1, "original NODE manifest is not unique")
    manifest_name = manifests[0]
    require(by_name[manifest_name]["bytes"] <= 64 << 20, "NODE manifest exceeded report export bound")
    raw = archive.read(manifest_name)
    write_new(reports / "original/NODE-MANIFEST.json", raw)
    records = json.loads(raw)
    require(type(records) is list, "original NODE manifest shape differs")
    prefix = PurePosixPath(manifest_name).parent
    logical = {}
    files = 0
    for record in records:
        safe_name(record["path"])
        require(record["path"] not in logical, "duplicate logical node")
        logical[record["path"]] = record
        if record["kind"] == "file":
            safe_name(record["storage_path"])
            name = (prefix / record["storage_path"]).as_posix()
            require(name in by_name, "manifest file is absent from original ZIP")
            observed = by_name[name]
            require(all(record[key] == observed[key] for key in ("bytes", "sha256", "git_blob")),
                    "logical file bytes do not match original NODE record")
            require(type(record["mode"]) is int and 0 <= record["mode"] <= 0o7777,
                    "invalid recorded logical POSIX mode")
            files += 1
        elif record["kind"] == "symlink":
            target = base64.b64decode(record["target_base64"], validate=True)
            require(hashlib.sha256(target).hexdigest() == record["target_sha256"], "link target digest differs")
    # Preserve every actual top-level terminal/owner file in these original
    # groups, rather than guessing which optional receipts were emitted.
    report_roots = ("scope/evidence/full-qualification-r2/", "evidence/launch/",
                    "evidence/bind/", "evidence/prepare/")
    wanted = sorted(name for name, record in logical.items() if record.get("kind") == "file"
                    and any(name.startswith(root) and "/" not in name[len(root):]
                            for root in report_roots))
    mandatory = {"scope/evidence/full-qualification-r2/OUTER.json",
                 "scope/evidence/full-qualification-r2/OWNER.json",
                 "scope/evidence/full-qualification-r2/qualification.json",
                 "evidence/launch/PROCESS-EXIT.json", "evidence/launch/RESULT.json"}
    require(mandatory <= set(wanted), "mandatory complete original reports are absent")
    require(all(logical[name]["bytes"] <= 64 << 20 for name in wanted),
            "an original report exceeds its complete-copy bound; no truncation")
    require(sum(logical[name]["bytes"] for name in wanted) <= 256 << 20,
            "complete original report set exceeds export bound; no truncation")
    selected = []
    for ordinal, name in enumerate(wanted):
        record = logical[name]
        original_member = (prefix / record["storage_path"]).as_posix()
        value = archive.read(original_member)
        require(all(identity(value)[key] == record[key] for key in ("bytes", "sha256", "git_blob")),
                "selected original report bytes differ")
        output = f"original/selected-{ordinal:02d}-{PurePosixPath(name).name}"
        write_new(reports / output, value)
        selected.append({"logical_path": name, "ZIP_member": original_member,
                         "output": output, "status": "EXACT_ORIGINAL_BYTES", "record": record})
    dump(reports / "SELECTED-ORIGINALS.json", {"manifest_member": manifest_name,
        "manifest_identity": identity(raw), "logical_nodes": len(records),
        "all_manifest_file_identities_verified": files, "reports": selected,
        "no_original_report_reserialization": True, "logical_modes_come_from_original_manifest": True})
    return selected


def transport(path, parts, reports, *, complete):
    before = path.stat()
    require(before.st_size <= PART_BYTES * MAX_PARTS, "original bytes exceed fixed raw-span slots")
    parts.mkdir(exist_ok=False)
    write_new(reports / "SPAN-STREAM.jsonl", b"")
    rows = []
    with path.open("rb") as source:
        offset = 0
        for index in range(MAX_PARTS):
            raw = source.read(PART_BYTES)
            if not raw:
                break
            name = f"part-{index:03d}.bin"
            write_new(parts / name, raw)
            rows.append({"index": index, "path": name, "original_ZIP_offset": offset,
                         "crc32": f"{zlib.crc32(raw) & 0xffffffff:08x}", **identity(raw)})
            with (reports / "SPAN-STREAM.jsonl").open("ab") as journal:
                journal.write((json.dumps(rows[-1], sort_keys=True) + "\n").encode())
                journal.flush()
            offset += len(raw)
        require(source.read(1) == b"", "original raw span inventory incomplete")
    # Independently re-read each stored raw span and compare every byte with
    # its original ZIP offset. No gzip, ZIP repacking, or expanded source copy.
    original_sha = hashlib.sha256()
    original_git = hashlib.sha1(b"blob " + str(before.st_size).encode() + b"\0")
    restored = 0
    with path.open("rb") as original:
        for row in rows:
            require(original.tell() == row["original_ZIP_offset"], "span offset differs")
            with (parts / row["path"]).open("rb") as part:
                digest = hashlib.sha256()
                part_git = hashlib.sha1(b"blob " + str(row["bytes"]).encode() + b"\0")
                total, crc = 0, 0
                while block := part.read(BLOCK):
                    require(original.read(len(block)) == block, "original raw span bytes differ")
                    total += len(block)
                    restored += len(block)
                    digest.update(block)
                    part_git.update(block)
                    crc = zlib.crc32(block, crc)
                    original_sha.update(block)
                    original_git.update(block)
                require(total == row["bytes"] and digest.hexdigest() == row["sha256"]
                        and part_git.hexdigest() == row["git_blob"] and f"{crc & 0xffffffff:08x}" == row["crc32"],
                        "stored raw span changed")
        require(original.read(1) == b"" and restored == before.st_size, "raw span extent differs")
    require(stamp(path.stat()) == stamp(before), "original changed during raw span readback")
    if complete:
        require(restored == ORIGINAL_BYTES and original_sha.hexdigest() == ORIGINAL_SHA, "complete raw transport pin differs")
    result = {"schema": "hepta.exact-original-ZIP-raw-span-transport.v1", "complete_expected_original": complete,
        "original_bytes": restored, "original_sha256": original_sha.hexdigest(),
        "original_git_blob": original_git.hexdigest(), "raw_span_bytes": offset,
        "per_artifact_upload_compression_level": 6,
        "parts": rows, "every_original_ZIP_byte_restored_and_compared": True,
        "original_ZIP_repacking_performed": False,
        "recipe": "Download each independent part artifact; CRC-read its single part-NNN.bin; verify raw part length/SHA/Git/CRC and contiguous original_ZIP_offset; concatenate in index order; verify exact original ZIP length/SHA/Git. Preserve original ZIP member bytes and logical NODE modes; artifact wrapper modes are not original modes."}
    dump(reports / ("TRANSPORT.json" if complete else "PARTIAL-TRANSPORT.json"), result)
    return result


def main():
    root = Path(sys.argv[1])
    require(root.is_absolute() and not root.exists(), "use one new absolute custody directory")
    root.mkdir(parents=True, exist_ok=False)
    reports = root / "reports"
    reports.mkdir()
    result = {"status": "FAIL", "product_executions": 0, "original_run_mutations": 0,
              "qualification_retries": 0, "original_artifact": {"run_id": ORIGINAL_RUN,
              "head_sha": ORIGINAL_HEAD, "id": ARTIFACT_ID, "name": ARTIFACT_NAME,
              "bytes": ORIGINAL_BYTES, "sha256": ORIGINAL_SHA}}
    started = time.monotonic_ns()
    code = 1
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
                "custody is authorized only for the fixed repository and one attempt")
        actual_code = Path(__file__).read_bytes()
        require(hashlib.sha256(actual_code).hexdigest() == os.environ.get("CUSTODY_SCRIPT_SHA256"),
                "custody script differs from the frozen workflow pin")
        dump(reports / "INTENT.json", {"original": result["original_artifact"],
             "script": identity(actual_code), "workflow": {key: os.environ.get(key) for key in
             ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_REF", "GITHUB_REPOSITORY")},
             "no_product_imports_or_execution": True})
        token = os.environ.get("GITHUB_TOKEN")
        require(type(token) is str and token, "read-only Actions token is absent")
        api(token, reports, redirect=False)
        location = api(token, reports, redirect=True)
        original, result["transfer"] = receive(location, root, reports)
        result["readback"] = verify_zip(original, reports)
        result["transport"] = transport(original, root / "parts", reports, complete=True)
        require(Path(__file__).read_bytes() == actual_code, "custody script changed during receipt")
        result["status"] = "EXACT_ORIGINAL_ZIP_CUSTODY_COMPLETE_NO_PRODUCT_EXECUTION"
        code = 0
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
        # Keep a failed transfer as explicitly partial bytes when possible.
        partial = root / "original.zip.partial"
        complete_file = root / "original.zip"
        candidate = complete_file if complete_file.is_file() else partial
        if candidate.is_file() and not (root / "parts").exists():
            try:
                result["failure_custody_transport"] = transport(candidate, root / "parts", reports,
                                                               complete=candidate == complete_file)
            except BaseException as transport_error:
                result["partial_transport_error"] = {"type": type(transport_error).__name__, "message": str(transport_error)}
    finally:
        result.update(exit_code=code, elapsed_ns=time.monotonic_ns() - started)
        dump(reports / "RESULT.json", result)
        print(json.dumps({key: result.get(key) for key in ("status", "exit_code", "elapsed_ns", "product_executions")}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
