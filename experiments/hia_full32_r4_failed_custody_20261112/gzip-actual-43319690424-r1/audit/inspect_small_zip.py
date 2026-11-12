"""Read bounded current small artifact; preserve every whole original, no execution."""
import argparse
import binascii
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

def require(value, message):
    if not value: raise ValueError(message)

def document(raw):
    def pairs(items):
        d = {}
        for k, v in items:
            require(k not in d, "duplicate JSON key")
            d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=pairs)

def wire(v): return (json.dumps(v, sort_keys=True, indent=2) + "\n").encode()

def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view); require(n > 0, "output write incomplete"); view = view[n:]
        os.fsync(fd)
    finally: os.close(fd)

def main():
    a = argparse.ArgumentParser(); a.add_argument("--zip", type=Path, required=True)
    a.add_argument("--bytes", type=int, required=True); a.add_argument("--sha256", required=True)
    a.add_argument("--output", type=Path, required=True); args = a.parse_args()
    require(args.output.is_dir() and not any(args.output.iterdir()), "new empty consumer directory required")
    before = args.zip.stat(); digest = hashlib.sha256()
    with args.zip.open("rb") as f:
        while block := f.read(1048576): digest.update(block)
    require(before.st_size == args.bytes and digest.hexdigest() == args.sha256, "official small ZIP external seal differs")
    output = args.output / "flat"; output.mkdir(mode=0o700)
    rows = []; bodies = {}; total = 0
    with zipfile.ZipFile(args.zip) as z:
        infos = z.infolist(); require(1 <= len(infos) <= 4128, "small actual member count exceeds bound")
        seen = set()
        for info in infos:
            name = info.filename; path = PurePosixPath(name)
            require(name not in seen and name == path.as_posix() and len(path.parts) == 1
                    and path.parts[0] not in (".", "..") and not path.is_absolute()
                    and "\\" not in name and "\x00" not in name,
                    "small ZIP member is duplicate or non-flat")
            seen.add(name)
            mode = info.external_attr >> 16
            require(not info.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and info.flag_bits & 1 == 0 and info.compress_type in (0, 8),
                    "small member has unexpected type/encryption/compression")
            require(0 <= info.file_size <= 64 << 20 and total + info.file_size <= 224 << 20,
                    "small original expansion exceeds fixed bound")
            total += info.file_size
            sha = hashlib.sha256(); crc = 0; count = 0
            target = output / name; fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with z.open(info) as source:
                    while block := source.read(1048576):
                        count += len(block); require(count <= info.file_size, "ZIP body exceeds directory size")
                        sha.update(block); crc = binascii.crc32(block, crc)
                        view = memoryview(block)
                        while view:
                            n = os.write(fd, view); require(n > 0, "small body write incomplete"); view = view[n:]
                os.fsync(fd)
            finally: os.close(fd)
            require(count == info.file_size and crc & 0xffffffff == info.CRC, "whole small CRC or size differs")
            reread = target.read_bytes(); require(len(reread) == count and hashlib.sha256(reread).hexdigest() == sha.hexdigest(), "small independent copy readback differs")
            row = {"name": name, "bytes": count, "sha256": sha.hexdigest(), "crc32": "%08x" % info.CRC,
                   "local": str(target), "complete_original_body": True}
            rows.append(row); bodies[name] = row
    after = args.zip.stat()
    require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), "small source identity changed")
    def raw(name): return (output/name).read_bytes()
    def doc(name): return document(raw(name))
    final = doc("FINAL.json"); context = doc("current--context.json"); setup = doc("current--setup.json")
    require(context["run_id"] == "43319690424" or context["run_id"] == 43319690424, "current run identity differs")
    require(context["actual_workflow_commit"] == "7e73762961b4bef8a1095cae34645c29a7072df7"
            and context["actual_control_checkout"] == "1b8c0df93d0e4295deef842db71482173ebd99b4"
            and context["policy_sha256"] == "844b1a0c739469d3b0d15b450b5c07a1e722f1d45a5beeb3cfa4599b80d77d42"
            and final["context"] == context, "exact current A/B/policy context differs")
    require(final["artifact"]["id"] == 13982129929 and final["artifact"]["bytes"] == 3010752230
            and final["artifact"]["sha256"] == "4f5b0439a47f873e90fb6382c0232d9e3ae99b0dd05eb5b5e01132eeec4c9380",
            "original failed artifact identity differs")
    for record in final["captured_controls"]:
        name = "current--" + record["name"].replace("/", "--")
        actual = bodies[name]
        require(actual["bytes"] == record["original"]["bytes"] and actual["sha256"] == record["original"]["sha256"], "current captured control changed")
        matches = [x for x in record["copies"] if x["path"].endswith("/small/" + name)]
        require(len(matches) == 1 and matches[0]["bytes"] == actual["bytes"] and matches[0]["sha256"] == actual["sha256"], "current small original copy not bound")
    guardian = doc("current--guard--guardian.json"); request_raw = raw("current--guard--request.json"); request = document(request_raw)
    life = guardian["lifecycle"]; cleanup = life["cleanup"]
    require(request == {"schema":"hia-external-guardian-request.v1", "controller_seconds":900,
            "command":setup["command"], "cwd":guardian["cwd"], "source_identities":setup["source_identities"]}
            and hashlib.sha256(request_raw).hexdigest() == setup["guardian_config_sha256"], "current guardian exact request differs")
    require(guardian["schema"] == "hepta.hia.external-qualification-guardian.v1"
            and guardian["command"] == setup["command"] and guardian["external_controller_seconds"] == 900
            and guardian["cold_180_second_gate_modified"] is False
            and guardian["lifecycle_implementation_sha256"] == "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
            and guardian["source_identities_before"] == setup["source_identities"]
            and life["schema"] == "hepta.hia.external-qualification-guardian.v1.lifecycle"
            and life["qualification_seconds"] == 900 and life["cleanup_seconds"] == 3
            and life["qualification_started"] is True and life["subreaper_enabled"] is True,
            "current original guardian implementation and limits differ")
    closed = (cleanup["complete"] is True and cleanup["observed_echild"] is True
              and cleanup["leader_reaped"] is True and cleanup["deadline_exceeded"] is False
              and cleanup["remaining_direct_children"] == [] and cleanup["errors"] == [])
    require(closed, "current original guardian is not closed")
    for name in ("child.stdout.log", "child.stderr.log"):
        require(guardian["logs"][guardian["cwd"] + "/guard/" + name] == bodies["current--guard--" + name]["sha256"], "current original child log differs")
    selected = []; critical = []; historical = {}
    if "INDEX.json" in bodies:
        index = doc("INDEX.json")
        for row in index.get("originals", []):
            actual = bodies[row["saved"]]
            require(actual["bytes"] == row["actual"]["bytes"] and actual["sha256"] == row["actual"]["sha256"], "selected original differs from original index")
            selected.append({**row, "consumer": actual})
            if row["path"].endswith(("/SUPPLY.json", "/FINAL.json", "/CUSTODY.json", "/ARCHIVE.json")) or row["path"] in ("supply/SUPPLY.json", "RUN-INTENT.json"):
                try: historical[row["scope"] + ":" + row["path"]] = doc(row["saved"])
                except (ValueError, UnicodeError): pass
        critical = index.get("critical_originals", [])
    audit = {"schema":"hia.full32-r4.small-actual-readback.v1", "status":"BOUNDED_SMALL_ORIGINALS_INDEPENDENTLY_READ",
             "small_zip":{"path":str(args.zip),"bytes":args.bytes,"sha256":args.sha256},
             "current_transport_status":final["status"], "current_transport_complete":final["complete_local_multipart_readback"],
             "current_guardian_closed":closed,"current_guardian_status":guardian["status"],
             "current_guardian_returncode":life["returncode"],"originals":rows,"total_original_bytes":total,
             "selected_originals":selected,"critical_originals":critical,"historical_summary_documents":historical,
             "current_errors":final.get("errors"), "current_small_diagnostics":final.get("small_diagnostics"),
             "all_10_range_payloads_received":False, "full_failed_original_ZIP_restored":False,
             "historical_qualification_reclassified":False,"product_reexecuted":False}
    save(args.output/"SMALL-READBACK.json",wire(audit))
    print(json.dumps({"status":audit["status"],"files":len(rows),"bytes":total,"selected":len(selected),
                      "current_transport_status":final["status"],"current_returncode":life["returncode"],
                      "current_errors":final.get("errors"),"historical_keys":list(historical)}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
