"""Five finite receiver-only archive controls; no product import or execution."""
import io
import json
from pathlib import Path
import stat
import tarfile
import zipfile

from audit_archive import Originals, pin, save


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def fixture(change=None):
    body = b"zero\0\xff"
    def row(name, kind, mode, size, inode):
        return {"path": name, "kind": kind,
                "identity": [1, inode, mode, 1001, 1001, 1, size, 1234000000000, 1235000000000]}
    rows = [row(".", "directory", stat.S_IFDIR | 0o700, 4096, 10),
            row("fixtures", "directory", stat.S_IFDIR | 0o700, 4096, 11),
            dict(row("fixtures/data.bin", "regular", stat.S_IFREG | 0o600, len(body), 12), **pin(body)),
            dict(row("fixtures/link", "symlink", stat.S_IFLNK | 0o777, 8, 13), target="data.bin"),
            dict(row("fixtures/fifo", "special", stat.S_IFIFO | 0o600, 0, 14),
                 no_open_or_follow_performed=True)]
    manifest = wire({"schema": "hepta.hia.bounded-read-typed-owned-custody.v1", "originals": rows,
                     "all_regular_bytes_preserved": True,
                     "symlinks_and_FIFO_are_typed_metadata": True,
                     "nanosecond_original_identities_preserved_in_manifest": True,
                     "tar_mtime_uses_whole_seconds": True, "direct_extraction_authorized": False})
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for item in rows[1:]:
            t = tarfile.TarInfo(item["path"])
            t.mode, t.uid, t.gid, t.mtime = stat.S_IMODE(item["identity"][2]), 1001, 1001, 1234
            if item["kind"] == "regular":
                raw = b"broken" if change == "regular" else body
                t.size = len(raw)
                archive.addfile(t, io.BytesIO(raw))
            elif item["kind"] == "directory":
                t.type = tarfile.DIRTYPE
                archive.addfile(t)
            elif item["kind"] == "symlink":
                t.type, t.linkname = tarfile.SYMTYPE, "different" if change == "symlink" else "data.bin"
                archive.addfile(t)
            else:
                t.type = tarfile.FIFOTYPE
                archive.addfile(t)
        t = tarfile.TarInfo(".BOUND-CUSTODY-MANIFEST.json")
        t.mode, t.size = 0o400, len(manifest)
        archive.addfile(t, io.BytesIO(manifest))
    typed = out.getvalue()
    receipt = {"schema": "hepta.hia.bounded-read-typed-custody-receipt.v1",
               "status": "EXACT_TYPED_ORIGINALS_RETAINED_NOT_PRODUCT_PASS",
               "archive": {"path": "/original/public/owned-originals.tar", **pin(typed)},
               "manifest": pin(manifest), "members": 5, "original_members": len(rows),
               "regular_original_bytes": len(body), "closed_current_outer_ECHILD": True,
               "no_product_execution": True, "no_special_member_open_or_follow": True}
    if change == "receipt":
        receipt["archive"]["sha256"] = "0" * 64
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../unsafe" if change == "unsafe" else "root/public/owned-originals.tar", typed)
        archive.writestr("root/public/CUSTODY.json", wire(receipt))
    return result.getvalue()


def main():
    root = Path(__file__).resolve().parent / "archive-controls-r1"
    root.mkdir(mode=0o700)
    outcomes = []
    for name in ("valid_regular_symlink_FIFO", "regular", "symlink", "receipt", "unsafe"):
        raw = fixture(None if name == "valid_regular_symlink_FIFO" else name)
        with (root / (name + ".zip")).open("xb") as output:
            output.write(raw)
        caught = None
        try:
            value = Originals(raw)
            value.read_zip()
            actual = value.read_typed()
            assert actual["regular_files"] == 1 and actual["regular_bytes"] == 6
            assert len(value.typed_rows) == 4
        except BaseException as error:
            caught = {"type": type(error).__name__, "message": str(error)}
        passed = (caught is None) == (name == "valid_regular_symlink_FIFO")
        outcomes.append({"id": name, "status": "PASS" if passed else "FAIL",
                         "original": pin(raw), "refusal": caught})
    result = {"scope": "SYNTHETIC_RECEIVER_ONLY_NOT_PRODUCT_OR_RUN_EVIDENCE",
              "schema": "hepta.hia.bounded-read-receiver-local-controls.v1",
              "status": "PASS" if all(r["status"] == "PASS" for r in outcomes) else "HOLD",
              "product_imported": False, "native_executed": False, "cases": outcomes,
              "reader": pin((Path(__file__).resolve().parent / "audit_archive.py").read_bytes())}
    save(root, "REPORT.json", result)
    print(json.dumps(result))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
