"""Archive raw qualification and tested source without rerunning anything."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import zipfile

raw, source, target = map(Path, sys.argv[1:])
if target.exists():
    raise SystemExit("archive must be create-only")
report = json.loads((raw / "language.json").read_bytes())
paths = [("qualification/" + p.relative_to(raw).as_posix(), p)
         for p in sorted(raw.rglob("*")) if p.is_file()]
for name, digest in report["source_manifest"].items():
    path = source / name
    if sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit("source differs from original report: " + name)
    paths.append(("source/" + name, path))
review = source / "review-evidence/hia-824-pump-language-review-20261109"
paths.extend(("review/" + p.name, p) for p in sorted(review.iterdir()) if p.is_file())
for name in ("tools/measure_hia_scalar_controller_controls.py",
             "tests/test_hia_scalar_controller_controls.py", ".github/workflows/hia-sixgap-source.yml"):
    paths.append(("source/" + name, source / name))
identities = {}
with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for name, path in paths:
        data = path.read_bytes()
        identities[name] = {"bytes": len(data), "sha256": sha256(data).hexdigest()}
        archive.writestr(name, data)
    archive.writestr("FILES.json", json.dumps(identities, indent=2, sort_keys=True) + "\n")
with zipfile.ZipFile(target) as archive:
    if archive.testzip() is not None:
        raise SystemExit("CRC mismatch")
    manifest = json.loads(archive.read("FILES.json"))
    for name, expected in manifest.items():
        data = archive.read(name)
        if len(data) != expected["bytes"] or sha256(data).hexdigest() != expected["sha256"]:
            raise SystemExit("member identity mismatch: " + name)
    members = len(archive.namelist())
print(json.dumps({"file": str(target), "bytes": target.stat().st_size,
    "sha256": sha256(target.read_bytes()).hexdigest(), "members": members,
    "crc_pass": True, "all_member_sha256_pass": True}, sort_keys=True))
