"""Read only the exact failed 469 CLI artifact; execute no component code."""
from pathlib import Path, PurePosixPath
from hashlib import sha256
import argparse, base64, json, stat, tarfile
EXPECTED_BYTES = 7522140
EXPECTED_SHA256 = "6d03b8ae26f437d3474ba169e0daa8a1561421474ed3ff447d72f52f2ed891e1"
PREFIX = "entry-independent-ci-build-r1/"
WANTED = (
    PREFIX + "generate_hia_cli_entry.py.stdout",
    PREFIX + "generate_hia_cli_entry.py.stderr",
    PREFIX + "summary.json",
)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidates = list(args.download.rglob("evidence.tar.xz"))
    assert len(candidates) == 1, [str(p) for p in candidates]
    archive = candidates[0]
    raw = archive.read_bytes()
    assert (len(raw), sha256(raw).hexdigest()) == (EXPECTED_BYTES, EXPECTED_SHA256)
    args.output.mkdir(parents=True, exist_ok=False)
    matches = {}
    all_names = set()
    members = 0
    with tarfile.open(archive, "r:xz") as handle:
        for item in handle:
            path = PurePosixPath(item.name)
            assert item.isfile() and not path.is_absolute() and ".." not in path.parts
            assert item.name not in all_names
            all_names.add(item.name)
            members += 1
            for suffix in WANTED:
                if item.name.endswith("/" + suffix):
                    assert suffix not in matches
                    content = handle.extractfile(item).read()
                    assert len(content) == item.size
                    destination = args.output / Path(suffix).name
                    destination.write_bytes(content)
                    destination.chmod(stat.S_IMODE(item.mode))
                    assert destination.read_bytes() == content
                    row = dict(member=item.name, bytes=len(content),
                               sha256=sha256(content).hexdigest(), mode=stat.S_IMODE(item.mode),
                               base64=base64.b64encode(content).decode("ascii"),
                               decoded_utf8=content.decode("utf-8", "backslashreplace"))
                    matches[suffix] = row
                    print("HIA_ORIGINAL_NESTED_FILE " + json.dumps(row, ensure_ascii=True, sort_keys=True), flush=True)
    assert members == 6053, members
    assert set(matches) == set(WANTED), sorted(matches)
    assert archive.read_bytes() == raw
    report = dict(status="EXACT_ORIGINAL_FAILURE_READBACK",
                  original_run=43101326649, original_job=130793278379,
                  original_commit="469b31f499289acf5e7dc2e2b6b70a1f06c7bd7b",
                  original_artifact_id=13892287301, archive_bytes=len(raw),
                  archive_sha256=EXPECTED_SHA256, archive_members=members,
                  matched_files=matches, component_execution_count=0,
                  qualification_claim=False)
    (args.output / "readback.json").write_text(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    print("HIA_ORIGINAL_FAILURE_READBACK " + json.dumps({k:v for k,v in report.items() if k != "matched_files"}, sort_keys=True), flush=True)
if __name__ == "__main__":
    main()
