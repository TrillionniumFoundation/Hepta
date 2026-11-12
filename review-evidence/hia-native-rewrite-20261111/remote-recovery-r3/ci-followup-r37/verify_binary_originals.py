"""Read immutable proposed evidence blobs; execute no project subject."""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

def main():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.alarm(180)
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    out = Path(os.environ["HIA_CI_OUTPUT"]).resolve()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    source = root / "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci-followup-r37/binary-readback-input.json"
    input_raw = source.read_bytes()
    manifest = json.loads(input_raw)
    git = ["git", "--no-replace-objects", "-c", "core.packedGitWindowSize=16m",
           "-c", "core.packedGitLimit=64m"]
    head = subprocess.check_output(git + ["rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert head == os.environ["GITHUB_SHA"]
    assert subprocess.check_output(git + ["rev-parse", "HEAD~2"], cwd=root, text=True).strip() == manifest["source_content_commit"]
    assert not subprocess.check_output(git + ["status", "--porcelain", "--untracked-files=all"], cwd=root)
    rows = []
    names = set()
    for row in manifest["files"]:
        path = root / row["path"]
        assert path.is_file() and not path.is_symlink() and path.is_relative_to(root)
        assert row["path"] not in names
        names.add(row["path"])
        assert format(path.stat().st_mode, "o") == row["mode"]
        raw = path.read_bytes()
        observed = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            gitsha=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        assert observed == {key: row[key] for key in ("bytes", "sha256", "gitsha")}
        inherited = subprocess.check_output(git + ["rev-parse", manifest["source_content_commit"] + ":" + row["path"]], cwd=root, text=True).strip()
        assert inherited == observed["gitsha"]
        assert path.read_bytes() == raw
        actual = dict(path=row["path"], mode=row["mode"], **observed)
        rows.append(actual)
        print("HIA_BINARY_BLOB_READBACK " + json.dumps(actual, sort_keys=True), flush=True)
    assert len(rows) == 49
    assert source.read_bytes() == input_raw
    assert not subprocess.check_output(git + ["status", "--porcelain", "--untracked-files=all"], cwd=root)
    summary = dict(schema="hia-follow37-immutable-binary-readback-v1", status="PASS_READBACK_ONLY",
        source_head=head, content_commit=manifest["source_content_commit"],
        content_tree=manifest["source_content_tree"], files=rows, total_bytes=sum(x["bytes"] for x in rows),
        all_original_bytes_Git_SHA_SHA256_mode_checked=True, before_after_equal=True,
        project_execution=0, native_entries=0, B3_compiles=0, whole_stack_closed=False,
        wall_ns=time.monotonic_ns() - start)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("HIA_BINARY_FULL_READBACK " + json.dumps(summary, sort_keys=True), flush=True)
    signal.alarm(0)

if __name__ == "__main__":
    main()
