"""Read-only exact Git source binding for the bounded-read development candidate."""
from hashlib import sha1, sha256
import os
from pathlib import Path
import shutil
import subprocess
from source_common import pin, read, require
from native_support import CANDIDATE, CANDIDATE_TREE

PARENT = "3241be194a817574a0cd08c798981cacb67c4e8d"

def git(source, executable, *arguments):
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "LD_"))
                   and k not in ("GITHUB_TOKEN", "GH_TOKEN")}
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run([str(executable), "--no-replace-objects", *arguments], cwd=source,
        env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=20).stdout

def source_git(source, rows):
    executable = Path(shutil.which("git")).resolve(strict=True)
    _, binary = read(executable, 64 << 20, system_binary=True)
    version = git(source, executable, "--version").decode().strip()
    head = git(source, executable, "rev-parse", "HEAD").decode().strip()
    tree = git(source, executable, "rev-parse", "HEAD^{tree}").decode().strip()
    head_raw, head_record = read(source / ".git/HEAD", 256)
    require(head == CANDIDATE and tree == CANDIDATE_TREE
            and head_raw == (CANDIDATE + "\n").encode(), "exact detached candidate differs")
    raw = git(source, executable, "cat-file", "commit", CANDIDATE)
    require(sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == CANDIDATE,
            "actual commit bytes differ")
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    require([x for x in headers if x.startswith(b"tree ")] == [b"tree " + CANDIDATE_TREE.encode()]
            and [x for x in headers if x.startswith(b"parent ")] == [b"parent " + PARENT.encode()],
            "actual commit parent/tree headers differ")
    tree_raw = git(source, executable, "ls-tree", "-r", "-z", "-l", "HEAD")
    actual = {}
    for item in tree_raw.split(b"\0"):
        if not item:
            continue
        fields, path = item.split(b"\t", 1)
        mode, kind, digest, size = fields.split()
        name = path.decode()
        require(kind == b"blob" and mode in (b"100644", b"100755") and name not in actual,
                "invalid actual tree member")
        actual[name] = {"mode": mode.decode(), "git_blob_sha1": digest.decode(), "size": int(size)}
    expected = {row["path"]: {k: row[k] for k in ("mode", "git_blob_sha1", "size")} for row in rows}
    require(len(actual) == len(expected) == 4025 and actual == expected, "full Git tree differs")
    index = git(source, executable, "ls-files", "--stage", "-z")
    git(source, executable, "diff", "--cached", "--quiet", CANDIDATE_TREE, "--")
    require(git(source, executable, "status", "--porcelain=v1", "--untracked-files=no") == b"",
            "tracked candidate changed")
    require(read(source / ".git/HEAD", 256)[1] == head_record
            and read(executable, 64 << 20, system_binary=True)[1] == binary, "Git observation drifted")
    return {"schema": "hepta.hia.bounded-read-actual-git-source.v1", "head": head, "tree": tree,
            "parents": [PARENT], "detached_HEAD": head_record, "commit": pin(raw),
            "tree_listing": pin(tree_raw), "index_sha256": sha256(index).hexdigest(),
            "tracked_status": "", "tree_members": 4025,
            "git": {"resolved": str(executable), "version": version, "binary": binary},
            "full_filesystem_observation_is_separate": True,
            "formal_full_git_consumer_qualification_claimed": False}
