"""Raw Git tree/blob/mode identity for Core-only qualification inputs.

This is a source-custody check, not native execution or language qualification.
The byte and file-mode checks are preserved from the earlier shared checker,
without importing its removed high-level/migration qualification dispatcher.
"""
from hashlib import sha1, sha256
import os
from pathlib import Path
import re,stat,subprocess
ROOT=Path(__file__).resolve().parents[1]

def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _git(*arguments, root=ROOT):
    # A local refs/replace entry must not reinterpret the commit/blob whose
    # immutable identity is being qualified. This also covers source_state.
    return subprocess.check_output(["git", "--no-replace-objects", *map(str, arguments)], cwd=root)


def _digest_file(path, *, expected_blob=None, expected_mode=None):
    """Hash stable regular bytes, optionally binding them to a raw Git blob."""
    path = Path(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _require(stat.S_ISREG(opened.st_mode), "opened object is not a regular file: " + str(path))
        _require((before.st_dev, before.st_ino, before.st_mode, before.st_size,
                  before.st_mtime_ns, before.st_ctime_ns)
                 == (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns),
                 "file changed before identity read: " + str(path))
        if expected_mode is not None:
            # Git tracks the owner's executable bit, not all POSIX permissions.
            # Do not let core.fileMode=false suppress this identity boundary.
            actual_mode = "100755" if opened.st_mode & stat.S_IXUSR else "100644"
            _require(actual_mode == expected_mode, "source mode differs from raw HEAD tree: " + str(path))
        digest = sha256()
        blob_digest = (sha1(b"blob " + str(opened.st_size).encode("ascii") + b"\0")
                       if expected_blob is not None else None)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            if blob_digest is not None:
                blob_digest.update(chunk)
        after_fd = os.fstat(stream.fileno())
    after = path.lstat()
    signatures = {(v.st_dev, v.st_ino, v.st_mode, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
                  for v in (before, opened, after_fd, after)}
    _require(len(signatures) == 1, "file changed during identity read: " + str(path))
    if blob_digest is not None:
        _require(blob_digest.hexdigest() == expected_blob,
                 "source bytes differ from raw HEAD blob: " + str(path))
    return digest.hexdigest()


def _inventory(tree):
    # The index is not a source of truth: assume-unchanged/skip-worktree can
    # hide modified or missing working bytes even from a clean `git status`.
    # One raw tree listing plus a bounded dual-hash read per file avoids loading
    # all tracked evidence blobs or forking cat-file once per source file.
    # Include directory entries: -r alone hides empty subtrees, including any
    # unsafe paths present in a deliberately constructed raw tree object.
    listing = _git("ls-tree", "-r", "-t", "--full-tree", "-z", tree)
    _require(not listing or listing.endswith(b"\0"), "incomplete raw HEAD tree inventory")
    entries = {}
    for record in listing.split(b"\0")[:-1]:
        metadata, separator, raw_name = record.partition(b"\t")
        fields = metadata.split(b" ")
        _require(separator and len(fields) == 3, "malformed raw HEAD tree member")
        mode, kind, blob = fields
        _require(((mode in {b"100644", b"100755"} and kind == b"blob")
                  or (mode == b"040000" and kind == b"tree"))
                 and re.fullmatch(rb"[0-9a-f]{40}", blob),
                 "raw HEAD tree member must be a directory or regular SHA-1 blob")
        name = raw_name.decode("utf-8")
        _require(name and all(part not in {"", ".", "..", ".git"} for part in name.split("/"))
                 and name not in entries, "unsafe or duplicate raw HEAD tree path")
        entries[name] = (mode.decode("ascii"), blob.decode("ascii"))
    return {name: _digest_file(ROOT / name, expected_mode=mode, expected_blob=blob)
            for name, (mode, blob) in sorted(entries.items()) if mode != "040000"}


def _source_state():
    head = _git("rev-parse", "HEAD").decode().strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", head), "source HEAD must use full SHA-1 identity")
    tree = _git("rev-parse", head + "^{tree}").decode().strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", tree), "source tree must use full SHA-1 identity")
    files = _inventory(tree)
    status = _git("status", "--porcelain", "--untracked-files=all").decode()
    _require(_git("rev-parse", "HEAD").decode().strip() == head,
             "source HEAD changed during identity read")
    return {"head": head, "tree": tree, "status": status, "files": files}
