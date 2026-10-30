"""Reconstruct verified original Git objects; publish only the registered branch."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
HEAD = '3533b95c53d23de2d22c91fcc05cb601b8448eb3'
TREE = '12fae5261a4478645c53e864bc262c1609d2f81d'
BRANCH = "work/hia-p0-p7-integrated-20261030"
REPOSITORY = "TrillionniumFoundation/Hepta"
PACK_SHA256 = 'f887d105ba713cd6528dba33c4433cc9d5fbbec7ebcef56bd9ff609bc0d5dd9b'
PACK_BYTES = 297477
BASES = ['ad23f44abe3e79fb975488c95e164d90126b963f', '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304']
EXPECTED_TARGET = '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304'


def run():
    started = time.monotonic_ns()
    receipt = {"schema": "hepta.git.object-transfer-result.v1", "head": HEAD,
               "tree": TREE, "branch": BRANCH, "repository": REPOSITORY,
               "published": False, "ci_dispatched": False, "commands": []}
    def git(*args, stdin=None):
        start = time.monotonic_ns()
        proc = subprocess.run(["git", *args], stdin=stdin, capture_output=True, check=False)
        receipt["commands"].append({"argv": ["git", *args], "returncode": proc.returncode,
            "stdout": proc.stdout.decode(errors="replace"), "stderr": proc.stderr.decode(errors="replace"),
            "wall_ns": time.monotonic_ns() - start})
        if proc.returncode:
            raise RuntimeError("Git object transfer failed: " + args[0])
        return proc.stdout.decode().strip()
    try:
        manifest = json.loads(MANIFEST.read_text())
        if (manifest["head"] != HEAD or manifest["tree"] != TREE or manifest["target_branch"] != BRANCH
                or manifest["repository"] != REPOSITORY or manifest["bases"] != BASES
                or manifest["expected_target_head"] != EXPECTED_TARGET or manifest["pack_bytes"] != PACK_BYTES
                or manifest["pack_sha256"] != PACK_SHA256 or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY):
            raise ValueError("Registered transfer identity differs")
        pack = Path(os.environ["RUNNER_TEMP"]) / "hepta-original-3533b95.pack"
        digest = hashlib.sha256(); count = 0
        with pack.open("xb") as output:
            for index, row in enumerate(manifest["chunks"]):
                expected_path = f".hia-transfer/3533b95/part-{index:03d}.bin"
                if row["path"] != expected_path or row["offset"] != count:
                    raise ValueError("Chunk inventory/order differs")
                data = (HERE / f"part-{index:03d}.bin").read_bytes()
                blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"] or blob != row["git_blob_sha"]:
                    raise ValueError("Chunk bytes differ")
                output.write(data); digest.update(data); count += len(data)
        if count != PACK_BYTES or digest.hexdigest() != PACK_SHA256:
            raise ValueError("Complete pack bytes differ")
        receipt.update(pack_sha256=digest.hexdigest(), pack_bytes=count, chunks=len(manifest["chunks"]))
        # The published exact base tree is omitted from the pack. Fetch its
        # exact commit; no application source code is executed.
        git("fetch", "--no-tags", "--depth=1", "origin", *BASES)
        with pack.open("rb") as source:
            git("index-pack", "--strict", "--stdin", stdin=source)
        if git("rev-parse", HEAD + "^{tree}") != TREE:
            raise ValueError("Restored source tree differs")
        for base in BASES:
            git("merge-base", "--is-ancestor", base, HEAD)
        for commit in manifest["commits"]:
            if git("cat-file", "-t", commit) != "commit":
                raise ValueError("Missing original commit")
        target = "refs/heads/" + BRANCH
        current = git("ls-remote", "--heads", "origin", target)
        receipt["target_before"] = current or None
        if not current or current.split()[0] not in (EXPECTED_TARGET, HEAD):
            raise ValueError("Target branch appeared or advanced; explicit lease refuses replacement")
        if current.split()[0] != HEAD:
            git("merge-base", "--is-ancestor", EXPECTED_TARGET, HEAD)
            # Atomic expected-head lease; ancestry was independently checked.
            git("push", "--force-with-lease=" + target + ":" + EXPECTED_TARGET, "origin", HEAD + ":" + target)
        if git("ls-remote", "--heads", "origin", target).split()[0] != HEAD:
            raise ValueError("Published branch does not resolve to the original commit")
        receipt["published"] = True
        receipt["original_commit_ids_preserved"] = True
        # GITHUB_TOKEN pushes do not recursively trigger ordinary push jobs.
        # Explicitly request the existing exact-head qualification workflow.
        payload = json.dumps({"ref": BRANCH}).encode()
        request = urllib.request.Request(
            "https://api.github.com/repos/" + REPOSITORY + "/actions/workflows/hepta-qualification.yml/dispatches",
            data=payload, method="POST", headers={"Authorization": "Bearer " + os.environ["HEPTA_TRANSFER_ACTIONS_TOKEN"],
                "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            receipt["dispatch_status"] = response.status
            receipt["ci_dispatched"] = response.status == 204
        if not receipt["ci_dispatched"]:
            raise RuntimeError("Qualification dispatch did not acknowledge")
    except BaseException as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        receipt["wall_ns"] = time.monotonic_ns() - started
        Path("TRANSFER_RESULT_3533b95.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({key: receipt.get(key) for key in ("head", "tree", "published", "ci_dispatched", "wall_ns", "error")}))


if __name__ == "__main__":
    run()
