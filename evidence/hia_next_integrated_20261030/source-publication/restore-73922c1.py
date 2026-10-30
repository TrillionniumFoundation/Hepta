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
HEAD = "73922c1a3971125dfb9703555e50e5cf6444e842"
TREE = "018f96450cb4f804d08383884986a57481fe85ee"
BRANCH = "work/hia-p0-p7-integrated-20261030"
REPOSITORY = "TrillionniumFoundation/Hepta"
PACK_SHA256 = "d560acd129b4be3eae25923ed580020c308bda265f35a11a7b1f0d5915c1bf1d"
PACK_BYTES = 80949501
BASES = ["95a67fb487da981e1941ec0d44c7f4305a22e6d6", "2cc9fb3b92a7306d2f5aae316c99e8364be700f9"]


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
                or manifest["expected_target_head"] is not None or manifest["pack_bytes"] != PACK_BYTES
                or manifest["pack_sha256"] != PACK_SHA256 or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY):
            raise ValueError("Registered transfer identity differs")
        pack = Path(os.environ["RUNNER_TEMP"]) / "hepta-original-73922c1.pack"
        digest = hashlib.sha256(); count = 0
        with pack.open("xb") as output:
            for index, row in enumerate(manifest["chunks"]):
                expected_path = f".hia-transfer/73922c1/part-{index:03d}.bin"
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
        # The two reviewed parent trees are the only objects omitted from the
        # pack. Fetch these public exact commits; no source code is executed.
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
        if current and current.split()[0] != HEAD:
            raise ValueError("Target branch appeared or advanced; explicit lease refuses replacement")
        if not current:
            # Empty expected ref is an atomic creation lease, not permission
            # to replace an existing branch, force main or rewrite history.
            git("push", "--force-with-lease=" + target + ":", "origin", HEAD + ":" + target)
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
        Path("TRANSFER_RESULT_73922c1.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({key: receipt.get(key) for key in ("head", "tree", "published", "ci_dispatched", "wall_ns", "error")}))


if __name__ == "__main__":
    run()
