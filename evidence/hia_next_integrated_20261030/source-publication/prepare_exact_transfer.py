"""Prepare a hash-bound exact Git object transfer from a published base."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parent / "hepta-integration"


def prepare(base, head):
    if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in (base, head)):
        raise ValueError("exact full commit IDs required")
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=REPO)
    if git("rev-parse", "HEAD").decode().strip() != head or git("status", "--porcelain"):
        raise ValueError("clean exact implementation HEAD required")
    git("merge-base", "--is-ancestor", base, head)
    def tree_objects(commit):
        entries = git("ls-tree", "-r", "-t", "-z", commit).split(b"\0")
        objects = {git("rev-parse", commit + "^{tree}").decode().strip()}
        for row in entries:
            if row:
                objects.add(row.split(b"\t", 1)[0].split()[2].decode())
        return objects
    short = head[:7]
    commits = git("rev-list", "--reverse", head, "^" + base).decode().splitlines()
    known = tree_objects(base) | {base}
    objects = set(commits)
    for commit in commits:
        objects.update(tree_objects(commit))
    objects -= known
    listing, pack = HERE / f"OBJECTS-{short}.txt", HERE / f"objects-{short}.pack"
    with listing.open("x") as stream:
        stream.write("\n".join(sorted(objects)) + "\n")
    started = time.monotonic()
    with listing.open("rb") as source, pack.open("xb") as output:
        subprocess.run(["git", "pack-objects", "--stdout"], cwd=REPO, stdin=source, stdout=output, check=True)
    data = pack.read_bytes()
    tree = git("rev-parse", head + "^{tree}").decode().strip()
    rows = []
    for index, offset in enumerate(range(0, len(data), 8 * 1024 * 1024)):
        chunk = data[offset:offset + 8 * 1024 * 1024]
        rows.append({"path": f".hia-transfer/{short}/part-{index:03d}.bin", "offset": offset,
            "bytes": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest(),
            "git_blob_sha": hashlib.sha1(b"blob " + str(len(chunk)).encode() + b"\0" + chunk).hexdigest()})
    manifest = {"schema": "hepta.git.object-transfer.v1", "repository": "TrillionniumFoundation/Hepta",
        "head": head, "tree": tree, "bases": [base], "target_branch": "work/hia-p0-p7-integrated-20261030",
        "expected_target_head": base, "commits": commits, "objects": len(objects), "pack_bytes": len(data),
        "pack_sha256": hashlib.sha256(data).hexdigest(), "chunks": rows,
        "pack_build_wall_seconds": time.monotonic() - started, "exact_original_commits_preserved": True,
        "objects_derived_only_from_registered_commit_trees": True}
    for prefix in ("TRANSFER", "REMOTE-MANIFEST"):
        with (HERE / f"{prefix}-{short}.json").open("x") as stream:
            json.dump(manifest, stream, indent=2); stream.write("\n")
    source = (HERE / "restore-f7cc872.py").read_text()
    assignments = {"HEAD": head, "TREE": tree, "BASES": [base], "EXPECTED_TARGET": base,
        "PACK_SHA256": manifest["pack_sha256"], "PACK_BYTES": len(data)}
    for name, value in assignments.items():
        source, count = re.subn(r"^" + name + r" = .*$", name + " = " + repr(value), source, flags=re.M)
        if count != 1:
            raise ValueError("unexpected helper template constant: " + name)
    # Match only short path/run labels, never a prefix inside a full Git SHA.
    source = re.sub(r"(?<![0-9a-f])f7cc872(?![0-9a-f])", short, source)
    parsed = ast.parse(source)
    actual = {node.targets[0].id: ast.literal_eval(node.value) for node in parsed.body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in assignments}
    if actual != assignments:
        raise ValueError("helper constants differ from manifest")
    with (HERE / f"restore-{short}.py").open("x") as stream:
        stream.write(source)
    workflow = (HERE / "hepta-object-transfer-f7cc872.yml").read_text().replace("f7cc872", short)
    with (HERE / f"hepta-object-transfer-{short}.yml").open("x") as stream:
        stream.write(workflow)
    return {"head": head, "tree": tree, "base": base, "commits": len(commits), "objects": len(objects),
        "pack_bytes": len(data), "pack_sha256": manifest["pack_sha256"],
        "base_tree": git("rev-parse", base + "^{tree}").decode().strip()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.base, args.head), sort_keys=True))
