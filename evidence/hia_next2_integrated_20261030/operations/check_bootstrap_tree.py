"""Recompute the entire remote transfer tree from immutable base objects."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "hepta-integration"


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--entries", type=Path, required=True)
    parser.add_argument("--expected-tree")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    nodes = {}
    def place(name, mode, sha):
        parts = name.split("/")
        if any(p in ("", ".", "..", ".git") for p in parts):
            raise ValueError("unsafe tree member")
        parent = nodes
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
            if not isinstance(parent, dict):
                raise ValueError("directory conflicts with blob")
        parent[parts[-1]] = (mode, sha)
    original = subprocess.check_output(["git", "--no-replace-objects", "ls-tree", "-r", "-z", args.base], cwd=REPO)
    count = 0
    for row in original.split(b"\0")[:-1]:
        metadata, raw_name = row.split(b"\t", 1)
        mode, kind, sha = metadata.decode().split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("unexpected base member")
        place(raw_name.decode(), mode, sha)
        count += 1
    additions = json.loads(args.entries.read_bytes())
    for row in additions:
        if row["type"] != "blob" or ("sha" in row) == ("content" in row):
            raise ValueError("exactly one blob identity or content required")
        place(row["path"], row["mode"], row.get("sha") or blob(row["content"].encode()))
    def tree(values):
        payload = bytearray()
        for name, value in sorted(values.items(), key=lambda item: item[0].encode() + (b"/" if isinstance(item[1], dict) else b"")):
            mode, sha = ("40000", tree(value)) if isinstance(value, dict) else value
            payload += mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha)
        return hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    computed = tree(nodes)
    if args.expected_tree is not None and computed != args.expected_tree:
        raise ValueError("complete bootstrap tree differs from remote")
    receipt = {"schema": "hepta.exact-bootstrap-tree-readback.v1", "base": args.base,
               "base_files": count, "additions": len(additions), "tree": computed,
               "remote_tree": args.expected_tree, "matches": computed == args.expected_tree if args.expected_tree else None,
               "entries_sha256": hashlib.sha256(args.entries.read_bytes()).hexdigest(),
               "base_source_blobs_and_modes_preserved": True}
    with args.output.open("x") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
