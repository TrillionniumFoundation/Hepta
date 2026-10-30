"""Transfer only new objects from the published delivery, with an older ref lease.

The previous evidence delivery already exists remotely. Reuse those immutable
objects while advancing only the authorized implementation branch by ancestry.
No main branch, old delivery branch, or repository setting is changed.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TRANSFER = ROOT / "hia-github-publication-20261030"
REPO = ROOT / "hepta-integration"
sys.path.insert(0, str(TRANSFER))
from prepare_exact_transfer import prepare


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    for value in (args.base, args.expected_target, args.head):
        if re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise ValueError("full original commit IDs required")
    subprocess.run(["git", "--no-replace-objects", "merge-base", "--is-ancestor",
                    args.expected_target, args.base], cwd=REPO, check=True)
    ancestry = subprocess.check_output(["git", "--no-replace-objects", "rev-list", "--ancestry-path",
                                        args.base, "^" + args.expected_target], cwd=REPO).splitlines()
    # Fetching both commits at depth 1 can leave the newer base marked shallow,
    # hiding the older target from merge-base even when its object is present.
    # Preserve the entire registered interval used for the fast-forward lease.
    fetch_depth = len(ancestry) + 1
    if not 1 <= fetch_depth <= 1024:
        raise ValueError("registered shallow ancestry interval is too large")
    summary = prepare(args.base, args.head)
    short = args.head[:7]
    bases = list(dict.fromkeys([args.base, args.expected_target]))
    for prefix in ("TRANSFER", "REMOTE-MANIFEST"):
        path = TRANSFER / f"{prefix}-{short}.json"
        value = json.loads(path.read_bytes())
        value.update(bases=bases, expected_target_head=args.expected_target,
                     object_delta_base=args.base,
                     base_fetch_depth=fetch_depth,
                     transfer_scope="new implementation objects; previously published delivery reused by exact identity")
        path.write_text(json.dumps(value, indent=2) + "\n")
    path = TRANSFER / f"restore-{short}.py"
    source = path.read_text()
    expected = {"BASES": bases, "EXPECTED_TARGET": args.expected_target}
    for name, value in expected.items():
        source, count = re.subn(r"^" + name + r" = .*$", name + " = " + repr(value), source, flags=re.M)
        if count != 1:
            raise ValueError("helper constant is not unique: " + name)
    anchor = 'git("fetch", "--no-tags", "--depth=1", "origin", *BASES)'
    if source.count(anchor) != 1:
        raise ValueError("helper fetch anchor differs")
    source = source.replace(anchor, 'git("fetch", "--no-tags", "--depth=' + str(fetch_depth) + '", "origin", *BASES)')
    actual = {node.targets[0].id: ast.literal_eval(node.value)
              for node in ast.parse(source).body
              if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id in expected}
    if actual != expected:
        raise ValueError("registered lease/fetch constants differ")
    path.write_text(source)
    summary.update(expected_target=args.expected_target, fetched_bases=bases,
                   base_fetch_depth=fetch_depth,
                   target_branch="work/hia-p0-p7-integrated-20261030",
                   qualification_requested=True,
                   helper_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    output = TRANSFER / f"PREPARE-IMPLEMENTATION-{short}.json"
    with output.open("x") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
