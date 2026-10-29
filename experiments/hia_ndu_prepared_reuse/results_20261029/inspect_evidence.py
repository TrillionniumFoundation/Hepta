#!/usr/bin/env python3
"""Read-only index / JSON-fragment audit; no compiler or experiment execution."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bound_file(base, row):
    path = base / row["path"]
    raw = path.read_bytes()
    if len(raw) != row["bytes"] or digest(raw) != row["sha256"]:
        raise ValueError("File identity mismatch: " + str(path))
    return raw


def reconstruct(index_path):
    index = json.loads(index_path.read_bytes())
    nodes, strings = {}, {}
    for part in index["files"]:
        rows = bound_file(index_path.parent, part).splitlines()
        if len(rows) != part["records"]:
            raise ValueError("Record count mismatch")
        for raw in rows:
            row = json.loads(raw)
            pointer = row["pointer"]
            if row["kind"] == "string_part":
                if row["index"] in strings.setdefault(pointer, {}):
                    raise ValueError("Duplicate string part")
                strings[pointer][row["index"]] = row["value"]
            else:
                if pointer in nodes:
                    raise ValueError("Duplicate pointer")
                nodes[pointer] = row

    def build(pointer):
        row = nodes[pointer]
        kind = row["kind"]
        if kind == "value":
            return row["value"]
        if kind == "object":
            return {key: build(pointer + "/" + str(key).replace("~", "~0").replace("/", "~1"))
                    for key in row["keys"]}
        if kind == "array":
            return [build(pointer + "/" + str(n)) for n in range(row["length"])]
        if kind == "string":
            text = "".join(strings[pointer][n] for n in range(row["parts"]))
            if len(text) != row["characters"]:
                raise ValueError("String length mismatch")
            return text
        raise ValueError("Unknown node kind: " + kind)

    value = build("")
    raw = canonical(value)
    if digest(raw) != index["retained_canonical_sha256"] or len(raw) != index["retained_json_bytes"]:
        raise ValueError("Reconstructed value mismatch: " + str(index_path))
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", nargs=2, metavar=("DATASET", "PATH"))
    args = parser.parse_args()
    index = json.loads((HERE / "INDEX.json").read_bytes())
    values = {}
    for row in index["datasets"]:
        bound_file(HERE, row)
        name = row["path"].split("/")[0]
        values[name] = reconstruct(HERE / row["path"])
    for row in index["supporting_files"]:
        bound_file(HERE, row)
    if args.output:
        name, target = args.output
        Path(target).write_text(json.dumps(values[name], ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"datasets_verified": len(values),
                      "experiments_executed": 0,
                      "dataset_names": list(values)}, sort_keys=True))


if __name__ == "__main__":
    main()
