"""Independent read-only mutations of retained campaign bytes; never runs NDU."""
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import tarfile
import types
from unittest.mock import patch


def load_archive(path):
    with tarfile.open(path, mode="r:xz") as archive:
        return {member.name: archive.extractfile(member).read()
                for member in archive.getmembers() if member.isfile()}


def module(repository, ref, kind):
    relative = "tools/replay_hia_ndu_" + kind + "_ranker.py"
    source = subprocess.check_output(["git", "show", ref + ":" + relative], cwd=repository)
    result = types.ModuleType("independent_" + kind)
    result.__file__ = "/__independent_frozen_checker__/" + relative
    exec(compile(source, result.__file__, "exec"), result.__dict__)
    return result, source


def replay(mod, source, files):
    root = Path("/__independent_retained_campaign__")
    original_read = Path.read_bytes

    def read(path):
        if path == Path(mod.__file__):
            return source
        if path.is_relative_to(root):
            return files[str(path.relative_to(root))]
        return original_read(path)

    with patch.object(Path, "read_bytes", read):
        return mod.replay(root, sha256(files["registration.json"]).hexdigest())


def mutate(mod, originals, arm, mutation):
    files = dict(originals)
    cells = [json.loads(line) for line in files["cell-ledger.jsonl"].splitlines()]
    cell = next(row for row in cells if row["arm"] == arm)
    name = cell["originals"]["path"]
    events = [json.loads(line) for line in files[name].splitlines()]
    mutation(cell, events)
    raw = b"\n".join(mod.wire(row) for row in events) + b"\n"
    files[name] = raw
    cell["originals"].update(bytes=len(raw), sha256=sha256(raw).hexdigest())
    files["cell-ledger.jsonl"] = b"\n".join(mod.wire(row) for row in cells) + b"\n"
    for row in cells:
        files["h%02d-p%02d-%s.json" % (row["horizon"], row["pair"], row["arm"])] = mod.wire(row)
    return files


def persistent_round(cell, events):
    attempt = cell["owner_cost"]["attempts"][0]
    value = attempt["wall_ns"] + 1
    events[1]["event"]["observation"]["wall_ns"] = value
    attempt["transport"]["wall_ns"] = value


def persistent_startup(cell, events):
    value = cell["owner_cost"]["preparation_wall_ns"] + 1
    events[0]["event"]["observation"]["wall_ns"] = value
    cell["owner_cost"]["startup"]["wall_ns"] = value


def persistent_close(cell, events):
    value = cell["owner_cost"]["close_wall_ns"] + 1
    events[-1]["event"]["observation"]["wall_ns"] = value
    cell["owner_cost"]["close"]["wall_ns"] = value


def persistent_prepared(cell, events):
    events[0]["observation"]["pump"]["wall_ns"] = cell["owner_cost"]["attempts"][0]["wall_ns"] + 1


def prepared(cell, events):
    events[0]["observation"]["pump"]["wall_ns"] = cell["prepared_cost"]["attempts"][0]["wall_ns"] + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ref", default="61ee1a3f74b37c59387e8bd2ac35e2ef99b15b0e")
    parser.add_argument("--expect", choices=("accept", "reject"), required=True)
    args = parser.parse_args()
    persistent, persistent_source = module(args.repository, args.ref, "persistent")
    prepared_mod, prepared_source = module(args.repository, args.ref, "prepared")
    pfiles = load_archive(args.repository / "review-evidence/hia-ndu-persistent-20261108-5e6c/originals.tar.xz")
    qfiles = load_archive(args.repository / "review-evidence/hia-ndu-prepared-20261108-5e6c/final-originals.tar.xz")
    cases = (
        ("persistent_round_gt_service", persistent, persistent_source, pfiles, "persistent_ndu", persistent_round),
        ("persistent_startup_gt_preparation", persistent, persistent_source, pfiles, "persistent_ndu", persistent_startup),
        ("persistent_transport_close_gt_owner_close", persistent, persistent_source, pfiles, "persistent_ndu", persistent_close),
        ("persistent_prepared_pump_gt_service", persistent, persistent_source, pfiles, "prepared_ndu", persistent_prepared),
        ("prepared_pump_gt_service", prepared_mod, prepared_source, qfiles, "prepared_ndu", prepared),
    )
    observations = []
    for label, mod, source, files, arm, mutation in cases:
        row = {"case": label, "checker_sha256": sha256(source).hexdigest()}
        try:
            result = replay(mod, source, mutate(mod, files, arm, mutation))
            row.update(accepted=True, nested_cost_intervals_reconciled=result["nested_cost_intervals_reconciled"])
        except ValueError as error:
            row.update(accepted=False, error=str(error))
        observations.append(row)
    print(json.dumps({"schema": "hepta.hia.ndu.inner-interval-review.v1", "ref": args.ref,
        "expect": args.expect, "native_processes_started": 0, "observations": observations}, indent=2))
    assert all(row["accepted"] is (args.expect == "accept") for row in observations)


if __name__ == "__main__":
    main()
