"""Independent comparison of raw integer timings with duplicate summary types."""
import argparse
from hashlib import sha256
import json

from reproduce import load_archive, module, replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--old-ref", default="61ee1a3f74b37c59387e8bd2ac35e2ef99b15b0e")
    parser.add_argument("--fixed-ref", required=True)
    args = parser.parse_args()
    from pathlib import Path
    directory = Path(args.repository)
    files = load_archive(directory / "review-evidence/hia-ndu-persistent-20261108-5e6c/originals.tar.xz")
    observations = []
    for label, ref in (("old", args.old_ref), ("fixed", args.fixed_ref)):
        mod, source = module(directory, ref, "persistent")
        for field in ("startup", "close", "round"):
            revised = dict(files)
            cells = [json.loads(line) for line in revised["cell-ledger.jsonl"].splitlines()]
            cell = next(row for row in cells if row["arm"] == "persistent_ndu")
            cost = cell["owner_cost"]
            summary = cost["attempts"][0]["transport"] if field == "round" else cost[field]
            summary["wall_ns"] = float(summary["wall_ns"])
            revised["cell-ledger.jsonl"] = b"\n".join(mod.wire(row) for row in cells) + b"\n"
            for row in cells:
                revised["h%02d-p%02d-%s.json" % (row["horizon"], row["pair"], row["arm"])] = mod.wire(row)
            observation = {"version": label, "ref": ref, "case": field + "_summary_only_float",
                           "checker_sha256": sha256(source).hexdigest()}
            try:
                result = replay(mod, source, revised)
                observation.update(accepted=True, nested_cost_intervals_reconciled=result["nested_cost_intervals_reconciled"])
            except ValueError as error:
                observation.update(accepted=False, error=str(error))
            observations.append(observation)
    print(json.dumps({"schema": "hepta.hia.ndu.cost-summary-types-review.v1",
                      "native_processes_started": 0, "observations": observations}, indent=2))
    assert all(row["accepted"] is (row["version"] == "old") for row in observations)


if __name__ == "__main__":
    main()
