"""Run the frozen LM campaign and retain whole-child CPU/wall/RSS plus failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    paths = {name: Path(str(args.prefix) + suffix) for name, suffix in
             (("raw", "-raw.json"), ("stdout", "-stdout.log"),
              ("stderr", "-stderr.log"), ("cost", "-process-cost.json"))}
    if any(path.exists() for path in paths.values()):
        parser.error("Refusing to overwrite campaign outputs")
    paths["raw"].parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "research.hcsn.round2_causal_lm", "--output", str(paths["raw"])]
    environment = dict(os.environ, OMP_NUM_THREADS="1", MKL_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1")
    start = time.perf_counter()
    with paths["stdout"].open("x") as out, paths["stderr"].open("x") as err:
        result = subprocess.run(command, env=environment, stdout=out, stderr=err)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = {"command": command, "returncode": result.returncode,
              "wall_seconds": time.perf_counter() - start,
              "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
              "maximum_resident_set_bytes": usage.ru_maxrss * 1024,
              "minor_page_faults": usage.ru_minflt, "major_page_faults": usage.ru_majflt,
              "scope": "entire sole child including imports, corpus loading, training, diagnostics, evaluation, generation and serialization",
              "runner_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with paths["cost"].open("x") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(record))
    raise SystemExit(result.returncode)
