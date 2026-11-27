"""Reproduce the native source construction and cold qualification from Git.

The checked-in seven native bootstrap roots are explicit trust inputs, not an
inherited qualification. Current HIA construction rebuilds the toolchain,
physically exports the source-only domain, and executes every native cold
phase under the existing 180+3 second owner. This host script is development
orchestration and is never included in the native source export.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import os
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.hia_native_cold_admission import admit_native_report, read_json
from tools.hia_native_cold_chain import regular
from tools.hia_native_cold_preseed import ROOT_NAMES


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def replay(output):
    if sys.flags.optimize:
        raise ValueError("native qualification requires enabled development assertions")
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("native cold qualification requires Linux x86-64")
    requested = Path(output).absolute()
    if any(path.is_symlink() for path in (requested, *requested.parents)):
        raise ValueError("native cold output cannot use symbolic links")
    if requested.exists():
        raise ValueError("native cold qualification requires a new report path")
    directory = requested.with_suffix(".native-cold")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GIT_OPTIONAL_LOCKS="0")
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT,
                                   env=environment, text=True, timeout=20).strip()
    subprocess.run(["/usr/bin/git", "diff", "--exit-code", "HEAD", "--"], cwd=ROOT,
                   env=environment, check=True, timeout=30, stdout=subprocess.DEVNULL)
    report = {"schema": "hepta.hia.native-cold-development-campaign.v1", "passed": False,
              "source_head": head, "source": str(ROOT), "calls": [],
              "whole_native_delivery_qualified": False, "whole_stack_rewritten_in_hia": False,
              "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3}

    def save():
        (directory / "campaign.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    def invoke(label, script, arguments):
        command = [sys.executable, "-I", "-B", str(ROOT / "tools" / script), *map(str, arguments)]
        row = {"label": label, "argv": command, "script": pin(regular(ROOT / "tools" / script))}
        report["calls"].append(row)
        save()
        started = time.monotonic_ns()
        with (directory / (label + ".stdout")).open("xb") as out, \
                (directory / (label + ".stderr")).open("xb") as err:
            child = subprocess.run(command, cwd=ROOT, env=environment, stdout=out, stderr=err)
        row.update(returncode=child.returncode, wall_elapsed_ns=time.monotonic_ns() - started,
                   stdout=pin((directory / (label + ".stdout")).read_bytes()),
                   stderr=pin((directory / (label + ".stderr")).read_bytes()))
        save()
        print("NATIVE_COLD_DEVELOPMENT_STEP", label, child.returncode, flush=True)
        if child.returncode != 0:
            raise RuntimeError("native cold stage failed; original evidence retained: " + label)

    try:
        from tools.hia_release_contract import validate_release_contract, source_domain
        contract = validate_release_contract(ROOT)
        if source_domain(contract) != "native":
            raise ValueError("native cold entry requires an explicitly native source contract")
        from tools.hia_selfhost_contract import CONTRACT_PATH
        sources = {**contract["source_identity"]["files"],
                   CONTRACT_PATH: sha256(regular(ROOT / CONTRACT_PATH)).hexdigest()}
        distribution = ROOT / "native/bootstrap/linux-x86_64"
        manifest_raw = regular(distribution / "manifest.json")
        manifest = read_json(manifest_raw)
        if (manifest.get("schema") != "hepta.hia.native-bootstrap-distribution.v1"
                or manifest.get("target") != "linux-x86_64"
                or set(manifest["executables"]) != {*ROOT_NAMES, "hia-cold-build"}):
            raise ValueError("invalid explicit native bootstrap distribution")
        rows = []
        for name in ROOT_NAMES:
            declared = manifest["executables"][name]
            if declared["path"] != "bin/" + name:
                raise ValueError("unexpected native bootstrap member path")
            path = distribution / declared["path"]
            raw = regular(path)
            if pin(raw) != {key: declared[key] for key in ("bytes", "sha256")} or raw[:4] != b"\x7fELF":
                raise ValueError("native bootstrap bytes differ: " + name)
            rows.append({"name": name, "path": str(path), **pin(raw)})
        receipt = directory / "bootstrap-inputs.json"
        receipt.write_text(json.dumps({"schema": "hepta.hia.native-cold-bootstrap-inputs.v1",
            "distribution_manifest": {"path": str(distribution / "manifest.json"), **pin(manifest_raw)},
            "historical_source": manifest["source"], "historical_qualification_reused": False,
            "bootstrap": rows}, indent=2, sort_keys=True) + "\n")
        preseed, preparation = directory / "preseed", directory / "preparation"
        build, exported, chain = directory / "build", directory / "export", directory / "chain"
        invoke("preseed", "hia_native_cold_preseed.py", ["--source", ROOT, "--output", preseed,
               "--root-receipt", receipt])
        invoke("prepare", "hia_native_cold_prepare.py", ["--source", ROOT, "--base", head,
               "--preseed", preseed, "--output", preparation])
        prepared = read_json((preparation / "report.json").read_bytes())
        if prepared["changed_sources"]:
            raise ValueError("checked-in native source freeze differs from actual native regeneration")
        before_pins = read_json((preparation / "before-source-pins.json").read_bytes())
        after_pins = read_json((preparation / "after-source-pins.json").read_bytes())
        for name, digest in sources.items():
            actual_pin = pin(regular(ROOT / name))
            if (before_pins.get(name) != actual_pin or after_pins.get(name) != actual_pin
                    or actual_pin["sha256"] != digest):
                raise ValueError("native source bytes changed during exact freeze replay: " + name)
        subprocess.run(["/usr/bin/git", "diff", "--exit-code", "HEAD", "--"], cwd=ROOT,
                       env=environment, check=True, timeout=30, stdout=subprocess.DEVNULL)
        invoke("construct", "hia_native_cold_construct.py", ["--source", ROOT, "--head", head,
               "--preparation", preparation, "--preseed", preseed, "--output", build])
        invoke("export", "hia_native_cold_export.py", ["--source", ROOT, "--build", build,
               "--preparation", preparation, "--output", exported])
        invoke("cold", "hia_native_cold_chain.py", ["--source", ROOT, "--head", head,
               "--preparation", preparation, "--build", build, "--export", exported,
               "--output", chain, "--stop-after-cold"])
        actual = read_json(regular(chain / "qualification.json"))
        if (actual["passed"] is not True or actual["whole_cold_qualified"] is not True
                or actual["source_head"] != head or len(actual["commands"]) != 1
                or actual["commands"][0]["native_descendants_only"] is not True):
            raise ValueError("complete current native cold chain did not pass")
        cold_path = Path(actual["cold"]["path"])
        cold_raw = regular(cold_path)
        if pin(cold_raw) != {key: actual["cold"][key] for key in ("bytes", "sha256")}:
            raise ValueError("native cold report changed after independent chain verification")
        base = cold_path.parent / "qualification/base"
        compiler = regular(base / "B3.flat", 1_048_576)
        from tools.generate_hia_native_observer import reference_image
        admit_native_report(compiler, cold_raw, contract=contract, sources=sources,
                            observer_bytes=reference_image())
        generations = []
        for name in ("B1", "B2", "B3"):
            path = base / (name + ".flat")
            raw = regular(path, 1_048_576)
            if raw != compiler:
                raise ValueError("native generation changed after qualification")
            generations.append({"name": name, "produced_image": str(path),
                "produced_bytes": len(raw), "produced_sha256": sha256(raw).hexdigest()})
        index_path = requested.with_suffix(".generations.json")
        index = {"schema": "hepta.hia.native-cold-generation-index.v1",
                 "source_head": head, "native_report": {"path": str(requested), **pin(cold_raw)},
                 "generations": generations, "location_index_only": True,
                 "hosted_qualification_claimed": False}
        with index_path.open("x") as stream:
            stream.write(json.dumps(index, indent=2, sort_keys=True) + "\n")
        if subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT,
                                   text=True, timeout=20).strip() != head:
            raise ValueError("native source Git HEAD changed")
        if validate_release_contract(ROOT) != contract or regular(cold_path) != cold_raw:
            raise ValueError("native source or qualification changed before publication")
        subprocess.run(["/usr/bin/git", "diff", "--exit-code", "HEAD", "--"], cwd=ROOT,
                       env=environment, check=True, timeout=30, stdout=subprocess.DEVNULL)
        with requested.open("xb") as stream:
            stream.write(cold_raw)
        report.update(passed=True, native_report={"path": str(requested), **pin(cold_raw)},
                      generation_index={"path": str(index_path), **pin(index_path.read_bytes())},
                      native_source_manifest=sources, development_orchestration_outside_native_export=True)
        save()
        return read_json(cold_raw)
    except BaseException:
        report["error"] = traceback.format_exc()
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = replay(args.output)
    print(json.dumps({"status": report["status"], "output": str(args.output),
                      "phase_count": len(report["phases"]),
                      "generation_sha256": report["generation_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
