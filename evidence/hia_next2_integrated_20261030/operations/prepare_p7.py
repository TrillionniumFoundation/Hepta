"""Freeze the external V13 stage plan without loading or querying the model."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import ast
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "hepta-integration"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    def git(*values):
        return subprocess.check_output(["git", "--no-replace-objects", *values], cwd=REPO).decode().strip()
    if git("rev-parse", "HEAD") != args.head or git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("clean complete integrated source required before freezing")
    base = args.output.absolute()
    if base == REPO or REPO in base.parents:
        raise ValueError("stage outputs must remain outside the frozen source")
    base.mkdir(parents=True, exist_ok=False)
    (base / "operations").mkdir()
    previous = ROOT / "p7-v12-integrated-44e34b7a/operations/run_stage.py"
    launcher = previous.read_text().replace("V12", "V13").replace("_v12.py", "_v13.py")
    launcher = launcher.replace("'task_or_generation_parameters_modified': False",
                                "'wrapper_modified_frozen_study_parameters': False")
    ast.parse(launcher)
    if "v12.py" in launcher or "V12" in launcher:
        raise ValueError("old CLI name survived the explicit outer adaptation")
    target = base / "operations/run_stage.py"
    target.write_text(launcher)
    (base / "FROZEN_HEAD.txt").write_text(args.head + "\n")
    protocol_path = "experiments/hia_agent_toolstudy_v13_20261030/PROTOCOL.json"
    protocol = (REPO / protocol_path).read_bytes()
    plan = {
        "schema": "hepta.p7.integrated-v13-outer-plan.v1",
        "source_head": args.head, "source_tree": git("rev-parse", "HEAD^{tree}"),
        "launcher_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "launcher_derived_from": {"path": str(previous), "sha256": hashlib.sha256(previous.read_bytes()).hexdigest()},
        "protocol_path": protocol_path, "protocol_sha256": hashlib.sha256(protocol).hexdigest(),
        "stages": ["capacity", "calibration", "main"],
        "main_eligibility": "fresh same-source capacity and 3/3 calibration; actual main CLI refuses before model construction on ineligibility",
        "prior_qualification_inherited": False,
        "task_examples_answers_or_selected_nodes_added": False,
        "generation_budget_changed": False,
        "public_generic_guidance_and_decoder_changed": True,
        "adaptive_followup_on_v12_failure": True,
        "public_preregistration_claimed": False,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "model_requests_before_plan": 0, "native_capacity_before_plan": 0,
        "outer_audit": "raw Git blob/tree/mode preflight/postflight; exact same owned execution CLI; stream identities, resources and actual costs retained",
        "all_previous_failed_runs_retained": True,
    }
    (base / "PLAN.json").write_text(json.dumps(plan, indent=2) + "\n")
    print(json.dumps({"output": str(base), "source_head": args.head,
                      "launcher_sha256": plan["launcher_sha256"], "model_requests": 0}))


if __name__ == "__main__":
    main()
