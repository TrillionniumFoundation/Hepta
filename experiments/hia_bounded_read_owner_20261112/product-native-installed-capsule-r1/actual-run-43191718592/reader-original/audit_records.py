"""Independent byte/receipt joins over one retained ba714f development artifact.

Only stdlib and the adjacent archive reader are imported. No Hepta module,
compiler, image, package builder or original test is executed. Remote identity
values are evidence from the sealed manifest, not invented local stat values.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import traceback
import zipfile

from audit_archive import (BRANCH, CANDIDATE, TREE, WORKFLOW_HEAD, Originals,
                           json_bytes, pin, require, safe_name, save)


CONTROL = "dc42857a35bb4b42edf22640ef7b189ea7b2c846"
POLICY = "aca860a9dfae551103afb897069ec9aa42df9fc9f221d3891f75f7fcac0a3628"
OWNER = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
GENERATED = "examples/hia_bootstrap/bounded_read.hiaasm"
NATURAL = {"qualification_started", "owned_child_observed",
           "qualification_exit_observed", "owned_child_reaped"}
NATIVE_LIMITS = {"cpu_seconds": 10, "address_bytes": 256 << 20,
                 "core_dumpable": False, "stack_bytes": 8 << 20,
                 "output_capacity": 1 << 20, "workspace_bytes": 1 << 20}


class Audit:
    def __init__(self, originals, controls, source, git, run_id):
        self.originals = originals
        self.files = originals.typed_bytes
        self.rows = {row["path"]: row for row in originals.typed_manifest["originals"]}
        self.controls, self.source, self.git = controls, source, git
        self.run_id = run_id
        self.checks, self.failures, self.facts = [], [], {}
        self.context = json_bytes(originals.public("context.json"))
        self.root = self.context["root"]
        self.remote_source = self.context["source"]
        self.python = self.context["python"]["resolved"]
        self.plan = json_bytes((controls / "source-manifest.json").read_bytes())
        self.expected = {r["path"]: r for r in self.plan["files"]}
        self.source_cache = {}

    def check(self, ok, name, **observed):
        row = {"id": name, "status": "PASS" if ok else "FAIL"}
        if observed:
            row["observed"] = observed
        self.checks.append(row)
        require(ok, name)

    def stage(self, name, function):
        try:
            function()
        except BaseException as error:
            self.failures.append({"stage": name, "type": type(error).__name__,
                                  "message": str(error), "traceback": traceback.format_exc()})

    def path(self, name):
        return self.root + "/" + safe_name(name)

    def relative(self, remote):
        require(type(remote) is str and remote.startswith(self.root + "/"),
                "record is not inside this original operation")
        return safe_name(remote[len(self.root) + 1:])

    def raw(self, name, expected=None):
        require(name in self.files, "missing actual original: " + name)
        raw = self.files[name]
        if expected is not None:
            require(expected["path"] == self.path(name), "original path binding differs")
            actual = pin(raw)
            require(expected["bytes"] == actual["bytes"] and expected["sha256"] == actual["sha256"],
                    "original byte binding differs: " + name)
            if "git_blob_sha1" in expected:
                require(expected["git_blob_sha1"] == actual["git_blob_sha1"], "original Git blob differs")
            if "identity" in expected:
                require(expected["identity"] == self.rows[name]["identity"],
                        "original manifest identity differs: " + name)
        return raw

    def obj(self, name, expected=None):
        return json_bytes(self.raw(name, expected))

    def source_raw(self, name):
        if name not in self.source_cache:
            require(name in self.expected, "not in canonical product source: " + name)
            expected = self.expected[name]
            path = self.source / name
            if path.is_file():
                raw = path.read_bytes()
            else:
                raw = subprocess.run(["git", "--git-dir", str(self.git), "cat-file", "blob",
                                      expected["git_blob_sha1"]], check=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
            actual = pin(raw)
            require(actual["bytes"] == expected["size"]
                    and actual["git_blob_sha1"] == expected["git_blob_sha1"],
                    "local canonical product original differs: " + name)
            self.source_cache[name] = raw
        return self.source_cache[name]

    def clean_owner(self, life, seconds):
        cleanup = life["cleanup"]
        return (life["status"] == "OWNED_PROCESS_COMPLETED"
                and type(life["returncode"]) is int and life["returncode"] == 0
                and life["qualification_seconds"] == seconds and life["cleanup_seconds"] == 3
                and life["qualification_started"] is True and life["subreaper_enabled"] is True
                and life["timed_out"] is False and life["exit_observed_before_deadline"] is True
                and life["event_overflow"] is False and life["interrupted_signals"] == []
                and life.get("owner_error") is None and cleanup["attempted"] is True
                and cleanup["complete"] is True and cleanup["observed_echild"] is True
                and cleanup["leader_reaped"] is True and cleanup["deadline_exceeded"] is False
                and cleanup["remaining_direct_children"] == [] and cleanup["errors"] == []
                and {"qualification_started", "qualification_exit_observed", "owned_child_reaped"}
                    <= {e["kind"] for e in life["events"]}
                and all(e["kind"] in NATURAL for e in life["events"]))

    def controls_and_outer(self):
        c = self.context
        self.check(c["run_id"] == self.run_id and c["run_attempt"] == 1
                   and c["workflow_commit"] == WORKFLOW_HEAD and c["actual_control_commit"] == CONTROL
                   and c["policy_sha256"] == POLICY and c["event"] == "create"
                   and c["trigger_branch"] == BRANCH and c["candidate_commit"] == CANDIDATE
                   and c["candidate_tree"] == TREE and c["candidate_leaves"] == 4051,
                   "exact_original_operation")
        policy = self.obj("control/policy.json")
        self.check(pin(self.raw("control/policy.json"))["sha256"] == POLICY,
                   "original_policy_raw")
        for name, expected in policy["controls"].items():
            raw = self.raw("control/" + name)
            self.check(pin(raw) == expected and raw == (self.controls / name).read_bytes(),
                       "actual_control:" + name)
        setup, request, guard = (self.obj(n) for n in (
            "setup.json", "guard/request.json", "guard/guardian.json"))
        self.check(setup["context"] == c and setup["controller_seconds"] == 180
                   and setup["cleanup_seconds"] == 3
                   and pin(self.raw("guard/request.json"))["sha256"] == setup["guardian_config_sha256"]
                   and request["command"] == setup["command"]
                   and request["source_identities"] == setup["source_identities"]
                   and request["cwd"] == c["source"] and request["controller_seconds"] == 180,
                   "outer_request_setup_complete_binding")
        self.check(guard["schema"] == "hepta.hia.external-qualification-guardian.v1"
                   and guard["status"] == "EXTERNAL_OWNED_PROCESS_COMPLETED"
                   and guard["command"] == setup["command"] and guard["cwd"] == c["source"]
                   and guard["external_controller_seconds"] == 180
                   and guard["source_identities_before"] == guard["source_identities_after"]
                       == setup["source_identities"]
                   and guard["input_identity_preserved"] is True
                   and guard["lifecycle_implementation_sha256"] == OWNER
                   and guard["qualification"] is None
                   and guard["cold_180_second_gate_modified"] is False
                   and self.clean_owner(guard["lifecycle"], 180), "outer_natural_180_3_ECHILD")
        self.check(guard["logs"] == {self.path("guard/" + n): pin(self.raw("guard/" + n))["sha256"]
                   for n in ("child.stdout.log", "child.stderr.log")}, "outer_actual_log_bytes")
        self.facts["outer_lifecycle"] = guard["lifecycle"]
        self.facts["runtime_binary_recovery_scope"] = (
            "Python/git/linker binary identities are original reported pins. Their external binary "
            "files are not in the owned tar and are not claimed as independently recovered bytes.")

    def source_reports(self):
        paths = ["evidence/source-before.json", "evidence/source-after.json",
                 "evidence/compiler/source-before.json", "evidence/compiler/source-after.json"]
        reports = [self.obj(p) for p in paths]
        self.check(all(value == reports[0] for value in reports[1:]), "four_complete_source_identity_reports_equal")
        rows = reports[0]
        self.check(len(rows) == 4051 and {r["path"] for r in rows} == set(self.expected),
                   "complete_source_4051_namespace")
        for row in rows:
            wanted = self.expected[row["path"]]
            require(row["mode"] == wanted["mode"] and row["bytes"] == wanted["size"]
                    and row["git_blob_sha1"] == wanted["git_blob_sha1"]
                    and stat.S_IMODE(row["identity"][2]) == int(wanted["mode"][-3:], 8),
                    "canonical source record mismatch: " + row["path"])
        self.check(True, "all_4051_source_records_match_frozen_canonical_tree")
        support = json_bytes(self.source_raw("docs/HIA_SELFHOST_CORE_SUPPORT.json"))
        declarations = support["source_identity"]["files"]
        self.check(len(declarations) == 815, "current_declared_source_815")
        for name, digest in declarations.items():
            require(pin(self.source_raw(name))["sha256"] == digest, "declared canonical source digest")
        self.check(True, "all_815_canonical_declared_source_bytes_read")
        self.facts["source_scope"] = "Remote full identity reports match 4051 canonical members; 815 canonical source byte originals independently read. Remote source directory itself is not re-opened after runner termination."

    def owners(self):
        labels = {"evidence/processes/fresh-compiler": 60, "evidence/processes/finite-gate": 180,
                  "evidence/finite/validation": 180, "evidence/finite/work/build": 60,
                  **{"evidence/finite/work/" + n: (180 if n == "original-eight" else 30)
                     for n in ("reject", "lifetime", "permission", "filesystem", "original-eight")},
                  **{"evidence/installation/" + n: seconds for n, seconds in (
                      ("packaging-tools", 15), ("sdist", 120), ("wheel", 120),
                      ("install", 120), ("installed-child", 5))}}
        actual = {name.removesuffix(".process-owner.json") for name in self.files
                  if name.endswith(".process-owner.json")}
        self.check(actual == set(labels) and len(actual) == 14, "exact_fourteen_inner_owner_namespace")
        found = []
        for base, seconds in labels.items():
            receipt_name = base + ".process-owner.json"
            request_name = receipt_name + ".request.json"
            receipt, request, step = self.obj(receipt_name), self.obj(request_name), self.obj(base + ".step.json")
            self.check(receipt["schema"] == request["schema"] == "hepta.hia.selfhost-process-owner.v1"
                       and receipt["request_sha256"] == pin(self.raw(request_name))["sha256"]
                       and receipt["implementation_sha256"] == request["implementation_sha256"] == OWNER
                       and request["deadline_ns"] - request["started_ns"] == seconds * 1000000000
                       and request["qualification_seconds"] == seconds and request["cleanup_seconds"] == 3
                       and request["command"] == step["command"] and request["cwd"] == step["cwd"]
                       and step["qualification_seconds"] == seconds and step["cleanup_seconds"] == 3
                       and step["owner_returned"] == dict(receipt, supervisor_returncode=0,
                                                    receipt_sha256=pin(self.raw(receipt_name))["sha256"])
                       and step["status"] == "OWNED_STEP_PASS"
                       and step["cleanup_closed_before_original_read"] is True
                       and not step.get("custody_errors") and self.clean_owner(receipt, seconds),
                       "inner_owner_request_receipt:" + base)
            names = [base + ".stdout.log", base + ".stderr.log", receipt_name, request_name,
                     receipt_name + ".stdout.log", receipt_name + ".stderr.log"]
            require(len(step["original_files"]) == 6, "six actual owner originals")
            for name, expected in zip(names, step["original_files"], strict=True):
                self.raw(name, expected)
            self.check(request["stdout_path"] == self.path(names[0])
                       and request["stderr_path"] == self.path(names[1])
                       and request["receipt_path"] == self.path(receipt_name)
                       and step["stdout"] == step["original_files"][0]
                       and step["stderr"] == step["original_files"][1],
                       "six_original_bytes_and_paths:" + base)
            found.append({"name": base, "seconds": seconds, "pid": receipt["qualification_pid"],
                          "command": request["command"], "cwd": request["cwd"], "env": request["env"]})
        self.facts["inner_owners"] = found

    def compiler(self):
        base = "evidence/compiler/"
        seed, raw = self.obj(base + "B0.receipt.json"), self.raw(base + "B0.so")
        selfhost = self.source_raw("examples/hia_bootstrap/selfhost.hiaasm")
        self.check(seed["schema"] == "hepta.hia.program.direct-native.v1"
                   and seed["ok"] is True and seed["kind"] == "shared" and seed["seed_only"] is True
                   and seed["artifact_bytes"] == len(raw) and seed["artifact_sha256"] == pin(raw)["sha256"]
                   and seed["output"] == self.path(base + "B0.so")
                   and seed["source_sha256"] == pin(selfhost)["sha256"]
                   and seed["support_contract_sha256"] == pin(self.source_raw("docs/HIA_SELFHOST_CORE_SUPPORT.json"))["sha256"],
                   "B0_original_receipt_actual_shared_bytes")
        for name, expected in seed["loaded_seed_modules"].items():
            require(pin(self.source_raw(name))["sha256"] == expected, "actual seed source module")
        self.check(bool(seed["loaded_seed_modules"]), "B0_complete_loaded_source_map")
        predecessor, predecessor_name = raw, base + "B0.so"
        stages = []
        for label, folder, input_raw, image_format in (
                ("B1", base, selfhost, "seed-shared"),
                ("B2", base, selfhost, "flat-x86-64"),
                ("bounded-read", "evidence/finite/work/build/", self.source_raw(GENERATED), "flat-x86-64")):
            prefix = folder + label
            request, receipt = self.obj(prefix + ".request.json"), self.obj(prefix + ".receipt.json")
            image, output = self.raw(prefix + ".image.bin"), self.raw(prefix + ".output.bin")
            wanted = {"format": image_format, "image": self.path(predecessor_name),
                      "image_sha256": pin(predecessor)["sha256"], "source": self.path(prefix + ".input.bin"),
                      "source_sha256": pin(input_raw)["sha256"], "capacity": 1 << 20,
                      "workspace_size": 1 << 20, "workspace_fill": 0,
                      "output": self.path(prefix + ".output.bin")}
            self.check(request == wanted and self.raw(prefix + ".input.bin") == input_raw,
                       label + "_complete_request_and_input")
            self.check(receipt["case"] == label and receipt["status"] == "returned"
                       and receipt["abi_status"] == 0 and receipt["source_unchanged"] is True
                       and receipt["forbidden_compiler_modules_loaded"] == []
                       and receipt["limits"] == NATIVE_LIMITS and receipt["format"] == image_format
                       and receipt["image_sha256"] == receipt["artifact_sha256"] == pin(predecessor)["sha256"]
                       and receipt["source_sha256"] == receipt["input_sha256"] == pin(input_raw)["sha256"]
                       and receipt["input_bytes"] == len(input_raw)
                       and receipt["output_sha256"] == pin(output)["sha256"]
                       and receipt["core_u32"] == receipt["produced_bytes"] == len(image) > 0
                       and receipt["produced_sha256"] == pin(image)["sha256"]
                       and receipt["produced_image"] == self.path(prefix + ".image.bin")
                       and len(output) == 1 << 20 and output[:len(image)] == image,
                       label + "_actual_complete_image_output_receipt")
            additions = {"case", "input_sha256", "input_bytes", "artifact_sha256", "format",
                         "runner_sha256", "wall_elapsed_ns", "produced_image", "produced_bytes", "produced_sha256"}
            self.check(additions <= set(receipt)
                       and self.obj(prefix + ".stdout.log") == {k: v for k, v in receipt.items() if k not in additions},
                       label + "_whole_child_stdout_projection")
            self.raw(prefix + ".stderr.log")
            stages.append({"label": label, "image": pin(image), "input": pin(input_raw),
                           "whole_output": pin(output), "wall_elapsed_ns": receipt["wall_elapsed_ns"]})
            predecessor, predecessor_name = image, prefix + ".image.bin"
        self.check(self.raw(base + "B1.image.bin") == self.raw(base + "B2.image.bin"), "actual_B1_B2_equality")
        self.facts["compiler_stages"] = stages

    def finite(self):
        population = json_bytes(self.source_raw("tools/hia_bounded_read_checks/populations.json"))
        final, report = self.obj("evidence/finite/acceptance.json"), self.obj("evidence/finite/work/report.json")
        self.check(final["status"] == report["status"] == "FINITE_BOUNDED_READ_VALIDATION_PASS"
                   and final["errors"] == report["errors"] == []
                   and report["finite_component_cases"] == 55 and report["original_methods"] == 8
                   and report["original_CLI_children"] == 7 and report["original_CLI_child_timeout_seconds"] == 20,
                   "actual_public_55_8_7_report")
        details = []
        for group in population["groups"]:
            folder = "evidence/finite/work/" + group["name"] + "/"
            result = self.obj(folder + "report.json")
            self.check(result["schema"] == group["schema"] and result["status"] == group["status"]
                       and result["expected_ids"] == result["loaded_ids"] == result["executed_ids"] == group["expected_ids"]
                       and result["errors"] == []
                       and set(result["anomalies"]) == {"skips", "expected_failures", "unexpected_successes", "failures", "errors"}
                       and all(type(v) is list and not v for v in result["anomalies"].values()),
                       "complete_exact_group:" + group["name"])
            if group["name"] == "original-eight":
                self.original_callers(folder, result)
                continue
            self.check([r["id"] for r in result["cases"]] == group["expected_ids"],
                       "complete_detail_population:" + group["name"])
            for entry in result["cases"]:
                name = folder + entry["id"] + ".json"
                detail = self.obj(name, entry.get("record", entry.get("original")))
                native = (detail.get("real_native_entry_required") is True
                          if group["name"] in ("reject", "lifetime") else
                          detail.get("actual_native_entry_returns", 0) > 0 and detail.get("terminal_permission_sealed") is True
                          if group["name"] == "permission" else
                          detail.get("actual_native_call_delta") == 1 and detail.get("actual_native_transition_delta", 0) > 0
                          and detail.get("retained_policy_calls") == [])
                self.check(detail["id"] == entry["id"] and detail["status"] == entry["status"] == "PASS" and native,
                           "finite_detail:" + group["name"] + "/" + entry["id"])
                details.append({"id": entry["id"], "original": pin(self.raw(name))})
        self.check(len(details) == 55, "all_fifty_five_actual_detail_bytes")
        self.facts["finite_details"] = details

    def original_callers(self, folder, result):
        policy = self.obj(folder + "child-policy.json", result["child_policy"])
        parent = self.obj(folder + "parent-original.json")
        self.check(result["testsRun"] == result["original_method_denominator"] == 8
                   and result["original_CLI_child_denominator"] == len(result["children"]) == 7
                   and result["actual_native_read_attempts"] == 12 and result["actual_native_read_returns"] == 11
                   and result["original_CLI_timeout_seconds"] == 20 and result["loader_errors"] == []
                   and parent == result["parent"], "original_eight_complete_counts")
        values = [parent]
        seen, commands, calls = set(), Counter(), 0
        for row in result["children"]:
            child = row["result"]
            pid = child["pid"]
            self.check(type(pid) is int and pid > 0 and pid not in seen, "unique_CLI_PID:" + str(pid))
            seen.add(pid)
            self.check(self.obj(folder + "children/child-%d.json" % pid, row["record"]) == child,
                       "actual_CLI_completion:" + str(pid))
            start = self.obj(folder + "children/start-%d.json" % pid, row["start"])
            self.check(start["pid"] == pid and start["parent_pid"] == child["parent_pid"] == parent["pid"]
                       and start["policy_sha256"] == pin(self.raw(folder + "child-policy.json"))["sha256"]
                       and start["native_identity"] == child["native_before"], "actual_CLI_start:" + str(pid))
            kind = child["argv"][1]
            count = 2 if kind == "patch" else 1
            self.check(child["argv"][0] == self.remote_source + "/tools/hia_core_reference.py"
                       and len(child["read_calls"]) == count
                       and all(c["outcome"] == "returned" for c in child["read_calls"]),
                       "actual_source_CLI_command_reads:" + str(pid))
            commands[kind] += 1
            calls += count
            values.append(child)
        for value in values:
            self.check(value["status"] == "ORIGINAL_CALLER_OBSERVER_PASS"
                       and value["retained_owner_calls"] == []
                       and value["source_before"] == value["source_after"]
                       and value["bundle_before"] == value["bundle_after"]
                       and value["native_before"] == value["native_after"]
                       and value["actual_executable"] == self.python
                       and value["original_CLI_timeout_seconds_unchanged"] == 20
                       and value["policy_sha256"] == pin(self.raw(folder + "child-policy.json"))["sha256"]
                       and all(r["native_calls_after"] == r["native_calls_before"] + 1
                               and r["native_transitions_after"] > r["native_transitions_before"]
                               for r in value["read_calls"]), "actual_native_caller_observer:" + str(value["pid"]))
        actual = {p for p in self.files if p.startswith(folder + "children/")}
        expected = {folder + "children/" + kind + "-%d.json" % pid for kind in ("child", "start") for pid in seen}
        self.check(actual == expected and calls == 8
                   and commands == Counter(verify=2, run=3, inspect=1, patch=1)
                   and len(parent["read_calls"]) == 4
                   and Counter(r["outcome"] for r in parent["read_calls"]) == Counter(returned=3, raised=1),
                   "seven_CLI_namespace_and_all_twelve_read_attempts")
        self.facts["original_CLI"] = {"PIDs": sorted(seen), "commands": dict(commands),
                                      "parent_attempts": 4, "child_attempts": calls}

    def installation(self):
        base = "evidence/installation/"
        report, result, request = (self.obj(base + name) for name in (
            "package-report.json", "installed-cases.json", "installed-request.json"))
        tree = ast.parse((self.controls / "installed_cases.py").read_bytes())
        ids = list(ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign)
                                        and any(isinstance(t, ast.Name) and t.id == "IDS" for t in n.targets))))
        self.check(report["status"] == "DEVELOPMENT_INSTALLATION_PASS"
                   and report["candidate_commit"] == report["source_head"] == CANDIDATE
                   and report["errors"] == [] and report["source_resource_count"] == 105
                   and report["source_python_count"] == 170 and report["native_source_resource_count"] == 90
                   and report["source_inputs_before"] == report["source_inputs_after"]
                   and report["immutable_inputs_before"] == report["immutable_inputs_after"],
                   "actual_offline_package_summary")
        self.check(result["status"] == "DEVELOPMENT_INSTALLED_CASES_PASS"
                   and result["expected_test_ids"] == result["loaded_test_ids"] == result["executed_test_ids"] == ids
                   and result["tests_run"] == len(ids) == 9
                   and all(type(result[k]) is int and result[k] == 0 for k in (
                       "failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
                   and result["request_sha256"] == pin(self.raw(base + "installed-request.json"))["sha256"]
                   and result["empty_PATH"] is True and result["isolated_no_site"] is True
                   and result["forbidden_authoring_attempts"] == result["forbidden_retained_owner_attempts"] == []
                   and [r["id"] for r in result["cases"]] == ids
                   and all(r["status"] == "PASS" for r in result["cases"]), "nine_exact_installed_cases")
        inputs = {row["path"]: self.source_raw(row["path"]) for row in report["source_inputs_after"]}
        for row in report["source_inputs_after"]:
            require(all(row[k] == v for k, v in pin(inputs[row["path"]]).items()), "package canonical input differs")
        declarations = report["actual_resource_declarations"]
        resources = ["docs/" + n for n in declarations["DISCOVERY_FILES"]] + declarations["NATIVE_SOURCE_FILES"] + declarations["PUBLICATION_BUILD_FILES"]
        contract = ast.parse(self.source_raw("hepta/hia_agent_contract.py"))
        literal = {t.id: ast.literal_eval(n.value) for n in contract.body if isinstance(n, ast.Assign)
                   for t in n.targets if isinstance(t, ast.Name) and t.id in declarations}
        self.check(declarations == {k: list(v) for k, v in literal.items()}
                   and len(resources) == len(set(resources)) == 105
                   and sum(n.startswith("hepta/") and n.endswith(".py") for n in inputs) == 170,
                   "actual_three_resource_tuples_and_170_Python")
        prefix = base + "installed/"
        actual_names = {n[len(prefix):] for n in self.files if n.startswith(prefix)}
        now = report["installed_after"]
        self.check(actual_names == {r["path"] for r in now} and result["installed_after"] == now,
                   "complete_actual_installed_namespace")
        for row in now:
            name = prefix + row["path"]
            raw = self.raw(name)
            require(all(row[k] == v for k, v in pin(raw).items())
                    and row["mode"] == format(stat.S_IMODE(self.rows[name]["identity"][2]), "04o")
                    and row["identity"] == self.rows[name]["identity"], "actual installed member differs")
        projection = lambda rows: [{k: r[k] for k in ("path", "bytes", "sha256", "git_blob_sha1", "mode")} for r in rows]
        self.check(projection(now) == projection(report["installed_before"])
                   and result["installed_source_bytes_and_modes_restored"] is True,
                   "installed_final_bytes_modes_restored_not_before_inode_equality")
        for name, raw in inputs.items():
            if name.startswith("hepta/"):
                require(self.raw(prefix + name) == raw, "installed Python/data differs")
        for name in resources:
            require(self.raw(prefix + "hepta/_data/" + name) == inputs[name], "installed resource differs")
        self.check({n for n in actual_names if n.startswith("hepta/_data/")}
                   == {"hepta/_data/" + n for n in resources}, "all_105_actual_installed_resource_bytes")
        self.package_archives(base, report, inputs, resources)
        manifest = self.obj(base + "native/manifest.json", report["manifest"])
        image = self.raw(base + "native/native.bin", report["native_image"])
        compiler = self.raw("evidence/compiler/B2.image.bin")
        component = self.raw("evidence/finite/work/build/bounded-read.image.bin")
        self.check(image == component and manifest == {
            "schema": "hepta.hia.bounded-read-native.v3", "source_sha256": pin(inputs[GENERATED])["sha256"],
            "image_path": "native.bin", "image_sha256": pin(image)["sha256"],
            "compiler_sha256": pin(compiler)["sha256"]}, "installed_bundle_exact_fresh_image_source_compiler")
        attempts, completed, reads = result["native_entry_attempts"], result["native_entry_completed"], result["native_reads"]
        self.check(result["native_completions"] == len(attempts) == len(completed) > 0
                   and result["native_read_returns"] == len(reads) == 7
                   and [r["id"] for r in reads] == [ids[0], ids[5], ids[6], ids[7], ids[8], ids[8], ids[8]]
                   and sum(r["status"] == 0 for r in completed) == 7
                   and all(a["case"] == b["case"] and a["argument_count"] == 3
                           and type(a["returned_status"]) is int and a["returned_status"] == b["status"]
                           and b["status"] in (0, 1) for a, b in zip(attempts, completed, strict=True)),
                   "all_seven_logical_native_reads_and_completed_entry_ledger")
        rebuilt = []
        for i, (row, raw) in enumerate(zip(reads, [b"bounded\0read\xff"] * 4 + [b"", b"x" * (8 << 20), b"bounded\0read\xff"], strict=True)):
            fixture = self.raw(base + "fixtures/read-%03d.bin" % i, row["fixture"])
            self.check(fixture == raw and row["input"] == row["output"] == pin(raw)
                       and row["native_calls_after"] == row["native_calls_before"] + 1
                       and row["native_statuses"] == [1] * (row["native_completed_calls"] - 1) + [0]
                       and row["native_read_returns"] == 1, "actual_installed_read_fixture:" + str(i))
            rebuilt.extend({"case": row["id"], "status": s} for s in row["native_statuses"])
        self.check(rebuilt == completed, "entire_continuation_ledger_reconstructed")
        for record in result["negative_manifest_originals"]:
            self.raw(self.relative(record["path"]), record)
        self.check(len(result["negative_manifest_originals"]) == 7,
                   "all_seven_negative_manifest_byte_originals")
        child = self.obj(base + "installed-child.process-owner.json.request.json")
        self.check(child["command"] == [self.python, "-I", "-S", "-B", self.path(base + "control/installed_cases.py"),
                   "--request", self.path(base + "installed-request.json"), "--request-sha256",
                   pin(self.raw(base + "installed-request.json"))["sha256"]]
                   and child["env"] == {"PATH": "", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
                   and child["cwd"] == self.path(base + "consumer-cwd")
                   and request["qualification_seconds"] == child["qualification_seconds"] == 5,
                   "actual_isolated_empty_PATH_five_second_installed_child")
        self.facts["installed"] = {"IDs": ids, "files": len(now), "Python": 170, "resources": 105,
                                  "logical_native_reads": 7, "actual_completed_entries": len(completed),
                                  "full_boundary_input": pin(b"x" * (8 << 20))}

    def package_archives(self, base, report, inputs, resources):
        sdist = self.raw(self.relative(report["sdist"]["path"]), report["sdist"])
        decoded = gzip.decompress(sdist)  # Complete gzip CRC/trailer validation.
        require(len(decoded) <= 128 << 20, "original sdist decoded bound")
        srows, seen, roots = [], set(), set()
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
            for member in archive.getmembers():
                name = safe_name(member.name, directory=member.isdir())
                require(name not in seen and (member.isfile() or member.isdir()), "sdist typed namespace")
                seen.add(name); roots.add(name.split("/")[0])
                if member.isdir():
                    continue
                raw = archive.extractfile(member).read()
                require(len(raw) == member.size, "sdist full extent")
                srows.append({"path": name.split("/", 1)[1], **pin(raw), "mode": format(member.mode, "04o")})
        self.check(len(roots) == 1 and srows == report["sdist_members"], "all_actual_sdist_members_bytes_modes_CRC")
        smap = {r["path"]: r for r in srows}
        for name, raw in inputs.items():
            require(name in smap and all(smap[name][k] == v for k, v in pin(raw).items()), "sdist lost canonical input")
        wheel = self.raw(self.relative(report["wheel"]["path"]), report["wheel"])
        wrows, seen, wdata = [], set(), {}
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            for item in archive.infolist():
                name = safe_name(item.filename, directory=item.is_dir())
                mode = item.external_attr >> 16
                require(name not in seen and not item.flag_bits & 1 and not stat.S_ISLNK(mode)
                        and (item.is_dir() or mode == 0 or stat.S_ISREG(mode)), "wheel namespace/type")
                seen.add(name)
                raw = archive.read(item)
                require(len(raw) == item.file_size, "wheel full member extent")
                if item.is_dir():
                    continue
                wdata[name] = raw
                wrows.append({"path": name, **pin(raw), "zip_crc32": item.CRC,
                              "mode": format(stat.S_IMODE(mode), "04o")})
        self.check(wrows == report["wheel_members"], "all_actual_wheel_members_bytes_modes_CRC")
        for name, raw in inputs.items():
            if name.startswith("hepta/"):
                require(wdata[name] == raw, "wheel canonical hepta source")
        for name in resources:
            require(wdata["hepta/_data/" + name] == inputs[name], "wheel canonical resource")
        self.check({n for n in wdata if n.startswith("hepta/_data/")}
                   == {"hepta/_data/" + n for n in resources}, "complete_wheel_source_resource_namespace")
        self.facts["package_archives"] = {"sdist": pin(sdist), "wheel": pin(wheel),
                                         "sdist_members": len(srows), "wheel_members": len(wrows)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--controls", type=Path, required=True)
    p.add_argument("--canonical-source", type=Path, required=True)
    p.add_argument("--git-dir", type=Path, required=True)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(mode=0o700)
    report = {"schema": "hepta.hia.bounded-read-v80-independent-original-record-audit.v1",
              "status": "HOLD", "source_commit": CANDIDATE, "source_tree": TREE,
              "run_id": args.run_id, "new_product_execution": False,
              "cold_or_full_qualification_claimed": False, "errors": []}
    try:
        archive_raw = args.archive.read_bytes()
        originals = Originals(archive_raw)
        originals.read_zip(); originals.read_typed()
        final_raw = originals.public("FINAL.json", required=False)
        final = json_bytes(final_raw) if final_raw is not None else None
        report["original_product_status"] = final.get("status") if final else "MISSING_FINAL"
        if not final or final.get("status") != "BOUNDED_READ_NATIVE_AND_INSTALL_ACTIONS_DEVELOPMENT_PASS":
            report["status"] = "ORIGINAL_HOLD_OR_FAILURE_PRESERVED"
            report["original_final_errors"] = final.get("errors") if final else None
            report["available_regular_originals"] = sorted(originals.typed_bytes)
        else:
            audit = Audit(originals, args.controls, args.canonical_source, args.git_dir, args.run_id)
            for name in ("controls_and_outer", "source_reports", "owners", "compiler", "finite", "installation"):
                audit.stage(name, getattr(audit, name))
            report["checks"] = audit.checks
            report["errors"] = audit.failures
            report["facts"] = audit.facts
            report["canonical_source_bytes_read"] = len(audit.source_cache)
            if not audit.failures:
                report["status"] = "INDEPENDENT_FINITE_NATIVE_INSTALL_ORIGINAL_JOINS_PASS_NOT_FULL_DOMAIN"
        require(args.archive.read_bytes() == archive_raw, "original archive changed during audit")
        report["archive"] = pin(archive_raw)
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error),
                                  "traceback": traceback.format_exc()})
    save(args.output, "RECORD-AUDIT.json", report)
    print(json.dumps({"status": report["status"], "checks": len(report.get("checks", [])),
                      "errors": report["errors"]}))
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
