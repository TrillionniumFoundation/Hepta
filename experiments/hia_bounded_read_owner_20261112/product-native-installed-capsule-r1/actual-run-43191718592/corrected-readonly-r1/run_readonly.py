"""One corrected read-only audit of the closed 43191718592 original ZIP.

No Hepta module is imported and no compiler, native image, installer or product
test is invoked.  The original workflow FAIL and FINAL HOLD are immutable
inputs.  Filesystem identities below are the original sealed manifest values,
never new local stat values presented as the former runner's state.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback

from audit_archive import Originals, json_bytes, pin, require, save
from audit_records import Audit, CANDIDATE, TREE, GENERATED, NATIVE_LIMITS


ARCHIVE_SHA = "bec5a2317ee9a1590dcd2ab2ac642df78012b7b32bebe5bcd6269bdbc563a506"
ARCHIVE_BYTES = 17443242
ORIGINAL_FINAL_SHA = "a362130184aa45acb5ec030f7ea17c8efb68594b98eb34d59eafa3adf267145d"
ORIGINAL_CASES_SHA = "0558c3f40428ce439943d11eda0f1b70caaaed9872a7306a1340f993d0a6be23"
ORIGINAL_VERIFIER_SHA = "92935fc562cfb7af8ab36df7a7de0f174d499e04c89c2ee73dd174d4aa4d21e4"
CORRECTED_VERIFIER_SHA = "2124f04e2c52e3271c0d36c1d724e08ed9871b7499348fb6df67624fedf5d6fa"
ORIGINAL_READER_SHA = "04711a788b86aff117841a6e9171b1fc10612172c27b7ce7562171ff7caa73a4"
CORRECTED_READER_SHA = "000e773bd4f1298502b2eff013b547967a2a17a831a8234958dc99e3da204bcf"
LEDGER_MESSAGE = "actual installed native completion ledger differs"


def function(raw, name):
    found = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name]
    require(len(found) == 1, "one exact frozen function required: " + name)
    return found[0]


def pure_function(raw, name, namespace):
    """Evaluate one reviewed observation function, without importing its module."""
    node = function(raw, name)
    require(not node.decorator_list, "unexpected observation function decorator")
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<frozen-observation:" + name + ">", "exec"), namespace)
    return namespace[name]


def condition(raw, name, message):
    found = [n for n in ast.walk(function(raw, name)) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "require"
             and len(n.args) == 2 and isinstance(n.args[1], ast.Constant)
             and n.args[1].value == message]
    require(len(found) == 1, "one exact frozen condition required: " + message)
    return compile(ast.Expression(body=found[0].args[0]), "<frozen-condition:" + message + ">", "eval")


def literal(raw, name):
    found = [n.value for n in ast.parse(raw).body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    require(len(found) == 1, "one literal required: " + name)
    return ast.literal_eval(found[0])


class ClosedOriginalAudit(Audit):
    def record_read(self, remote, maximum):
        """Actual bytes plus original identity; no runner path is opened here."""
        remote = str(remote)
        if remote.startswith(self.root + "/"):
            name = self.relative(remote)
            raw, row = self.raw(name), self.rows[name]
            require(row["kind"] == "regular", "only sealed regular bytes can be read")
            identity = row["identity"]
        elif remote.startswith(self.remote_source + "/"):
            name = remote[len(self.remote_source) + 1:]
            raw = self.source_raw(name)
            rows = {r["path"]: r for r in self.obj("evidence/source-after.json")}
            identity = rows[name]["identity"]
            require(rows[name]["sha256"] == sha256(raw).hexdigest(), "canonical source/original identity mismatch")
        else:
            raise ValueError("external runtime binary is not an archived byte original: " + remote)
        require(len(raw) <= maximum, "original read exceeds unchanged bound")
        return raw, {"path": remote, "bytes": len(raw), "sha256": sha256(raw).hexdigest(), "identity": identity}

    def frozen_check(self, raw, function_name, message, namespace, audit_id):
        self.check(eval(condition(raw, function_name, message), namespace) is True, audit_id,
                   exact_original_message=message)

    def arity_and_negative_controls(self):
        original = (self.controls / "actions_verify.py").read_bytes()
        fixed = (Path(__file__).parent / "actions_verify.py").read_bytes()
        old_reader = (Path(__file__).parent.parent / "receiver/audit_records.py").read_bytes()
        new_reader = (Path(__file__).parent / "audit_records.py").read_bytes()
        needle = b'a["argument_count"] == 3'
        self.check(sha256(original).hexdigest() == ORIGINAL_VERIFIER_SHA
                   and sha256(fixed).hexdigest() == CORRECTED_VERIFIER_SHA
                   and original.count(needle) == 1
                   and original.replace(needle, b'a["argument_count"] == 6') == fixed,
                   "only_frozen_verifier_arity_constant_changed")
        self.check(sha256(old_reader).hexdigest() == ORIGINAL_READER_SHA
                   and sha256(new_reader).hexdigest() == CORRECTED_READER_SHA
                   and old_reader.count(needle) == 1
                   and old_reader.replace(needle, b'a["argument_count"] == 6') == new_reader,
                   "only_independent_reader_arity_constant_changed")
        bridge = self.source_raw("hepta/hia_bounded_read_native.py")
        image = self.source_raw("hepta/hia_json_preflight_native.py")
        for name, raw in (("hia_bounded_read_native", bridge), ("hia_json_preflight_native", image)):
            self.check((Path(__file__).parent / ("bound-source-" + name + ".py")).read_bytes() == raw,
                       "canonical_ABI_source:" + name)
        session = next(n for n in ast.parse(bridge).body if isinstance(n, ast.ClassDef) and n.name == "BoundedReadSession")
        step = next(n for n in session.body if isinstance(n, ast.FunctionDef) and n.name == "step")
        calls = [n for n in ast.walk(step) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == "_entry"]
        self.check(len(calls) == 1 and len(calls[0].args) == 6 and not calls[0].keywords
                   and [ast.unparse(x) for x in calls[0].args] == [
                       "raw", "len(raw)", "self.output", "len(self.output)", "self.workspace", "len(self.workspace)"],
                   "actual_adapter_passes_six_flat_arguments")
        image_class = next(n for n in ast.parse(image).body if isinstance(n, ast.ClassDef) and n.name == "NativeHiaJsonImage")
        prototypes = [n for n in ast.walk(image_class) if isinstance(n, ast.Call)
                      and isinstance(n.func, ast.Attribute) and n.func.attr == "CFUNCTYPE"]
        self.check(len(prototypes) == 1 and ast.unparse(prototypes[0]) ==
                   "ctypes.CFUNCTYPE(ctypes.c_uint64, *[ctypes.c_void_p, ctypes.c_uint64] * 3)",
                   "actual_native_image_signature_is_three_pointer_length_pairs")
        result = self.obj("evidence/installation/installed-cases.json")
        self.check(sha256(self.raw("evidence/installation/installed-cases.json")).hexdigest() == ORIGINAL_CASES_SHA,
                   "all_actual_210_records_are_the_original_sealed_bytes")
        ids = list(literal((self.controls / "installed_cases.py").read_bytes(), "IDS"))
        def evaluate(code, value):
            return eval(code, {"result": value, "attempts": value["native_entry_attempts"],
                               "completed": value["native_entry_completed"], "reads": value["native_reads"], "ids": ids})
        old = condition(original, "verify_installation", LEDGER_MESSAGE)
        corrected = condition(fixed, "verify_installation", LEDGER_MESSAGE)
        self.check(evaluate(old, result) is False, "frozen_original_predicate_reproduces_observed_HOLD_without_running_product")
        self.check(evaluate(corrected, result) is True, "corrected_predicate_accepts_all_unchanged_actual_210_records")
        negatives = []
        for count in (3, 5):
            for extent in ("all", "one"):
                value = copy.deepcopy(result)
                targets = value["native_entry_attempts"] if extent == "all" else value["native_entry_attempts"][104:105]
                for row in targets:
                    row["argument_count"] = count
                rejected = evaluate(corrected, value) is False
                self.check(rejected, "wrong_actual_record_argument_count_%d_%s_rejected" % (count, extent))
                negatives.append({"replacement_count": count, "extent": extent,
                                  "changed_record_count": len(targets), "rejected": rejected,
                                  "record_population": len(value["native_entry_attempts"])})
        self.facts["ABI_and_rejection_controls"] = {"logical_spans": 3, "flat_C_ABI_parameters": 6,
            "actual_records": len(result["native_entry_attempts"]),
            "actual_argument_counts": dict(Counter(r["argument_count"] for r in result["native_entry_attempts"])),
            "negative_controls": negatives, "old_predicate": False, "corrected_predicate": True,
            "product_native_code_executed_by_controls": False,
            "ABI_sources": {"bridge": pin(bridge), "image_class": pin(image)}}

    def compiler_original_observer(self):
        control = self.raw("control/native_support.py")
        namespace = {"read": self.record_read, "require": require, "Path": Path, "json": json,
                     "sha256": sha256, "GENERATED": GENERATED, "NATIVE_LIMITS": NATIVE_LIMITS,
                     "QUALIFY_SHA": literal(control, "QUALIFY_SHA"), "CHILD_SHA": literal(control, "CHILD_SHA")}
        observe = pure_function(control, "observe_compiler_bundle", namespace)
        before = observe(Path(self.remote_source), Path(self.path("evidence/compiler")))
        combined = observe(Path(self.remote_source), Path(self.path("evidence/compiler")),
                           Path(self.path("evidence/finite/work/build")))
        prep = self.obj("evidence/compiler/report.json")
        driver = self.obj("evidence/report.json")
        self.check(before == prep["compiler_bundle_before"] == prep["compiler_bundle_after"]
                   == driver["preparation"]["compiler_bundle"] == driver["compiler_after"],
                   "unchanged_original_compiler_observer_all_actual_records_equal")
        self.check(combined == driver["compiler_and_component_before"] == driver["compiler_and_component_after"],
                   "unchanged_original_observer_component_full_bundle_equal")
        self.check(prep["B1_receipt"] == before["stages"]["B1"]["receipt"]
                   and prep["B2_receipt"] == before["stages"]["B2"]["receipt"],
                   "two_original_preparation_receipts_whole_equal")
        common = self.raw("control/source_common.py")
        measure = pure_function(common, "measurements", {})
        asm = self.raw("evidence/compiler/bounded-read.hiaasm", prep["assembly"])
        abi = self.raw("evidence/compiler/source-entry-abi.json", prep["entry_abi"])
        observed, functions = measure(self.obj("evidence/compiler/bounded-read.hia.json", prep["core_document"]), asm)
        limits = literal(control, "LIMITS")
        self.check(observed == prep["measurements"] and functions == prep["functions"]
                   and observed["functions"] == 14 and all(observed[k] <= v for k, v in limits.items())
                   and asm == self.source_raw(GENERATED)
                   and abi == self.source_raw("hepta/hia_bounded_read_abi.json"),
                   "actual_saved_Core_document_all_original_caps_and_exact_HIA_ABI")
        self.facts["actual_images"] = {"compiler": pin(self.raw("evidence/compiler/B2.image.bin")),
            "component": pin(self.raw("evidence/finite/work/build/bounded-read.image.bin")),
            "source": pin(asm), "ABI": pin(abi)}

    def package_request_and_five_commands(self):
        base = "evidence/installation/"
        value = self.obj(base + "package-report.json")
        root, installed = Path(self.path(base.rstrip("/"))), Path(self.path(base + "installed"))
        source, control = Path(self.remote_source), Path(self.path("control"))
        original = self.raw("control/actions_verify.py")
        ids = list(literal(self.raw("control/installed_cases.py"), "IDS"))
        namespace = {"value": value, "CANDIDATE": CANDIDATE, "CANDIDATE_TREE": TREE,
                     "source": source, "root": root, "ids": ids}
        self.frozen_check(original, "verify_installation", "complete actual package report conjunction differs",
                          namespace, "exact_original_package_header_conjunction")
        head = value["source_head_original"]
        self.check(head == value["source_head_after"] and head["path"] == self.remote_source + "/.git/HEAD"
                   and head["bytes"] == 41 and head["sha256"] == sha256((CANDIDATE + "\n").encode()).hexdigest(),
                   "original_reported_detached_HEAD_byte_binding_no_live_git_claim")
        inputs = {r["path"]: self.source_raw(r["path"]) for r in value["source_inputs_after"]}
        declarations = value["actual_resource_declarations"]
        resources = ["docs/" + n for n in declarations["DISCOVERY_FILES"]] + declarations["NATIVE_SOURCE_FILES"] + declarations["PUBLICATION_BUILD_FILES"]
        child_raw, child_record = self.record_read(root / "control/installed_cases.py", 1 << 20)
        self.check(child_raw == self.raw("control/installed_cases.py") and child_record == value["executed_child"],
                   "actual_installed_child_is_the_fixed_script")
        immutable = value["immutable_inputs_after"]
        for key, remote in (("image", self.path("evidence/finite/work/build/bounded-read.image.bin")),
                            ("compiler", self.path("evidence/compiler/B2.image.bin")),
                            ("child_script", self.path("control/installed_cases.py"))):
            self.check(immutable[key] == self.record_read(remote, 64 << 20)[1], "installation_actual_immutable_input:" + key)
        self.check(immutable["python"] == self.context["python"]["binary"],
                   "installation_reported_external_Python_identity_equal_not_external_byte_recovery")
        manifest, manifest_record = self.record_read(root / "native/manifest.json", 16384)
        image, image_record = self.record_read(root / "native/native.bin", 1 << 20)
        expected = {"schema": "hia.bounded-read.installed-request.v1", "scope": "DEVELOPMENT_INSTALLATION",
            "candidate_commit": CANDIDATE, "source_head_original": head,
            "installation_root": str(root), "installed_root": str(installed),
            "manifest_path": str(root / "native/manifest.json"), "manifest_original": manifest_record,
            "image_original": image_record, "compiler_input": immutable["compiler"],
            "source_sha256": sha256(inputs[GENERATED]).hexdigest(),
            "bridge_sha256": sha256(inputs["hepta/hia_bounded_read_native.py"]).hexdigest(),
            "abi_sha256": sha256(inputs["hepta/hia_bounded_read_abi.json"]).hexdigest(),
            "child_script": child_record, "source_checkout": self.remote_source, "source_resource": GENERATED,
            "expected_test_ids": ids, "expected_native_read_returns": 7, "installed_before": value["installed_before"],
            "module_names": sorted(n for n in inputs if n.startswith("hepta/") and n.endswith(".py")),
            "resource_names": resources, "output": str(root / "installed-cases.json"),
            "qualification_seconds": 5, "cleanup_seconds": 3,
            "formal_cold_qualification": False, "CLI_replacement_tested": False}
        self.check(self.obj(base + "installed-request.json", value["installed_request"]) == expected,
                   "complete_original_installed_request_all_fields_equal")
        environment = {"PATH": str(Path(self.python).parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_CONFIG_FILE": "/dev/null"}
        version = 'import importlib.metadata,json;print(json.dumps({k:importlib.metadata.version(k) for k in ("pip","setuptools","wheel")},sort_keys=True))'
        sdist, wheel = value["sdist"]["path"], value["wheel"]["path"]
        commands = [
            ("packaging-tools", 15, root / "consumer-cwd", [self.python, "-I", "-B", "-c", version], environment),
            ("sdist", 120, root / "package-source", [self.python, "-I", "-B", "setup.py", "sdist", "--dist-dir", str(root / "sdist")], environment),
            ("wheel", 120, root / "consumer-cwd", [self.python, "-I", "-B", "-m", "pip", "--isolated", "wheel", "--no-cache-dir", "--no-deps", "--no-index", "--no-build-isolation", "--wheel-dir", str(root / "wheels"), sdist], environment),
            ("install", 120, root / "consumer-cwd", [self.python, "-I", "-B", "-m", "pip", "--isolated", "install", "--no-cache-dir", "--no-deps", "--no-index", "--no-compile", "--target", str(installed), wheel], environment),
            ("installed-child", 5, root / "consumer-cwd", [self.python, "-I", "-S", "-B", str(root / "control/installed_cases.py"), "--request", str(root / "installed-request.json"), "--request-sha256", sha256(self.raw(base + "installed-request.json")).hexdigest()], {"PATH": "", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})]
        for label, seconds, cwd, command, env in commands:
            request = self.obj(base + label + ".process-owner.json.request.json")
            self.check(request["command"] == command and request["cwd"] == str(cwd)
                       and request["env"] == env and request["qualification_seconds"] == seconds
                       and request["cleanup_seconds"] == 3, "entire_frozen_packaging_command_env_cwd:" + label)
        versions = self.obj(base + "packaging-tools.stdout.log")
        self.check(versions == value["packaging_versions"] and versions["setuptools"] == "78.1.1"
                   and versions["wheel"] == "0.46.3" and type(versions["pip"]) is str,
                   "actual_packaging_tool_versions_complete_stdout")

    def unchanged_installation_tail(self):
        """Run only the frozen verifier's previously unreached observation AST.

        The original 'from source_common import wire' is replaced by that exact
        pure function's AST. Reads map to authenticated archive byte originals,
        not to a fabricated physical runner tree. No package/product is imported.
        """
        raw = self.raw("control/actions_verify.py")
        node = function(raw, "verify_installation")
        start = next(i for i, n in enumerate(node.body) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == "expected_bytes" for t in n.targets))
        tail = node.body[start:]
        require(isinstance(tail[-1], ast.Return), "frozen tail boundary")
        body = []
        removed = []
        for n in tail[:-1]:
            if isinstance(n, ast.ImportFrom):
                require(n.module == "source_common" and len(n.names) == 1 and n.names[0].name == "wire",
                        "unreviewed import in observation tail")
                removed.append(ast.unparse(n))
            else:
                body.append(n)
        require(removed == ["from source_common import wire"], "exact pure wire substitution")
        package = self.obj("evidence/installation/package-report.json")
        result = self.obj("evidence/installation/installed-cases.json")
        inputs = {r["path"]: self.source_raw(r["path"]) for r in package["source_inputs_after"]}
        root = Path(self.path("evidence/installation"))
        ids = list(literal(self.raw("control/installed_cases.py"), "IDS"))
        namespace = {"result": result, "reads": result["native_reads"], "completed": result["native_entry_completed"],
            "ids": ids, "root": root, "installed": root / "installed", "inputs": inputs,
            "manifest": self.obj("evidence/installation/native/manifest.json"),
            "copied_image_pin": self.record_read(root / "native/native.bin", 1 << 20)[1],
            "source_sha": sha256(inputs[GENERATED]).hexdigest(),
            "abi_sha": sha256(inputs["hepta/hia_bounded_read_abi.json"]).hexdigest(),
            "read": self.record_read, "pin": pin, "Path": Path, "json": json}
        def observed_require(ok, message):
            self.check(bool(ok), "unchanged_original_tail:" + message)
        namespace["require"] = observed_require
        namespace["wire"] = pure_function(self.raw("control/source_common.py"), "wire", {"json": json})
        code = compile(ast.Module(body=body, type_ignores=[]), "<unchanged-original-post-ledger-observations>", "exec")
        exec(code, namespace)
        self.facts["post_failure_original_predicates"] = {
            "original_verifier": pin(raw), "first_original_line": node.body[start].lineno,
            "last_original_line": tail[-2].end_lineno, "all_original_observation_AST_preserved": True,
            "sole_import_substitution": removed[0], "read_mapping": "sealed bytes + original identity records; no live runner filesystem claim"}

    def complete_driver_summary(self):
        raw = self.raw("control/actions_verify.py")
        report = self.obj("evidence/report.json")
        self.frozen_check(raw, "verify_outputs", "complete actual driver result differs",
                          {"report": report, "CANDIDATE": CANDIDATE, "CANDIDATE_TREE": TREE},
                          "all_original_driver_header_scope_and_limits")
        result = self.obj("evidence/installation/installed-cases.json")
        package = self.obj("evidence/installation/package-report.json")
        installation = {"expected_ids": result["expected_test_ids"],
            "report": self.record_read(self.path("evidence/installation/package-report.json"), 32 << 20)[1],
            "cases": self.record_read(self.path("evidence/installation/installed-cases.json"), 8 << 20)[1],
            "request": self.record_read(self.path("evidence/installation/installed-request.json"), 4 << 20)[1],
            "installed_root": package["installed_root"], "manifest": package["manifest"]}
        self.frozen_check(raw, "verify_outputs", "driver installation summary does not match the actual records",
                          {"report": report, "installation": installation},
                          "all_original_post_installation_driver_summary_fields")
        prep = self.obj("evidence/compiler/report.json")
        limits = literal(self.raw("control/native_support.py"), "LIMITS")
        plan_pin = self.record_read(self.path("control/source-manifest.json"), 1 << 20)[1]
        self.frozen_check(raw, "verify_outputs", "fresh compiler source/cap/scope conjunction differs",
            {"preparation": prep, "CANDIDATE": CANDIDATE, "CANDIDATE_TREE": TREE,
             "plan_pin": plan_pin, "NATIVE_LIMITS": NATIVE_LIMITS, "LIMITS": limits,
             "git": report["source_git_after"]}, "original_fresh_compiler_header_and_caps")
        self.check(prep["source_git_before"] == prep["source_git_after"] == report["source_git_before"]
                   == report["source_git_after"] == self.obj("setup.json")["source_actual_HEAD"],
                   "all_original_git_identity_reports_equal_without_reopening_runner")
        for key, filename in (("support", "docs/HIA_SELFHOST_CORE_SUPPORT.json"),
                              ("coverage", "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json")):
            self.check(prep["current_contracts"][key] == pin(self.source_raw(filename)),
                       "actual_generated_in_memory_contract_record:" + key)
        self.check(prep["current_contracts"]["generated_in_memory_without_source_write"] is True,
                   "recorded_actual_generator_scope_without_generator_rerun")
        seed = self.obj("evidence/compiler/B0.receipt.json")
        self.check(prep["fresh_seed"]["receipt"] == seed
                   and seed["python"]["path"] == self.python
                   and seed["python"]["sha256"] == self.context["python"]["binary"]["sha256"]
                   and seed["python"]["version"] == self.context["python"]["version"],
                   "actual_B0_receipt_reported_runtime_identity_join")
        base_env = self.obj("evidence/processes/fresh-compiler.process-owner.json.request.json")["env"]
        self.check(set(base_env) == {"PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE"}
                   and base_env["LANG"] == base_env["LC_ALL"] == "C.UTF-8"
                   and base_env["PYTHONDONTWRITEBYTECODE"] == base_env["PYTHONNOUSERSITE"] == "1",
                   "top_product_environment_has_no_ambient_selector_or_loader")
        commands = [
            ("fresh-compiler", 60, [self.python, "-I", "-S", "-B", self.path("control/prepare_native.py"),
             "--source-root", self.remote_source, "--source-manifest", self.path("control/source-manifest.json"),
             "--output", self.path("evidence/compiler")]),
            ("finite-gate", 180, [self.python, "-I", "-S", "-B", self.remote_source + "/tools/qualify_hia_bounded_read.py",
             "--compiler", self.path("evidence/compiler/B2.image.bin"), "--development", "--output", self.path("evidence/finite")])]
        for label, seconds, command in commands:
            r = self.obj("evidence/processes/" + label + ".process-owner.json.request.json")
            self.check(r["command"] == command and r["cwd"] == self.remote_source
                       and r["env"] == base_env and r["qualification_seconds"] == seconds
                       and r["cleanup_seconds"] == 3, "complete_original_top_command:" + label)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    own = Path(__file__).parent
    request_raw = args.request.read_bytes()
    request = json_bytes(request_raw)
    args.output.mkdir(mode=0o700)
    report = {"schema": "hepta.hia.bounded-read-corrected-readonly-original-audit.v1",
        "status": "HOLD", "run_id": 43191718592, "artifact_id": 13930698085,
        "original_workflow_status": "failure", "original_FINAL_status": "HOLD",
        "source_commit": CANDIDATE, "source_tree": TREE, "request": pin(request_raw),
        "new_product_execution": False, "native_images_invoked": False,
        "installation_rerun": False, "original_outputs_modified": False,
        "original_workflow_failure_reclassified": False, "formal_cold_or_full_qualification_claimed": False,
        "errors": [], "checks": [], "facts": {}}
    archive = Path(request["archive_path"])
    raw = None
    audit = None
    try:
        require(request["schema"] == "hepta.hia.bounded-read-corrected-readonly-request.v1"
                and request["source_commit"] == CANDIDATE and request["original_run"] == 43191718592,
                "fixed read-only request differs")
        for name, expected in request["controls"].items():
            require(pin((own / name).read_bytes()) == expected, "frozen read-only control differs: " + name)
        raw = archive.read_bytes()
        require(len(raw) == ARCHIVE_BYTES and sha256(raw).hexdigest() == ARCHIVE_SHA,
                "same sealed original ZIP is required")
        originals = Originals(raw)
        originals.read_zip(); originals.read_typed()
        final_raw = originals.public("FINAL.json")
        final = json_bytes(final_raw)
        require(sha256(final_raw).hexdigest() == ORIGINAL_FINAL_SHA and final["status"] == "HOLD"
                and len(final["errors"]) == 1 and LEDGER_MESSAGE in final["errors"][0]["traceback"],
                "original HOLD identity or exact failure changed")
        report["original_errors"] = final["errors"]
        audit = ClosedOriginalAudit(originals, Path(request["original_controls"]),
            Path(request["canonical_source"]), Path(request["git_dir"]), 43191718592)
        for name in ("controls_and_outer", "source_reports", "arity_and_negative_controls",
                     "owners", "compiler", "compiler_original_observer", "finite", "installation",
                     "package_request_and_five_commands", "unchanged_installation_tail", "complete_driver_summary"):
            audit.stage(name, getattr(audit, name))
        report["checks"], report["errors"], report["facts"] = audit.checks, audit.failures, audit.facts
        report["canonical_source_bytes_read"] = len(audit.source_cache)
        report["original_archive"] = pin(raw)
        report["original_final"] = pin(final_raw)
        report["original_case_report"] = pin(audit.raw("evidence/installation/installed-cases.json"))
        report["scope"] = "Authenticated original bytes and recorded identities; no reconstruction of live runtime state and no new product execution. The six-argument assertion is corrected only in this reader."
        if not audit.failures:
            report["status"] = "CORRECTED_READONLY_AUDIT_PASS_ORIGINAL_WORKFLOW_FAIL_AND_FINAL_HOLD_PRESERVED"
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()})
    finally:
        try:
            if raw is not None:
                require(archive.read_bytes() == raw, "original archive changed during read-only audit")
            require(args.request.read_bytes() == request_raw, "request changed")
            for name, expected in request["controls"].items():
                require(pin((own / name).read_bytes()) == expected, "read-only control changed: " + name)
            report["original_archive_and_controls_unchanged"] = True
        except BaseException as error:
            report["status"] = "HOLD"
            report["errors"].append({"phase": "final_readback", "type": type(error).__name__, "traceback": traceback.format_exc()})
        save(args.output, "REPORT.json", report)
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]),
                      "errors": report["errors"], "new_product_execution": False}))
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
