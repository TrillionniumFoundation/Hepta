"""Independent readback of one closed bounded-read Actions development run.

This reader does not import a product module, execute a native image or reuse
the worker's PASS flag as proof. Its caller must first bind the original outer
guardian to this exact request and prove a closed ECHILD boundary.
"""
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path

from source_common import fixed_read, measurements, pin, read, require, snapshot
from native_support import (CANDIDATE, CANDIDATE_TREE, GENERATED, LIMITS,
    NATIVE_LIMITS, OWNER_SHA, SELECTOR, generated_rows, natural_process,
    observe_compiler_bundle, source_manifest)
from git_binding import source_git

ANOMALIES = {"skips", "expected_failures", "unexpected_successes", "failures", "errors"}

def original(path, expected=None, maximum=8 << 20):
    raw, actual = read(path, maximum)
    if expected is not None:
        require(expected["path"] == str(path) and expected["bytes"] == len(raw)
                and expected["sha256"] == actual["sha256"], "retained original bytes differ")
        if "identity" in expected:
            require(expected["identity"] == actual["identity"], "retained original identity differs")
        if "git_blob_sha1" in expected:
            require(expected["git_blob_sha1"] == pin(raw)["git_blob_sha1"], "original Git blob differs")
    return json.loads(raw), actual

def verify_owned_step(step, base, source, command, environment, seconds):
    label = step["label"]
    out, err = base / (label + ".stdout.log"), base / (label + ".stderr.log")
    receipt_path = base / (label + ".process-owner.json")
    request_path = Path(str(receipt_path) + ".request.json")
    receipt, receipt_pin = original(receipt_path, step["receipt"], 4 << 20)
    request, request_pin = original(request_path, step["request"], 1 << 20)
    returned = dict(receipt, supervisor_returncode=0, receipt_sha256=receipt_pin["sha256"])
    require(step["status"] == "OWNED_STEP_PASS" and step["cleanup_closed_before_original_read"] is True
            and not step.get("custody_errors") and not step.get("custody_deferred_until_outer_cleanup")
            and step["command"] == command and step["cwd"] == str(source)
            and step["qualification_seconds"] == seconds and step["cleanup_seconds"] == 3
            and step["owner_returned"] == returned,
            "actual inner owner returned projection differs")
    require(request["schema"] == receipt["schema"] == "hepta.hia.selfhost-process-owner.v1"
            and request["stdout_path"] == str(out) and request["stderr_path"] == str(err)
            and request["receipt_path"] == str(receipt_path)
            and request["implementation_sha256"] == receipt["implementation_sha256"] == OWNER_SHA
            and receipt["request_sha256"] == request_pin["sha256"]
            and type(request["started_ns"]) is int and type(request["deadline_ns"]) is int
            and request["deadline_ns"] - request["started_ns"] == int(seconds * 1000000000),
            "inner original request/receipt identity or deadline differs")
    natural_process(receipt, returned, request, command, source, environment, seconds)
    paths = (out, err, receipt_path, request_path, Path(str(receipt_path) + ".stdout.log"),
             Path(str(receipt_path) + ".stderr.log"))
    actual_files = [read(path, 16 << 20)[1] for path in paths]
    require(step["original_files"] == actual_files and step["stdout"] == actual_files[0]
            and step["stderr"] == actual_files[1], "complete six inner owner originals differ")
    stored, _ = original(base / (label + ".step.json"))
    require(stored == step, "inner stored step differs from driver report")
    return {"label": label, "request": request_pin, "receipt": receipt_pin,
            "qualification_pid": receipt["qualification_pid"], "seconds": seconds,
            "cleanup_seconds": 3, "natural_ECHILD": True}

def population(group, report):
    ids = group["expected_ids"]
    require(group["method_count"] == len(ids) and len(set(ids)) == len(ids)
            and report["schema"] == group["schema"] and report["status"] == group["status"]
            and report["expected_ids"] == report["loaded_ids"] == report["executed_ids"] == ids
            and report["errors"] == [] and set(report["anomalies"]) == ANOMALIES
            and all(type(v) is list and not v for v in report["anomalies"].values()),
            "original complete population or five-anomaly result differs")

def verify_callers(source, evidence, report, manifest_pin, manifest, parent_pid, python):
    base = evidence / "original-eight"
    require(report["testsRun"] == report["original_method_denominator"] == 8
            and report["original_CLI_child_denominator"] == len(report["children"]) == 7
            and report["actual_native_read_attempts"] == 12 and report["actual_native_read_returns"] == 11
            and report["original_CLI_timeout_seconds"] == 20 and report["loader_errors"] == [],
            "original eight and seven CLI denominator differs")
    require(report["manifest"] == manifest_pin, "callers actual manifest differs")
    require(set(report["source_pins"]) == {"tests/test_hia_program_tools.py", "tools/hia_core_reference.py",
        "hepta/hia_program_tools.py", "hepta/hia_bounded_read_native.py", GENERATED},
        "complete original caller source map differs")
    for name, expected in report["source_pins"].items():
        require(pin(read(source / name, 1 << 20)[0]) == expected, "callers actual source differs")
    policy, policy_pin = original(base / "child-policy.json", report["child_policy"], 1 << 20)
    require(policy == {"schema": "hepta.hia.bounded-read-original-eight-child-policy.v1",
        "source": str(source), "source_pins": report["source_pins"], "manifest": manifest_pin["path"],
        "manifest_sha256": manifest_pin["sha256"], "image_sha256": manifest["image_sha256"],
        "parent_pid": parent_pid, "children": str(base / "children"),
        "parent_record": str(base / "parent-original.json")}, "original child selector policy differs")
    parent, parent_pin = original(base / "parent-original.json", maximum=4 << 20)
    require(parent == report["parent"] and parent["pid"] == parent_pid, "actual original parent differs")
    def observer(value, role):
        require(value["schema"] == "hepta.hia.bounded-read-original-caller-observer.v1"
                and value["status"] == "ORIGINAL_CALLER_OBSERVER_PASS" and value["role"] == role
                and value["policy_sha256"] == policy_pin["sha256"] and value["source"] == str(source)
                and value["manifest"] == manifest_pin["path"] and value["retained_owner_calls"] == []
                and value["source_before"] == value["source_after"]
                and value["bundle_before"] == value["bundle_after"]
                and value["native_before"] == value["native_after"]
                and value["actual_executable"] == python
                and value["original_CLI_timeout_seconds_unchanged"] == 20,
                "actual caller source/image/retained owner observation differs")
        for name, expected in value["source_after"].items():
            raw, actual = read(source / name, 1 << 20)
            require(expected == actual,
                    "actual observer source pin differs")
        require(value["bundle_after"] == {"manifest": manifest_pin,
                "image": read(Path(manifest_pin["path"]).parent / manifest["image_path"], 1 << 20)[1]},
                "observer actual native bundle differs")
        calls = value["read_calls"]
        require(calls and value["ledger_after"]["calls"] - value["ledger_before"]["calls"] == len(calls)
                and all(row["native_calls_after"] == row["native_calls_before"] + 1
                        and row["native_transitions_after"] > row["native_transitions_before"]
                        and row["outcome"] in ("returned", "raised") for row in calls),
                "actual native caller attempts/returns differ")
    observer(parent, "parent")
    require(len(parent["read_calls"]) == 4 and Counter(r["outcome"] for r in parent["read_calls"])
            == Counter({"returned": 3, "raised": 1}), "parent ordinary and symlink calls differ")
    commands, seen, rows, total = Counter(), set(), [], 0
    for entry in report["children"]:
        child = entry["result"]
        pid = child["pid"]
        require(type(pid) is int and pid > 0 and pid not in seen, "duplicate original child PID")
        seen.add(pid)
        actual, child_pin = original(base / "children" / ("child-%d.json" % pid), entry["record"], 4 << 20)
        beginning, start_pin = original(base / "children" / ("start-%d.json" % pid), entry["start"], 65536)
        require(actual == child and child["parent_pid"] == parent_pid
                and beginning["schema"] == "hepta.hia.bounded-read-original-caller-start.v1"
                and beginning["pid"] == pid and beginning["parent_pid"] == parent_pid
                and beginning["policy_sha256"] == policy_pin["sha256"]
                and beginning["source"] == str(source) and beginning["manifest"] == manifest_pin["path"]
                and beginning["native_identity"] == child["native_before"], "child start/completion differs")
        observer(child, "child")
        argv = child["argv"]
        require(argv[0] == str(source / "tools/hia_core_reference.py")
                and argv[1] in ("verify", "run", "inspect", "patch"), "another CLI entered population")
        count = 2 if argv[1] == "patch" else 1
        require(len(child["read_calls"]) == count
                and all(r["outcome"] == "returned" for r in child["read_calls"]), "CLI read count differs")
        commands[argv[1]] += 1
        total += count
        rows.append({"start": start_pin, "completion": child_pin})
    actual_names = {p.name for p in (base / "children").iterdir()}
    require(actual_names == {kind + "-%d.json" % pid for pid in seen for kind in ("start", "child")}
            and len(seen) == 7 and total == 8
            and commands == Counter({"verify": 2, "run": 3, "inspect": 1, "patch": 1}),
            "complete seven CLI namespace and command population differs")
    return {"parent": parent_pin, "policy": policy_pin, "children": rows,
            "original_methods": 8, "CLI_children": 7, "native_attempts": 12, "native_returns": 11}

def runtime_environment():
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}


def current_source_map(source):
    raw, _ = read(source / "docs/HIA_SELFHOST_CORE_SUPPORT.json", 8 << 20)
    value = json.loads(raw)
    mapping = value["source_identity"]["files"]
    require(type(mapping) is dict and len(mapping) == 815,
            "complete current declared source denominator differs")
    for name, digest in mapping.items():
        require(type(name) is str and not name.startswith("/") and "\\" not in name
                and all(part not in ("", ".", "..", ".git") for part in name.split("/"))
                and read(source / name, 64 << 20)[1]["sha256"] == digest,
                "current declared source bytes differ: " + str(name))
    return dict(mapping, **{"docs/HIA_SELFHOST_CORE_SUPPORT.json": sha256(raw).hexdigest()})


def verify_finite(source, directory, compiler, python):
    """Read all original public qualifier owners, 55 details and seven CLI pairs."""
    work = directory / "work"
    final, final_pin = original(directory / "acceptance.json", maximum=8 << 20)
    require(final["schema"] == "hepta.hia.bounded-read-finite-acceptance.v1"
            and final["status"] == "FINITE_BOUNDED_READ_VALIDATION_PASS"
            and final["product_full_qualification"] is False and final["errors"] == []
            and final["outer_seconds"] == 180 and final["cleanup_seconds"] == 3
            and final["scope"] == "FINITE_55_PLUS_ORIGINAL_8_AND_7_CLI_NOT_FULL_QUALIFICATION"
            and len(final["processes"]) == 1, "actual public qualifier final result differs")
    command = [python, "-B", str(source / "tools/qualify_hia_bounded_read.py"), "--worker",
               "--output", str(work), "--compiler", str(compiler), "--development"]
    require(final["processes"][0]["label"] == "validation", "public outer owner label differs")
    owners = [verify_owned_step(final["processes"][0], directory, source, command,
                               runtime_environment(), 180)]
    report, report_pin = original(work / "report.json", final["report"], 32 << 20)
    require(report["schema"] == "hepta.hia.bounded-read-finite-validation.v1"
            and report["status"] == "FINITE_BOUNDED_READ_VALIDATION_PASS"
            and report["errors"] == [] and report["source_preserved"] is True
            and report["outer_seconds"] == 180 and report["cleanup_seconds"] == 3
            and report["finite_component_cases"] == 55 and report["original_methods"] == 8
            and report["original_CLI_children"] == 7 and report["original_CLI_child_timeout_seconds"] == 20
            and report["filesystem_and_context_operations_remain_hosted"] is True
            and all(report[key] is False for key in ("production_activated", "all_input_equivalence_proved",
                        "cold_qualification", "whole_native_delivery_qualified"))
            and report["python"] == {"implementation": "CPython", "version": "3.14.4", "executable": python}
            and len(report["processes"]) == 6 and len(report["groups"]) == 5,
            "actual public qualifier full conjunction differs")
    sources = current_source_map(source)
    require(report["source_before"] == report["source_after"] == sources,
            "public qualifier source closure differs from actual files")
    compiler_raw, compiler_pin = read(compiler, 1 << 20)
    require(report["compiler_before"] == report["compiler_after"] == {
        "bytes": len(compiler_raw), "sha256": compiler_pin["sha256"]}, "public compiler changed")
    build_directory = work / "build"
    command = [python, "-B", str(source / "tools/build_hia_bounded_read.py"),
               "--compiler", str(compiler), "--output", str(build_directory), "--development"]
    require(report["processes"][0]["label"] == "build", "public build owner label differs")
    owners.append(verify_owned_step(report["processes"][0], work, source, command,
                                   runtime_environment(), 60))
    build, build_pin = original(build_directory / "build.json", report["build"]["record"], 8 << 20)
    manifest, manifest_pin = original(build_directory / "manifest.json", maximum=16384)
    assembly, assembly_pin = read(source / GENERATED, 1 << 20)
    abi_raw, _ = read(source / "hepta/hia_bounded_read_abi.json", 16384)
    image_raw, image_pin = read(build_directory / "bounded-read.image.bin", 1 << 20)
    wanted_manifest = {"schema": "hepta.hia.bounded-read-native.v3",
        "source_sha256": assembly_pin["sha256"], "image_path": "bounded-read.image.bin",
        "image_sha256": image_pin["sha256"], "compiler_sha256": compiler_pin["sha256"]}
    bundle = {"manifest": manifest_pin, "image": image_pin, "value": wanted_manifest}
    require(manifest == wanted_manifest and report["bundle_before"] == report["bundle_after"] == bundle
            and build["schema"] == "hepta.hia.bounded-read-build.v1"
            and build["status"] == "NATIVE_CANDIDATE_BUILT"
            and build["scope"] == report["build"]["scope"] == "DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD"
            and build["source_manifest"] == sources and build["compiler_sha256"] == compiler_pin["sha256"]
            and build["cold_report_sha256"] is None and build["manifest"] == manifest
            and build["manifest_sha256"] == manifest_pin["sha256"]
            and build["source_owned_abi"] == json.loads(abi_raw)
            and build["source_owned_abi_sha256"] == sha256(abi_raw).hexdigest()
            and build["build_inputs_stable"] is True
            and build["filesystem_and_context_operations_remain_hosted"] is True
            and all(build[name] is False for name in (
                "production_activated", "all_input_equivalence_proved", "whole_native_delivery_qualified")),
            "actual source-owned development build differs")
    require(set(build["owned_source_sha256"]) == set(('examples/hia_bootstrap/bounded_read.hiaasm', 'hepta/hia_bounded_read_abi.json', 'hepta/hia_bounded_read_native.py', 'hepta/hia_program_tools.py', 'hepta/hia_json_preflight_native.py', 'hepta/hia_worker_report_native.py', 'tools/generate_hia_bounded_read.py', 'tools/build_hia_bounded_read.py', 'tools/qualify_hia_bounded_read.py', 'tools/hia_selfhost_process_owner.py', 'tools/qualify_hia_selfhost.py', 'tools/hia_selfhost_child.py', 'tests/test_hia_bounded_read_source.py', 'tests/test_hia_program_tools.py', 'tests/fixtures/hia_program_tools_acffa.py.txt', 'tools/hia_core_reference.py', 'hepta/hia_agent_contract.py', 'MANIFEST.in', 'setup.py', 'pyproject.toml', 'docs/HIA_BOUNDED_READ_NATIVE.md', 'tools/hia_bounded_read_checks/source_common.py', 'tools/hia_bounded_read_checks/populations.json', 'tools/hia_bounded_read_checks/reject_cases.py', 'tools/hia_bounded_read_checks/lifetime_cases.py', 'tools/hia_bounded_read_checks/permission_cases.py', 'tools/hia_bounded_read_checks/filesystem_cases.py', 'tools/hia_bounded_read_checks/original_eight.py', 'tools/hia_bounded_read_checks/caller_observer.py')),
            "complete owned build input population differs")
    for name, digest in build["owned_source_sha256"].items():
        require(sources.get(name) == digest, "build input not in actual current source closure")
    combined = observe_compiler_bundle(source, compiler.parent, build_directory)
    require(build["native_compile_receipt"] == combined["stages"]["bounded-read"]["receipt"],
            "actual public build receipt differs from independent full-byte compiler readback")
    expected_compile_names = {"bounded-read." + suffix for suffix in (
        "request.json", "stdout.log", "receipt.json", "output.bin", "image.bin", "stderr.log", "input.bin")}
    require(set(build["compiler_originals"]) == expected_compile_names,
            "public builder complete original namespace differs")
    for name, expected in build["compiler_originals"].items():
        raw, actual = read(build_directory / name, 4 << 20)
        require(expected == {"bytes": len(raw), "sha256": actual["sha256"]},
                "public builder original output differs")
    frozen, frozen_pin = original(source / "tools/hia_bounded_read_checks/populations.json", maximum=65536)
    groups = frozen["groups"]
    names = ["reject", "lifetime", "permission", "filesystem", "original-eight"]
    require(frozen["finite_component_cases"] == 55 and frozen["original_methods"] == 8
            and frozen["original_CLI_children"] == 7 and frozen["original_CLI_child_timeout_seconds"] == 20
            and [row["name"] for row in groups] == names
            and [row["method_count"] for row in groups] == [12, 24, 10, 9, 8]
            and [row["qualification_seconds"] for row in groups] == [30, 30, 30, 30, 180]
            and [row["name"] for row in report["groups"]] == names
            and [row["label"] for row in report["processes"]] == ["build"] + names,
            "complete fixed public populations differ")
    selected = dict(runtime_environment(), **{SELECTOR: str(build_directory / "manifest.json")})
    summaries, details, caller = [], [], None
    for index, group in enumerate(groups):
        name = group["name"]
        folder = work / name
        command = [python, "-B", str(source / "tools/hia_bounded_read_checks" / group["script"]),
                   "--source-root", str(source), "--manifest", str(build_directory / "manifest.json"),
                   "--output", str(folder)]
        if group["oracle"]:
            command += ["--oracle", str(source / "tests/fixtures/hia_program_tools_acffa.py.txt")]
        owner = verify_owned_step(report["processes"][index + 1], work, source, command,
                                  selected, group["qualification_seconds"])
        owners.append(owner)
        row = report["groups"][index]
        result, observed = original(folder / "report.json", row["report"], 16 << 20)
        population(group, result)
        require(result == row["result"], "group original/report body differs")
        actual_originals = []
        if name != "original-eight":
            require([entry["id"] for entry in result["cases"]] == group["expected_ids"]
                    and all(entry["status"] == "PASS" for entry in result["cases"]),
                    "complete finite detail population differs")
            for entry in result["cases"]:
                detail, detail_pin = original(folder / (entry["id"] + ".json"),
                                              entry.get("record", entry.get("original")), 4 << 20)
                require(detail["id"] == entry["id"] and detail["status"] == "PASS",
                        "finite case original failed")
                if name in ("reject", "lifetime"):
                    require(detail["real_native_entry_required"] is True,
                            "native differential entry was not required")
                elif name == "permission":
                    require(type(detail["actual_native_entry_returns"]) is int
                            and detail["actual_native_entry_returns"] > 0
                            and detail["terminal_permission_sealed"] is True,
                            "native one-use terminal permission differs")
                else:
                    require(detail["actual_native_call_delta"] == 1
                            and type(detail["actual_native_transition_delta"]) is int
                            and detail["actual_native_transition_delta"] > 0
                            and detail["retained_policy_calls"] == [], "native filesystem observation differs")
                actual_originals.append(detail_pin)
                details.append(detail_pin)
        else:
            caller = verify_callers(source, work, result, manifest_pin, manifest,
                                    owner["qualification_pid"], python)
            for child in result["children"]:
                for key in ("record", "start"):
                    path = Path(child[key]["path"])
                    require(path.parent == folder / "children", "caller original path differs")
                    actual_originals.append(read(path, 4 << 20)[1])
        require(row["originals"] == actual_originals, "all group original pins differ")
        summaries.append({"name": name, "report": observed, "expected_ids": group["expected_ids"]})
    require(len(details) == 55 and len(owners) == 7 and caller is not None,
            "complete public finite gate readback is missing")
    return {"acceptance": final_pin, "report": report_pin, "build": build_pin,
            "population": frozen_pin, "groups": summaries, "detail_originals": details,
            "owners": owners, "original_callers": caller, "source_members": len(sources),
            "finite_component_cases": 55, "original_methods": 8, "CLI_children": 7,
            "native_compile_wall_seconds": 20, "native_compile_CPU_seconds": 10,
            "development_only": True, "cold_qualification": False}


def verify_installation(source, evidence, control, python, component_image, compiler):
    """Independently join the five owned processes, archives, installed tree and nine cases."""
    import package_helper as package
    root = evidence / "installation"
    installed = root / "installed"
    value, value_pin = original(root / "package-report.json", maximum=32 << 20)
    ids = list(package.IDS)
    require(value["schema"] == "hia.bounded-read.development-installation.v1"
            and value["status"] == "DEVELOPMENT_INSTALLATION_PASS" and value["scope"] == "DEVELOPMENT_INSTALLATION"
            and value["candidate_commit"] == value["source_head"] == CANDIDATE
            and value["resource_baseline"] == {"commit": CANDIDATE, "tree": CANDIDATE_TREE}
            and value["source"] == str(source) and value["evidence"] == str(root)
            and value["expected_test_ids"] == ids and value["errors"] == []
            and value["source_resource_count"] == 105 and value["native_source_resource_count"] == 90
            and value["source_python_count"] == 170 and value["source_and_inputs_stable"] is True
            and value["installed_bytes_and_modes_restored"] is True
            and all(value[name] is False for name in ("native_compilation_performed_here",
                "formal_cold_qualification", "CLI_replacement_tested", "whole_native_delivery_qualified"))
            and [row["label"] for row in value["processes"]]
                == ["packaging-tools", "sdist", "wheel", "install", "installed-child"],
            "complete actual package report conjunction differs")
    head_raw, head_pin = read(source / ".git/HEAD", 128)
    require(head_raw == (CANDIDATE + "\n").encode()
            and value["source_head_original"] == value["source_head_after"] == head_pin,
            "actual package detached source head differs")
    inputs, source_rows, declarations, resources = package.source_inputs(source)
    require(source_rows == value["source_inputs_before"] == value["source_inputs_after"]
            and value["actual_resource_declarations"] == {k: list(v) for k, v in declarations.items()},
            "actual complete packaging source/resource inputs differ")
    immutable = {}
    for name, path in (("image", component_image), ("compiler", compiler),
                       ("child_script", control / "installed_cases.py"), ("python", Path(python))):
        _, immutable[name] = read(path, 64 << 20, system_binary=name == "python")
    require(value["immutable_inputs_before"] == value["immutable_inputs_after"] == immutable
            and value["owner_implementation"] == read(control / "process_owner_impl.py", 1 << 20)[1]
            and value["owner_implementation"]["sha256"] == OWNER_SHA,
            "actual installation compiler/image/control/runtime input differs")
    environment = {"PATH": str(Path(python).parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_CONFIG_FILE": "/dev/null"}
    versions_command = [python, "-I", "-B", "-c",
        'import importlib.metadata,json;print(json.dumps({k:importlib.metadata.version(k) for k in ("pip","setuptools","wheel")},sort_keys=True))']
    owners = [verify_owned_step(value["processes"][0], root, root / "consumer-cwd",
                               versions_command, environment, 15)]
    versions = json.loads(read(root / "packaging-tools.stdout.log", 1 << 20)[0])
    require(versions == value["packaging_versions"] and versions["setuptools"] == "78.1.1"
            and versions["wheel"] == "0.46.3" and type(versions["pip"]) is str,
            "actual installed packaging tools differ")
    owners.append(verify_owned_step(value["processes"][1], root, root / "package-source",
        [python, "-I", "-B", "setup.py", "sdist", "--dist-dir", str(root / "sdist")], environment, 120))
    sdist_path, wheel_path = Path(value["sdist"]["path"]), Path(value["wheel"]["path"])
    require(sdist_path.parent == root / "sdist" and sdist_path.name.endswith(".tar.gz")
            and list((root / "sdist").iterdir()) == [sdist_path]
            and wheel_path.parent == root / "wheels" and wheel_path.suffix == ".whl"
            and list((root / "wheels").iterdir()) == [wheel_path],
            "actual one-sdist/one-wheel namespace differs")
    sdist_pin, sdist_rows = package.sdist_inventory(sdist_path, inputs)
    wheel_pin, wheel_rows = package.wheel_inventory(wheel_path, inputs, resources)
    require(value["sdist"] == sdist_pin and value["sdist_members"] == sdist_rows
            and value["wheel"] == wheel_pin and value["wheel_members"] == wheel_rows,
            "actual full archive member bytes/CRC/modes differ")
    owners.append(verify_owned_step(value["processes"][2], root, root / "consumer-cwd",
        [python, "-I", "-B", "-m", "pip", "--isolated", "wheel", "--no-cache-dir", "--no-deps",
         "--no-index", "--no-build-isolation", "--wheel-dir", str(root / "wheels"), str(sdist_path)],
        environment, 120))
    owners.append(verify_owned_step(value["processes"][3], root, root / "consumer-cwd",
        [python, "-I", "-B", "-m", "pip", "--isolated", "install", "--no-cache-dir", "--no-deps",
         "--no-index", "--no-compile", "--target", str(installed), str(wheel_path)], environment, 120))
    now = package.inventory(installed)
    package.verify_installed(now, inputs, resources)
    require(now == value["installed_after"]
            and package.byte_projection(now) == package.byte_projection(value["installed_before"]),
            "actual restored installed bytes/modes differ; original inode equality is not required")
    manifest, manifest_pin = original(root / "native/manifest.json", value["manifest"], 16384)
    copied_image_raw, copied_image_pin = read(root / "native/native.bin", 1 << 20)
    source_sha = sha256(inputs[GENERATED]).hexdigest()
    bridge_sha = sha256(inputs["hepta/hia_bounded_read_native.py"]).hexdigest()
    abi_sha = sha256(inputs["hepta/hia_bounded_read_abi.json"]).hexdigest()
    require(manifest == {"schema": "hepta.hia.bounded-read-native.v3", "source_sha256": source_sha,
                "image_path": "native.bin", "image_sha256": immutable["image"]["sha256"],
                "compiler_sha256": immutable["compiler"]["sha256"]}
            and copied_image_raw == read(component_image, 1 << 20)[0]
            and copied_image_pin == value["native_image"]
            and value["installed_root"] == str(installed)
            and value["bridge_path"] == str(installed / "hepta/hia_bounded_read_native.py")
            and value["manifest_path"] == str(root / "native/manifest.json"),
            "installed selectable bundle does not match actual fresh build")
    child_source, child_pin = read(root / "control/installed_cases.py", 1 << 20)
    require(child_source == inputs_or_control(control / "installed_cases.py")
            and child_pin == value["executed_child"], "actual executed installed child source differs")
    request, request_pin = original(root / "installed-request.json", value["installed_request"], 4 << 20)
    expected_request = {"schema": "hia.bounded-read.installed-request.v1", "scope": "DEVELOPMENT_INSTALLATION",
        "candidate_commit": CANDIDATE, "source_head_original": head_pin,
        "installation_root": str(root), "installed_root": str(installed),
        "manifest_path": str(root / "native/manifest.json"), "manifest_original": manifest_pin,
        "image_original": copied_image_pin, "compiler_input": immutable["compiler"],
        "source_sha256": source_sha, "bridge_sha256": bridge_sha, "abi_sha256": abi_sha,
        "child_script": child_pin, "source_checkout": str(source), "source_resource": GENERATED,
        "expected_test_ids": ids, "expected_native_read_returns": 7,
        "installed_before": value["installed_before"],
        "module_names": sorted(name for name in inputs if name.startswith("hepta/") and name.endswith(".py")),
        "resource_names": list(resources), "output": str(root / "installed-cases.json"),
        "qualification_seconds": 5, "cleanup_seconds": 3,
        "formal_cold_qualification": False, "CLI_replacement_tested": False}
    require(request == expected_request, "complete actual installed request differs")
    child_environment = {"PATH": "", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    owners.append(verify_owned_step(value["processes"][4], root, root / "consumer-cwd",
        [python, "-I", "-S", "-B", str(root / "control/installed_cases.py"),
         "--request", str(root / "installed-request.json"), "--request-sha256", request_pin["sha256"]],
        child_environment, 5))
    result, result_pin = original(root / "installed-cases.json", value["installed_cases"], 8 << 20)
    require(result["schema"] == "hia.bounded-read.installed-cases.v1"
            and result["status"] == "DEVELOPMENT_INSTALLED_CASES_PASS"
            and result["scope"] == "DEVELOPMENT_INSTALLATION"
            and result["request_sha256"] == request_pin["sha256"]
            and result["expected_test_ids"] == result["loaded_test_ids"] == result["executed_test_ids"] == ids
            and result["tests_run"] == 9
            and all(type(result[key]) is int and result[key] == 0 for key in (
                "failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
            and result["isolated_no_site"] is True and result["empty_PATH"] is True
            and result["cold_qualified"] is False and result["CLI_replacement_tested"] is False
            and result["forbidden_authoring_attempts"] == result["forbidden_retained_owner_attempts"] == []
            and result["installed_source_bytes_and_modes_restored"] is True
            and result["installed_after"] == now
            and [row["id"] for row in result["cases"]] == ids
            and all(row["status"] == "PASS" for row in result["cases"]),
            "complete installed nine-case result differs")
    attempts, completed, reads = result["native_entry_attempts"], result["native_entry_completed"], result["native_reads"]
    require(type(result["native_completions"]) is int and result["native_completions"] == len(attempts) == len(completed) > 0
            and result["native_read_returns"] == len(reads) == 7
            and [row["id"] for row in reads] == [ids[0], ids[5], ids[6], ids[7], ids[8], ids[8], ids[8]]
            and sum(row["status"] == 0 for row in completed) == 7
            and all(a["case"] == b["case"] and a["argument_count"] == 3
                    and type(a["returned_status"]) is int and a["returned_status"] == b["status"]
                    and b["status"] in (0, 1) for a, b in zip(attempts, completed, strict=True)),
            "actual installed native completion ledger differs")
    expected_bytes = [b"bounded\0read\xff"] * 4 + [b"", b"x" * (8 << 20), b"bounded\0read\xff"]
    reconstructed = []
    for index, (row, raw) in enumerate(zip(reads, expected_bytes, strict=True)):
        path = root / "fixtures" / ("read-%03d.bin" % index)
        actual, fixture_pin = read(path, 8 << 20)
        require(actual == raw and row["fixture"] == fixture_pin
                and row["input"] == row["output"] == pin(raw)
                and row["native_read_returns"] == 1
                and row["native_calls_after"] == row["native_calls_before"] + 1
                and type(row["native_completed_calls"]) is int and row["native_completed_calls"] >= 2
                and row["native_statuses"] == [1] * (row["native_completed_calls"] - 1) + [0],
                "actual installed public read bytes or continuation sequence differs")
        reconstructed.extend({"case": row["id"], "status": status} for status in row["native_statuses"])
    require(reconstructed == completed
            and [row["native_completed_calls"] for row in result["cases"]]
                == [sum(r["case"] == name for r in completed) for name in ids],
            "complete native case ledger does not match all seven logical reads")
    names = ("schema", "source", "image", "shape", "compiler-format", "oversized", "duplicate-key")
    require(len(result["negative_manifest_originals"]) == len(names), "manifest negative population differs")
    negative_values = [dict(manifest, schema="hepta.hia.bounded-read-native.invalid"),
        dict(manifest, source_sha256="0" * 64), dict(manifest, image_sha256="0" * 64),
        dict(manifest, unexpected="not an admitted manifest field"), dict(manifest, compiler_sha256="g" * 64)]
    from source_common import wire
    expected_negative = []
    for item in negative_values:
        item["image_path"] = copied_image_pin["path"]
        expected_negative.append(wire(item))
    expected_negative.append(b" " * 16385)
    duplicate = wire(dict(manifest, image_path=copied_image_pin["path"]))
    expected_negative.append(b'{"schema":' + json.dumps(manifest["schema"]).encode() + b',' + duplicate[1:])
    for name, expected_raw, record in zip(names, expected_negative, result["negative_manifest_originals"], strict=True):
        actual, observed = read(root / "invalid-manifests" / (name + ".json"), 65536)
        require(actual == expected_raw and record == observed, "actual manifest-negative bytes differ")
    origins = result["module_origins"]
    require({"hepta.hia_bounded_read_native", "hepta.hia_program_tools", "hepta.hia_json_preflight_native"} <= set(origins),
            "actual installed module origins incomplete")
    for name, path in origins.items():
        path = Path(path)
        require((name == "hepta" or name.startswith("hepta.")) and installed in path.parents
                and path.relative_to(installed).as_posix() in inputs
                and read(path, 8 << 20)[0] == inputs[path.relative_to(installed).as_posix()],
                "installed module origin is not the actual package source")
    observations = result["cases"][0]["observations"]
    require(observations["python_modules"] == 170 and observations["source_resources"] == 105
            and observations["admitted_source_sha256"] == source_sha
            and observations["abi_descriptor"]["runtime_adapter_consumes_descriptor"] is False,
            "installed ABI descriptor scope differs")
    _, abi_record = read(installed / "hepta/_data/hepta/hia_bounded_read_abi.json", 16384)
    require(observations["abi_descriptor"]["record"] == abi_record and abi_record["sha256"] == abi_sha,
            "actual installed source-owned descriptor differs")
    return {"report": value_pin, "request": request_pin, "cases": result_pin,
        "owners": owners, "sdist": sdist_pin, "wheel": wheel_pin,
        "installed_members": len(now), "source_python_members": 170, "source_resources": 105,
        "expected_ids": ids, "native_read_returns": 7, "native_entry_returns": len(completed),
        "source_head": CANDIDATE, "installed_root": str(installed), "manifest": manifest_pin,
        "whole_native_delivery_qualified": False, "general_installed_suite_executed": False}


def inputs_or_control(path):
    return read(path, 1 << 20)[0]


def verify_outputs(root, setup, policy):
    """Accept only after the caller proves this run's natural outer ECHILD."""
    context = setup["context"]
    source, evidence, control = Path(context["source"]), root / "evidence", root / "control"
    python = context["python"]["resolved"]
    report, report_pin = original(evidence / "report.json", maximum=32 << 20)
    require(report["schema"] == "hepta.hia.bounded-read-product-native-installation.v1"
            and report["status"] == "BOUNDED_READ_PRODUCT_AND_INSTALLATION_PENDING_OUTER_GUARDIAN"
            and report["candidate_commit"] == CANDIDATE and report["candidate_tree"] == CANDIDATE_TREE
            and report["finite_component_cases"] == 55 and report["original_methods"] == 8
            and report["original_CLI_children"] == 7 and report["original_CLI_timeout_seconds"] == 20
            and report["errors"] == [] and report["all_started_inner_owners_closed"] is True
            and report["source_preserved"] is True and report["outer_qualification_seconds_required"] == 180
            and report["outer_cleanup_seconds_required"] == 3 and report["outer_guardian_verified_here"] is False
            and report["fresh_B0_B1_B2_requested"] is True
            and report["filesystem_and_context_operations_remain_hosted"] is True
            and all(report[name] is False for name in ("old_compiler_reused", "cold_qualification",
                "all_input_equivalence_proved", "whole_native_delivery_qualified", "source_mutation_authorized",
                "existing_general_installed_resource_suite_executed"))
            and [row["label"] for row in report["processes"]] == ["fresh-compiler", "finite-gate"],
            "complete actual driver result differs")
    ctl, ctl_pin = original(control / "control-manifest.json", report["control_manifest"], 1 << 20)
    require(ctl_pin["sha256"] == context["control_manifest_sha256"]
            and ctl["schema"] == "hepta.hia.bounded-read-product-capsule-controls.v1"
            and ctl["candidate_commit"] == CANDIDATE and ctl["candidate_tree"] == CANDIDATE_TREE
            and ctl["outer_qualification_seconds"] == 180 and ctl["outer_cleanup_seconds"] == 3
            and ctl["dispatch_authorized_by_this_file"] is False
            and ctl["files"] == {k: v for k, v in policy["controls"].items() if k != "control-manifest.json"},
            "complete exact control manifest differs")
    actual_controls = {name: fixed_read(control / name, expected)[1] for name, expected in ctl["files"].items()}
    require(report["control_before"] == report["control_after"] == actual_controls,
            "all copied control source identities changed")
    rows, _, plan_pin = source_manifest(control / "source-manifest.json")
    require(report["source_manifest"] == plan_pin, "actual source plan differs")
    actual_source = snapshot(source, rows)
    require(len(actual_source) == 4051, "complete source leaf population differs")
    for filename, key in (("source-before.json", "source_before"), ("source-after.json", "source_after")):
        value, _ = original(evidence / filename, report[key], 8 << 20)
        require(value == actual_source, "actual complete source identity changed")
    git = source_git(source, rows)
    require(git == report["source_git_before"] == report["source_git_after"] == setup["source_actual_HEAD"],
            "exact detached Git source identity differs")
    fresh_command = [python, "-I", "-S", "-B", str(control / "prepare_native.py"),
        "--source-root", str(source), "--source-manifest", str(control / "source-manifest.json"),
        "--output", str(evidence / "compiler")]
    top_owners = [verify_owned_step(report["processes"][0], evidence / "processes", source,
                                    fresh_command, runtime_environment(), 60)]
    compiler_directory = evidence / "compiler"
    preparation, preparation_pin = original(compiler_directory / "report.json", report["preparation"]["record"], 16 << 20)
    require(preparation["schema"] == "hepta.hia.bounded-read-product-fresh-compiler.v1"
            and preparation["status"] == "FRESH_B0_B1_B2_DEVELOPMENT_READY"
            and preparation["scope"] == "FRESH_B0_B1_B2_DEVELOPMENT_NOT_COLD"
            and preparation["candidate_commit"] == CANDIDATE and preparation["candidate_tree"] == CANDIDATE_TREE
            and preparation["errors"] == [] and preparation["source_manifest"] == plan_pin
            and preparation["host_successor_compiler_calls"] == []
            and preparation["source_preserved"] is True
            and preparation["compile_wall_seconds"] == 20 and preparation["native_limits"] == NATIVE_LIMITS
            and preparation["original_authoring_limits"] == LIMITS
            and preparation["source_git_before"] == preparation["source_git_after"] == git
            and preparation["core_roundtrip"] is True and preparation["deterministic_source"] is True
            and all(preparation[key] is False for key in ("source_mutation_authorized", "old_compiler_reused",
                        "B3_or_mutation_qualification_claimed", "whole_native_delivery_qualified")),
            "fresh compiler source/cap/scope conjunction differs")
    for filename, key in (("source-before.json", "source_before"), ("source-after.json", "source_after")):
        value, _ = original(compiler_directory / filename, preparation[key], 8 << 20)
        require(value == actual_source, "preparation complete source identity differs")
    assembly, assembly_pin = read(source / GENERATED, 1 << 20)
    abi, abi_pin = read(source / "hepta/hia_bounded_read_abi.json", 16384)
    copied_assembly, copied_assembly_pin = read(compiler_directory / "bounded-read.hiaasm", 1 << 20)
    copied_abi, copied_abi_pin = read(compiler_directory / "source-entry-abi.json", 16384)
    require(copied_assembly == assembly and copied_assembly_pin == preparation["assembly"]
            and copied_abi == abi and copied_abi_pin == preparation["entry_abi"],
            "actual checked/generated HIA and source-owned ABI copies differ")
    document, _ = original(compiler_directory / "bounded-read.hia.json", preparation["core_document"], 4 << 20)
    observed, functions = measurements(document, assembly)
    require(observed == preparation["measurements"] and functions == preparation["functions"]
            and observed["functions"] == 14 and all(observed[name] <= bound for name, bound in LIMITS.items()),
            "all original compiler caps differ")
    support_raw = read(source / "docs/HIA_SELFHOST_CORE_SUPPORT.json", 8 << 20)[0]
    coverage_raw = read(source / "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json", 8 << 20)[0]
    require(preparation["current_contracts"] == {"support": pin(support_raw), "coverage": pin(coverage_raw),
             "generated_in_memory_without_source_write": True}, "actual generated contract hashes differ")
    linker = preparation["linker"]
    require(read(Path(linker["resolved"]), 64 << 20, system_binary=True)[1]
            == linker["binary_before"] == linker["binary_after"], "actual linker bytes differ")
    for suffix, field in (("stdout.log", "version_stdout"), ("stderr.log", "version_stderr")):
        require(read(compiler_directory / ("linker-version." + suffix), 1 << 20)[1] == linker[field],
                "actual linker version original differs")
    compiler_bundle = observe_compiler_bundle(source, compiler_directory)
    require(compiler_bundle == preparation["compiler_bundle_before"] == preparation["compiler_bundle_after"]
            == report["preparation"]["compiler_bundle"] == report["compiler_after"]
            and preparation["B1_receipt"] == compiler_bundle["stages"]["B1"]["receipt"]
            and preparation["B2_receipt"] == compiler_bundle["stages"]["B2"]["receipt"],
            "actual B0/B1/B2 full original bundle differs")
    seed, _ = original(compiler_directory / "B0.receipt.json", maximum=8 << 20)
    require(preparation["fresh_seed"] == {"receipt": seed,
                "image": read(compiler_directory / "B0.so", 16 << 20)[1],
                "selfhost": read(source / "examples/hia_bootstrap/selfhost.hiaasm", 1 << 20)[1]}
            and seed["python"]["path"] == python
            and seed["python"]["sha256"] == context["python"]["binary"]["sha256"]
            and seed["python"]["version"] == context["python"]["version"],
            "actual seed runtime/receipt/artifact binding differs")
    compiler = compiler_directory / "B2.image.bin"
    require(preparation["compiler_path"] == str(compiler), "fresh actual compiler path differs")
    finite_command = [python, "-I", "-S", "-B", str(source / "tools/qualify_hia_bounded_read.py"),
        "--compiler", str(compiler), "--development", "--output", str(evidence / "finite")]
    top_owners.append(verify_owned_step(report["processes"][1], evidence / "processes", source,
                                       finite_command, runtime_environment(), 180))
    finite = verify_finite(source, evidence / "finite", compiler, python)
    require(finite == report["finite"], "public finite gate differs from independent originals")
    component_directory = evidence / "finite/work/build"
    combined = observe_compiler_bundle(source, compiler_directory, component_directory)
    require(combined == report["compiler_and_component_before"] == report["compiler_and_component_after"],
            "current component compiler/input/output/receipt binding differs")
    installation = verify_installation(source, evidence, control, python,
                                      component_directory / "bounded-read.image.bin", compiler)
    require(report["installed_case_ids"] == installation["expected_ids"]
            and report["installation"]["report"] == installation["report"]
            and report["installation"]["case_report"] == installation["cases"]
            and report["installation"]["case_request"] == installation["request"]
            and report["installation"]["installed_root"] == installation["installed_root"]
            and report["installation"]["manifest_path"] == installation["manifest"]["path"]
            and report["installation"]["source_resource_count"] == 105
            and report["installation"]["source_python_count"] == 170
            and report["installation"]["native_source_resource_count"] == 90
            and report["installation"]["case_methods"] == 9
            and report["installation"]["native_read_returns"] == 7
            and report["installation"]["scope"] == "DEVELOPMENT_INSTALLATION",
            "driver installation summary does not match the actual records")
    require(snapshot(source, rows) == actual_source and source_git(source, rows) == git,
            "source changed during independent final readback")
    return {"report": report_pin, "preparation": preparation_pin, "source_commit": CANDIDATE,
        "source_tree": CANDIDATE_TREE, "source_leaves": 4051, "generated_source": assembly_pin,
        "source_owned_ABI": abi_pin, "outer_owner_required_seconds": 180, "cleanup_seconds": 3,
        "top_owners": top_owners, "finite": finite, "installation": installation,
        "fresh_compiler_sha256": combined["compiler_sha256"], "image_sha256": combined["image_sha256"],
        "fresh_B0_B1_B2": True, "all_input_equivalence_proved": False,
        "cold_qualification": False, "whole_native_delivery_qualified": False}

