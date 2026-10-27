"""Data-only namespace review and a frozen-source qualification limitation."""
from collections import Counter
import re

from performance_audit import COMPILER, parse, require, sha
from report_audit import assignment, literal


def namespace_review(report, sources):
    source = sources["experiments/agent_eval/sandbox_qualification.py"]
    names = literal(assignment(source, "CHECKS"))
    required_namespaces = literal(assignment(source, "REQUIRED_NAMESPACES"))
    require(len(names) == len(set(names)) == 10 and set(report["checks"]) == set(names),
            "namespace frozen check inventory")
    require(report["schema"] == "hepta.sandbox_qualification.v1"
            and report["compiler_sha256"] == COMPILER, "namespace source identity")
    require(report["implementation_sha256"] == {name: sha(sources["experiments/agent_eval/" + name])
            for name in ("sandbox.py", "sandbox_qualification.py")}, "namespace implementation identity")
    statuses = {name: report["checks"][name]["status"] for name in names}
    require(all(value in {"passed", "failed", "not_run"} for value in statuses.values()),
            "namespace check status domain")
    require(report["qualified"] is all(value == "passed" for value in statuses.values())
            and report["ai_comparison_eligible"] is False, "namespace aggregate scope")
    available = report["startup"]["available"]
    require(type(available) is bool, "namespace startup availability")
    computed = {"startup": available}
    host_states = {}
    boundary = report.get("boundary")
    if boundary is not None:
        require(boundary["required_namespaces"] == list(required_namespaces), "required namespace names")
        require(set(boundary["namespaces"]) == set(required_namespaces) | {"uts", "cgroup"},
                "observed namespace inventory")
        for row in boundary["namespaces"].values():
            require(row["different"] is (row["parent"] != row["child"]), "namespace inode comparison")
        executed = boundary["returncode"] == 0
        inside = boundary["inside"]
        path_names = {"parent_oracle_canary", "parent_credentials_canary", "capsule_symlink_to_parent",
                      "proc_parent_root_escape", "proc_init_root_escape", "proc_environment",
                      "parent_private_oracle_module", "host_credentials_path"}
        require(set(boundary["paths"]) == set(inside["path_checks"]) == path_names,
                "boundary path observation denominator")
        for name, row in boundary["paths"].items():
            state = row["host_stat_status"]
            require(state in {"present", "absent", "unobservable"}, "host path tri-state")
            if state == "present":
                require(row["host_exists"] is True and row["host_stat_errno"] is None,
                        "present host path observation")
            elif state == "absent":
                require(row["host_exists"] is False and type(row["host_stat_errno"]) is int,
                        "absent host path observation")
            else:
                require(row["host_exists"] is None and type(row["host_stat_errno"]) is int,
                        "unobservable host path observation")
            host_states[name] = {key: row[key] for key in ("host_exists", "host_stat_status", "host_stat_errno")}
        for row in inside["path_checks"].values():
            require(type(row["unreadable"]) is bool, "inside path readability domain")
            if row["unreadable"]:
                require(type(row["errno"]) is int, "inside unreadable errno")
        computed.update({
            "namespace_identity": executed and all(boundary["namespaces"][name]["different"]
                                                    for name in required_namespaces),
            "capabilities_dropped": executed and all(inside["capabilities"][name] == 0
                                                      for name in ("effective", "permitted", "inheritable"))
                                     and inside["capabilities"]["no_new_privileges"] == 1,
            "empty_proc": executed and inside["proc_entries"] == [],
            "parent_paths_unreadable": executed and all(row["unreadable"] for row in inside["path_checks"].values()),
            "credentials_not_inherited": executed and not inside["credential_in_environment"],
            "host_network_unreachable": executed and inside["host_loopback"]["blocked"]
                                         and not boundary["parent_listener_received_connection"],
            "system_files_read_only": executed and inside["usr_read_only"] and inside["toolchain_visible"]
                                      and inside["toolchain_read_only"],
        })
    native_process = report.get("native_process")
    if native_process is not None:
        if native_process["status"] != "exited" or native_process["returncode"] != 0:
            computed["hepta_rust_native"] = False
        else:
            native = parse(native_process["stdout"].encode())
            require(native == report["native"], "native probe stdout/report linkage")
            computed["hepta_rust_native"] = bool(native["analysis_ok"] and native["build"]["ok"]
                and native["execution"]["returncode"] == 0 and native["build"].get("artifact_sha256"))
            flags = native["workspace_backend"]["flags"]
            computed["workspace_native_profile"] = bool(native["workspace_ok"]
                and native["workspace_profile"]["native_flags"] == flags
                and "sysroot=" + report["toolchain"]["sysroot"] in flags)
    for name, result in computed.items():
        require(statuses[name] == ("passed" if result else "failed"), "namespace recorded predicate differs: " + name)
    require(all(statuses[name] == "not_run" for name in names if name not in computed),
            "namespace completion without its raw predicate evidence")
    expected_status = "qualified" if report["qualified"] else "not_qualified" if available else "environment_blocked"
    require(report["status"] == expected_status, "namespace aggregate status")
    return {"checks": statuses, "counts": dict(Counter(statuses.values())), "qualified": report["qualified"],
            "status": report["status"], "error": report.get("error"), "computed_check_count": len(computed),
            "host_path_observations": host_states, "host_path_counts": dict(Counter(
                row["host_stat_status"] for row in host_states.values())),
            "scope": "recorded probe predicates and frozen source identity; no sandbox or native probe repeated"}


def declaration_limitation(sources, kind):
    symbol = kind + "_case"
    harness_name = "examples/cpp/" + kind + "_migration/harness.c"
    qualifier_name = "tools/qualify_cpp_" + kind + "_llvm.py"
    harness = sources[harness_name]
    prefix, conditional = harness.split(b"#ifdef __cplusplus\n", 1)
    cpp, remainder = conditional.split(b"#else\n", 1)
    c_branch, after = remainder.split(b"#endif\n", 1)
    require(('extern "C" uint64_t ' + symbol + '(').encode() in cpp
            and symbol.encode() not in prefix + c_branch
            and ("uint64_t actual = " + symbol + "(").encode() in after, "frozen standalone C declaration defect differs")
    require(b"harness.c" in sources[qualifier_name] and b"-std=c11" in sources[qualifier_name],
            "standalone C harness build source differs")
    return {"id": "standalone-" + kind + "-C-caller-lacks-return-prototype",
        "status": "unfixed_in_tested_source",
        "source_inputs": {name: {"bytes": len(sources[name]), "sha256": sha(sources[name])}
                          for name in (harness_name, qualifier_name, "tools/validate_cpp_" + kind + ".py")},
        "finding": "The standalone C harness calls " + symbol + " without a preceding C declaration; its uint64_t prototype is present only in the C++ branch.",
        "consequence": "Finite recorded passes do not establish full-width C return ABI correctness for this qualifier. No original pass or failure is changed by this independent limitation record.",
        "no_causal_attribution_from_static_finding_alone": True,
        "scope": "exact tested source and retained reports; no compile or native reexecution"}


def diagnostic_review(members):
    reports = sorted(name for name in members if any(name.startswith(prefix)
        and "/" not in name[len(prefix):] and name.endswith(".json")
        for prefix in ("artifacts/candidate/", "artifacts/hia-unified/")))
    found = []
    pattern = re.compile(r"(?m)^.*?\b(warning|error):[^\n]*?implicit declaration of function[^\n]*?\b(composed_case|owned_case)\b[^\n]*$")

    def visit(value, member, pointer):
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, member, pointer + "/" + str(index))
        elif isinstance(value, dict):
            for key, item in value.items():
                location = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                if key == "stderr" and isinstance(item, str):
                    for match in pattern.finditer(item):
                        found.append({"member": member, "json_pointer": location, "severity": match[1],
                            "symbol": match[2], "line_in_stderr": item[:match.start()].count("\n") + 1,
                            "diagnostic_line": match[0], "stderr_sha256": sha(item.encode()),
                            "process_returncode": value.get("returncode"), "process_command": value.get("command")})
                else:
                    visit(item, member, location)

    for name in reports:
        visit(parse(members[name]), name, "")
    return {"primary_json_reports_scanned": reports, "primary_json_report_count": len(reports),
            "diagnostic_occurrences": len(found), "by_severity_and_symbol": dict(Counter(
                row["severity"] + "/" + row["symbol"] for row in found)), "records": found,
            "scope": "Every stderr string inside first-level candidate and hia-unified JSON reports; occurrences are not inferred from older runs or counted again from text logs."}


def review_supplemental(members, sidecars):
    selected = parse(sidecars["source-identities.json"])
    sources = {row["git_path"]: sidecars[row["archived_path"]] for row in selected["files"]}
    return {"schema": "hepta.ci-candidate.supplemental-review.v1", "source_commit": selected["source_commit"],
        "namespace": namespace_review(parse(members["artifacts/candidate/sandbox.json"]), sources),
        "known_qualification_limitations": [declaration_limitation(sources, kind) for kind in ("composed", "owned")],
        "implicit_C_declaration_diagnostics": diagnostic_review(members), "native_execution_repeated": False}
