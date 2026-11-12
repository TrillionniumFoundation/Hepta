def validate_negative_processes(tests, request, operation, evidence):
    """Read all four actual refusal commands independently from their raw files."""
    from pathlib import PurePosixPath
    import tempfile
    spec = request["source_child_process_policy"]
    require(spec["schema"] == "hepta.source83-four-negative-python-permissions.v1"
            and spec["target_test_id"] == "tests.test_hia_store_page_gates.StorePageCIGateTests."
                "test_real_command_rejects_bad_cold_and_development_before_creating_evidence"
            and spec["script"] == "tools/qualify_hia_store_page_ci.py"
            and spec["cases"] == [{"owner": owner, "development": development}
                for owner in ("authority", "page") for development in (False, True)]
            and spec["prefixes"] == {"authority": "HEPTA_HIA_AGENT_STORE_AUTHORITY",
                                    "page": "HEPTA_HIA_ARTIFACT_PAGE"}
            and spec["environment"] == {"PATH": "", "LANG": "C", "LC_ALL": "C"}
            and spec["development_value"] == "/old/development"
            and spec["python_flags"] == ["-I", "-S", "-B"]
            and spec["input_bytes_utf8"] == "{}" and type(spec["timeout_seconds"]) is int
            and spec["timeout_seconds"] == 10 and type(spec["expected_processes"]) is int
            and spec["expected_processes"] == 4
            and spec["all_other_subprocess_entries_forbidden"] is True
            and spec["native_and_compiler_entries_forbidden"] is True
            and spec["zero_process_scope_claimed"] is False,
            "frozen negative-command policy differs")
    require(type(tests["allowed_negative_processes"]) is int
            and tests["allowed_negative_processes"] == 4
            and tests["forbidden_attempts"] == []
            and type(tests["forbidden_attempt_count"]) is int
            and tests["forbidden_attempt_count"] == 0
            and tests["negative_permission_refusals"] == []
            and tests["zero_process_scope_claimed"] is False
            and tests["source_child_process_policy"] == spec,
            "actual allowed/forbidden command accounting differs")
    rows = tests["allowed_negative_process_records"]
    require(type(rows) is list and len(rows) == 4
            and [row["case"] for row in rows] == spec["cases"]
            and [row["index"] for row in rows] == [1, 2, 3, 4]
            and all(type(row["index"]) is int for row in rows),
            "negative-command original record order/count differs")
    source = operation / "source"
    original_source = {row["relative_path"]: row for row in request["source_files"]}
    binding_names = ["tests/test_hia_store_page_gates.py",
                     "tools/qualify_hia_store_page_ci.py",
                     "tools/hia_store_page_gates.py",
                     "tools/build_hia_json_preflight.py"]
    require(spec["binding_sources"] == binding_names, "negative source binding set differs")
    temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    previous_end = None
    originals = []
    for index, (row, case) in enumerate(zip(rows, spec["cases"]), 1):
        require(row["schema"] == "hepta.source83-negative-admission-process.v1"
                and row["status"] == "NEGATIVE_ADMISSION_RETURNED_AND_CLOSED"
                and row.get("error") is None and not row.get("preservation_errors")
                and row["test_id"] == spec["target_test_id"]
                and type(row["pid"]) is int and row["pid"] > 0
                and row["popen_permission_consumed"] is True
                and row["process_started"] is True and row["original_run_called"] is True
                and row["original_run_returned"] is True
                and row["original_process_context_closed"] is True
                and type(row["returncode"]) is int and row["returncode"] != 0
                and type(row["returncode_after_original_run"]) is int
                and row["returncode_after_original_run"] == row["returncode"]
                and type(row["timeout_seconds"]) is int and row["timeout_seconds"] == 10
                and row["output_absent"] is True and row["evidence_absent"] is True,
                "negative command was not a normal closed real refusal")
        cwd = Path(row["cwd"])
        require(type(row["cwd"]) is str and cwd.is_absolute()
                and PurePosixPath(row["cwd"]).as_posix() == row["cwd"]
                and all(part not in (".", "..") for part in PurePosixPath(row["cwd"]).parts)
                and cwd.parent == temporary_parent
                and row["temporary_parent"] == str(temporary_parent),
                "negative temporary path differs")
        command = [request["runtime"]["path"], "-I", "-S", "-B",
                   str(source / spec["script"]), "component", "--owner", case["owner"],
                   "--cold-report", str(cwd / "cold.json"), "--output", str(cwd / "report.json"),
                   "--evidence-dir", str(cwd / "evidence")]
        env = dict(spec["environment"])
        if case["development"]:
            env[spec["prefixes"][case["owner"]] + "_DEVELOPMENT_MANIFEST"] = "/old/development"
        require(row["command"] == command and row["environment"] == env
                and row["runtime_before"] == row["runtime_after"] == request["runtime"],
                "actual negative argv/env/interpreter differs")
        before, after = row["directory_before"], row["directory_after"]
        directory_keys = {"device", "inode", "mode", "uid", "gid", "nlink", "size",
                          "mtime_ns", "ctime_ns"}
        require(before == after and set(before) == directory_keys
                and all(type(before[key]) is int for key in directory_keys)
                and before["mode"] == 0o700 and before["uid"] == os.geteuid(),
                "observed private temporary directory identity differs")
        cold = row["cold_before"]
        require(cold == row["cold_after"] and cold["path"] == str(cwd / "cold.json")
                and type(cold["size"]) is int and cold["size"] == 2
                and cold["sha256"] == sha256(b"{}").hexdigest()
                and cold["uid"] == os.geteuid() and cold["nlink"] == 1
                and type(cold["mode"]) is int and cold["mode"] & 0o022 == 0,
                "observed original empty cold receipt differs")
        require(row["binding_sources_before"] == row["binding_sources_after"]
                and [pin["path"] for pin in row["binding_sources_before"]]
                    == [str(source / name) for name in binding_names],
                "actual negative command source binding differs")
        for name, observed in zip(binding_names, row["binding_sources_before"]):
            exact_pin(observed, source)
            require(all(observed[key] == original_source[name][key]
                        for key in ("size", "sha256", "git_blob_sha1", "mode")),
                    "frozen negative-command source content differs")
        stem = evidence / ("negative-admission-" + str(index))
        for field, suffix in (("input_original", ".input.bin"), ("stdout", ".stdout.bin"),
                              ("stderr", ".stderr.bin"), ("request_original", ".request.json"),
                              ("receipt_original", ".receipt.json")):
            expected = row[field]
            require(expected["path"] == str(stem.with_suffix(suffix)),
                    "negative-command original path differs")
            originals.append(exact_pin(expected, evidence))
        input_raw = read(stem.with_suffix(".input.bin"), owned=True)[0]
        stderr_raw = read(stem.with_suffix(".stderr.bin"), owned=True)[0]
        needle = b"development selection" if case["development"] else b"nested_report"
        require(input_raw == b"{}" and needle in stderr_raw,
                "actual negative input/error bytes differ")
        original, _, _ = json_read(stem.with_suffix(".request.json"), owned=True)
        keys = ("schema", "index", "case", "test_id", "command", "cwd", "environment",
                "timeout_seconds", "runtime_before", "binding_sources_before", "temporary_parent",
                "directory_before", "cold_before", "input_original", "started_monotonic_ns")
        require(original == {key: row[key] for key in keys}, "original negative request differs")
        receipt, _, _ = json_read(stem.with_suffix(".receipt.json"), owned=True)
        require(receipt == {key: value for key, value in row.items() if key != "receipt_original"},
                "original negative terminal receipt differs")
        require(type(row["started_monotonic_ns"]) is int
                and type(row["ended_monotonic_ns"]) is int
                and row["ended_monotonic_ns"] >= row["started_monotonic_ns"]
                and (previous_end is None or row["started_monotonic_ns"] >= previous_end),
                "negative command sequence timestamps differ")
        previous_end = row["ended_monotonic_ns"]
    require(len({row["cwd"] for row in rows}) == 4
            and len(originals) == len({row["path"] for row in originals}) == 20,
            "negative commands did not retain four independent original input/output sets")
    return {"schema": "hepta.source83-negative-command-readback.v1", "allowed_negative_processes": 4,
            "forbidden_attempts": 0, "test_id": spec["target_test_id"], "complete_originals": originals,
            "temporary_input_scope": "Original held-fd before/after observations and exact two-byte copies; original TemporaryDirectory paths are removed by the unchanged tests."}


