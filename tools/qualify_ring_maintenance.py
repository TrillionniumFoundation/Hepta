#!/usr/bin/env python3
"""Execute an actual upstream maintenance cycle and bounded Linux host profiles.

The original Makefile, public header, and two original C example clients remain
byte-identical to each pinned upstream commit. Only ringbuffer.c's implementation
is substituted at its normal compiler invocation. This route translates bodies
to checked Hepta and the Rust backend; it is not standalone HIA Core ABI proof.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import platform
import random
import shutil
import signal
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.c_contracts import decode_contracts
from hepta.c_migrate import migrate_c_project
from tools.qualify_c_ring_buffer import (
    FLAGS, QualificationEvidence, checkpoint, layout_probe, owned_client,
    run_sequences,
)

FIXTURE = ROOT / "tests/fixtures/c_migration/ring_buffer_maintenance"
CONTRACT = ROOT / "tests/fixtures/c_migration/ring_buffer/contracts.json"
PROTOCOL_PATH = ROOT / "experiments/ring_maintenance/PROTOCOL_20261030.json"
HOST_SOURCE = ROOT / "tools/fixtures/ring_maintenance_host.c"
SUPERVISOR_SOURCE = ROOT / "examples/hia_filecheck/rss_supervisor.c"
PINNED = {
    "before": ("1468e24fc55986d7c432d1d26115e3b28f985fe0", "bcf333c0428cb28cd6b2296a7fc24d9d9b21b177"),
    "after": ("8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba", "c65911bc45ec4914cff55f5fd422bad7c5694270"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def identity(path):
    path = Path(path)
    return {"path": str(path.absolute()), "bytes": path.stat().st_size, "sha256": digest(path)}


def git_object(kind, content):
    return sha1(kind.encode() + b" " + str(len(content)).encode() + b"\0" + content).hexdigest()


def tree_identity(files):
    """Reconstruct the whole upstream Git tree, including executable file mode."""
    root = {}
    seen = set()
    for row in files:
        path = PurePosixPath(row["path"])
        require(not path.is_absolute() and all(x not in {".", ".."} for x in path.parts)
                and str(path) == row["path"] and path.parts, "invalid upstream path")
        require(row["path"] not in seen, "duplicate upstream path")
        require(row["mode"] in {"100644", "100755"}, "unsupported upstream file mode")
        seen.add(row["path"])
        node = root
        for part in path.parts[:-1]:
            node = node.setdefault(part, {})
            require(isinstance(node, dict), "upstream path prefix conflict")
        require(path.name not in node, "upstream path collision")
        node[path.name] = (row["mode"], row["git_blob"])

    def hash_tree(node):
        rows = []
        for name, value in node.items():
            if isinstance(value, dict):
                rows.append((name + "/", "40000", name, hash_tree(value)))
            else:
                rows.append((name, value[0], name, value[1]))
        content = b"".join(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(blob)
                           for _, mode, name, blob in sorted(rows))
        return git_object("tree", content)
    return hash_tree(root)


def verify_upstream(fixture=FIXTURE):
    fixture = Path(fixture)
    manifest = json.loads((fixture / "UPSTREAM.json").read_text())
    require(manifest["repository"] == "https://github.com/AndersKaloer/Ring-Buffer", "upstream repository drift")
    versions = manifest["versions"]
    require([x["name"] for x in versions] == list(PINNED), "upstream revision inventory drift")
    inventories = {}
    for version in versions:
        require((version["commit"], version["tree"]) == PINNED[version["name"]], "upstream commit/tree drift")
        require(len(version["files"]) == 12, "incomplete upstream tree")
        require(tree_identity(version["files"]) == version["tree"], "upstream Git tree mismatch")
        for row in version["files"]:
            path = fixture / "blobs" / row["git_blob"]
            require(path.is_file() and not path.is_symlink(), "upstream blob is not a regular file")
            data = path.read_bytes()
            require(len(data) == row["bytes"] and sha256(data).hexdigest() == row["sha256"]
                    and git_object("blob", data) == row["git_blob"], "upstream blob mismatch: " + row["path"])
        inventories[version["name"]] = {x["path"]: (x["mode"], x["git_blob"]) for x in version["files"]}
    a, b = inventories["before"], inventories["after"]
    changed = sorted(k for k in a.keys() | b.keys() if a.get(k) != b.get(k))
    require(changed == ["examples/tail.c"], "unexpected upstream maintenance change")
    return manifest


def materialize(version, directory, fixture=FIXTURE):
    directory.mkdir(parents=True)
    for row in version["files"]:
        target = directory / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((fixture / "blobs" / row["git_blob"]).read_bytes())
        target.chmod(int(row["mode"], 8) & 0o777)
    verify_materialized(version, directory)


def verify_materialized(version, directory):
    for row in version["files"]:
        path = directory / row["path"]
        require(path.is_file() and not path.is_symlink() and digest(path) == row["sha256"]
                and path.stat().st_size == row["bytes"], "upstream source changed: " + row["path"])
        require((path.stat().st_mode & 0o111) == (int(row["mode"], 8) & 0o111), "upstream mode changed")


def source_bindings():
    paths = [Path(__file__), CONTRACT, PROTOCOL_PATH, HOST_SOURCE, SUPERVISOR_SOURCE,
             ROOT / "tools/qualify_c_ring_buffer.py", ROOT / "tools/qualify_c_migration.py",
             *sorted((ROOT / "hepta").glob("*.py")), *sorted(FIXTURE.rglob("*"))]
    return {str(p.relative_to(ROOT)): digest(p) for p in paths if p.is_file()}


def verify_committed_sources(command, bindings, commit):
    """A matching HEAD alone cannot authorize untracked or dirty source code."""
    listed = command(["git", "ls-tree", "-r", "--full-tree", commit, "--", *bindings],
                     "source.committed_inventory", cwd=ROOT)["stdout"]
    tree = {}
    for line in listed.splitlines():
        metadata, path = line.split("\t", 1)
        mode, kind, blob = metadata.split()
        require(kind == "blob" and mode in {"100644", "100755"}, "unexpected committed source kind")
        tree[path] = blob
    require(set(tree) == set(bindings), "source binding includes files absent from --source-sha")
    for name, expected_sha256 in bindings.items():
        data = (ROOT / name).read_bytes()
        require(sha256(data).hexdigest() == expected_sha256 and git_object("blob", data) == tree[name],
                "working source differs from --source-sha: " + name)
    return {"commit": commit, "files": len(tree), "git_tree_and_source_hashes_match": True}


def tail_cases(protocol):
    inputs = [b"", b"a\xffb", b"JIHGFEDCBA9876543210", bytes(range(256)),
              bytes(reversed(range(256))), b"\xff", b"0123456789abcdef\xfftail"]
    inputs.extend(bytes([i]) for i in range(256))
    randomizer = random.Random(protocol["tail_case_seed"])
    for _ in range(protocol["tail_random_cases"]):
        size = randomizer.choice([0, 1, 14, 15, 16, 31, 255, 1024])
        inputs.append(bytes(randomizer.randrange(256) for _ in range(size)))
    return inputs


def tail_oracle(data, revision):
    require(revision in PINNED, "unknown upstream revision")
    # This is the observed LP64 x86_64 signed-char configuration of the original
    # Makefile clients. The protocol separately checks CHAR_MIN == -128.
    visible = data.split(b"\xff", 1)[0] if revision == "before" else data
    return visible[-15:]


def make_wrapper(directory, *, cc, original, library):
    """CC integration is narrow and logged; no upstream source/Makefile edits."""
    configuration = {"compiler": identity(cc), "original": identity(original),
                     "replacement": identity(library), "log": str(directory / "cc-invocations.jsonl")}
    config = directory / "cc-wrapper.json"
    config.write_text(json.dumps(configuration, sort_keys=True, indent=2) + "\n")
    wrapper = directory / "cc-wrapper.py"
    wrapper.write_text('''from hashlib import sha256
import json, os
from pathlib import Path
import subprocess, sys, time
configuration = json.loads(Path(__file__).with_suffix('.json').read_text())
def check(record):
    path = Path(record['path'])
    if not path.is_file() or path.stat().st_size != record['bytes'] or sha256(path.read_bytes()).hexdigest() != record['sha256']:
        raise SystemExit('CC integration input identity changed')
for key in ('compiler', 'original', 'replacement'):
    check(configuration[key])
arguments = sys.argv[1:]
original = Path(configuration['original']['path']).resolve()
hits = [i for i, value in enumerate(arguments) if not value.startswith('-') and Path(value).resolve() == original]
if len(hits) != 1 or '-c' in arguments or '-o' not in arguments:
    raise SystemExit('CC integration accepts exactly one expected implementation in a link invocation')
result = list(arguments)
result[hits[0]] = configuration['replacement']['path']
result.append('-Wl,-rpath,' + str(Path(configuration['replacement']['path']).parent))
command = [configuration['compiler']['path'], *result]
started = time.perf_counter_ns()
process = subprocess.run(command)
row = {'original_arguments': arguments, 'executed_argv': command, 'cwd': os.getcwd(),
       'replaced_original': configuration['original'], 'replacement': configuration['replacement'],
       'returncode': process.returncode, 'wall_ns': time.perf_counter_ns() - started}
with Path(configuration['log']).open('a') as stream:
    stream.write(json.dumps(row, sort_keys=True) + '\\n')
for key in ('compiler', 'original', 'replacement'):
    check(configuration[key])
raise SystemExit(process.returncode)
''')
    return wrapper, configuration


def expected_thread_observation(threads, batches, transactions):
    checksums, byte_counts = [], []
    for thread in range(threads):
        checksum, total = 1469598103934665603, 0
        for ordinal in range(batches * transactions):
            count = (ordinal + thread * 13) % 96
            total += count
            for index in range(count):
                value = (ordinal * 17 + thread * 23 + index * 7) & 255
                checksum = ((checksum ^ value) * 1099511628211) & ((1 << 64) - 1)
        checksums.append(checksum)
        byte_counts.append(total)
    return checksums, byte_counts


def validate_observation(observed, profile, protocol, expected):
    threads = profile["threads"]
    batches, transactions = protocol["batches_per_thread"], protocol["transactions_per_batch"]
    require(type(observed.get("threads")) is int and observed["threads"] == threads
            and type(observed.get("shared")) is bool and observed["shared"] == profile["shared"], "concurrency profile mismatch")
    require(observed.get("batches_per_thread") == batches and observed.get("transactions_per_batch") == transactions
            and observed.get("transactions") == threads * batches * transactions, "incomplete concurrency work")
    require(observed.get("checksums") == expected[0] and observed.get("bytes_per_thread") == expected[1], "independent thread oracle mismatch")
    samples = observed.get("batch_ns")
    require(type(samples) is list and len(samples) == threads * batches
            and all(type(x) is int and x > 0 for x in samples), "invalid batch timing inventory")
    require(type(observed.get("whole_run_ns")) is int and observed["whole_run_ns"] > 0, "invalid whole-run timing")
    return observed


def quantile(values, percent):
    ordered = sorted(values)
    require(bool(ordered), "missing timing observations")
    return ordered[max(0, (len(ordered) * percent + 99) // 100 - 1)]


class Trial:
    def __init__(self, evidence, report, *, clang, rustc, source_sha):
        self.evidence, self.report = evidence, report
        self.protocol = report["protocol"]
        self.clang = str(Path(shutil.which(clang) or clang).resolve())
        self.rustc = str(Path(shutil.which(rustc) or rustc).resolve())
        self.gcc = str(Path(shutil.which("gcc") or "gcc").resolve())
        self.make = str(Path(shutil.which("make") or "make").resolve())
        self.source_sha = source_sha
        self.work = evidence.retained / "workspace"
        self.work.mkdir()
        self.versions = {}

    def command(self, argv, role, **kwargs):
        return self.evidence.command([os.fspath(x) for x in argv], role=role, **kwargs)

    def stage(self, name):
        checkpoint(self.report, self.evidence, name)

    def build_version(self, version):
        label = version["name"]
        self.stage(label + ".materialize_original_project")
        directory = self.work / label
        directory.mkdir()
        original, migrated = directory / "original", directory / "migrated"
        materialize(version, original)
        materialize(version, migrated)
        record = {"upstream": version, "original_project": str(original), "migrated_project": str(migrated)}
        self.report["versions"][label] = record
        record["original_make"] = self.command([self.make, "all", "tail"], label + ".make.original", cwd=original / "examples")
        self.stage(label + ".capture_and_implementation_migration")
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(migrated), "file": "ringbuffer.c",
            "arguments": [self.clang, *FLAGS, "-O2", "-c", "ringbuffer.c"]}], indent=2) + "\n")
        begin = time.perf_counter_ns()
        first_process = self.evidence.process_count
        with self.evidence.backend_processes(label + ".migration_native"):
            migration = migrate_c_project(database, directory / "translation",
                contracts=decode_contracts(CONTRACT.read_bytes()), clang=self.clang, rustc=self.rustc, verify_native=True)
        record["migration"] = migration
        record["automatic_migration_wall_ns"] = time.perf_counter_ns() - begin
        record["migration_native_process_range"] = [first_process, self.evidence.process_count]
        require(migration["ok"] and migration["declaration_inventory_complete"], "migration incomplete")
        require(migration["coverage"]["active_project_declarations"] == 22
                and migration["coverage"]["status_counts"]["function_converted"] == 9, "migration denominator drift")
        library = directory / "translation/libtranslated.so"
        source = directory / "translation/source.hepta"
        record["migration_disposition"] = {
            "function_definition_denominator": 9, "function_bodies_converted": 9,
            "ringbuffer_c_bodies_left_behind_an_ffi_call": 0, "manual_migrated_body_edits": 0,
            "original_c_client_translation_units": 2, "public_header_inline_helpers_retained_in_clients": 3,
            "path": "Clang AST -> checked Hepta -> Rust reference backend -> C ABI wrappers",
            "standalone_hia_core": False, "contract_origin": "existing caller-authored record/view contracts",
            "source": identity(source), "bridge": identity(directory / "translation/bridge.rs"),
            "library": identity(library), "human_hours_measured": False}
        wrapper, config = make_wrapper(directory, cc=self.gcc, original=migrated / "ringbuffer.c", library=library)
        self.stage(label + ".original_make_with_migrated_implementation")
        record["migrated_make"] = self.command([self.make, "all", "tail", "CC=" + sys.executable + " " + str(wrapper)],
            label + ".make.migrated", cwd=migrated / "examples")
        invocations = [json.loads(line) for line in Path(config["log"]).read_text().splitlines()]
        require(len(invocations) == 2 and all(row["returncode"] == 0 for row in invocations), "missing original Makefile link invocations")
        for row in invocations:
            require(str(library) in row["executed_argv"] and not any(Path(arg).name == "ringbuffer.c" for arg in row["executed_argv"]), "original implementation was linked")
        record["cc_integration"] = {"wrapper": identity(wrapper), "configuration": identity(wrapper.with_suffix(".json")),
                                    "invocations": invocations, "original_implementation_linked": False}
        self.stage(label + ".original_upstream_clients")
        observations = []
        outputs = []
        for route, project in (("original", original), ("migrated", migrated)):
            result, index = self.evidence.process([str(project / "examples/simple")],
                role=label + ".simple." + route, capture_output=True, timeout=10, require_success=True)
            outputs.append(result.stdout)
            observations.append({"client": "simple", "route": route, "process_index": index,
                                 "stdout_sha256": sha256(result.stdout).hexdigest(), "stdout_bytes": len(result.stdout), "exit_code": result.returncode})
        require(outputs[0] == outputs[1], "original simple client mismatch")
        case_rows = []
        for case, data in enumerate(tail_cases(self.protocol)):
            expected = tail_oracle(data, label)
            row = {"case": case, "input_hex": data.hex(), "expected_hex": expected.hex(),
                   "desired_current_tail_hex": data[-15:].hex(), "historical_0xff_bug_exercised": b"\xff" in data,
                   "routes": {}}
            for route, project in (("original", original), ("migrated", migrated)):
                result, index = self.evidence.process([str(project / "examples/tail")],
                    role=label + ".tail." + route, input=data, capture_output=True, timeout=10, require_success=True)
                require(result.stdout == expected, "tail behavior differs from pinned revision oracle")
                row["routes"][route] = {"stdout_hex": result.stdout.hex(), "process_index": index, "exit_code": result.returncode}
            case_rows.append(row)
        record["original_clients"] = {"simple": observations, "tail_cases": case_rows,
            "tail_case_count": len(case_rows), "simple_assertions_enabled": True,
            "tail_scope": "Historical EOF behavior preserved before upstream update and fixed only by actual upstream client change"}
        self.stage(label + ".independent_api_sequences")
        c_library = directory / "original.so"
        record["c_reference_build"] = self.command([self.gcc, *FLAGS, "-O2", "-shared", "-fPIC", original / "ringbuffer.c", "-o", c_library], label + ".reference_library")
        record["api_sequences"] = run_sequences(c_library, library, seed=self.protocol["differential_seed"],
            steps=self.protocol["differential_steps_per_capacity"], evidence=self.evidence, run_name=label)
        verify_materialized(version, original)
        verify_materialized(version, migrated)
        record["upstream_sources_and_modes_unchanged_after_build"] = True
        self.versions[label] = (directory, c_library, library)

    def host_profiles(self):
        self.stage("native_abi_and_owned_resource_failures")
        directory, original, migrated = self.versions["after"]
        abi = directory / "abi"
        abi.mkdir()
        shutil.copyfile(directory / "original/ringbuffer.h", abi / "ringbuffer.h")
        generated = (directory / "translation/generated.rs").read_text()
        self.report["abi"] = layout_probe(original, generated, abi, self.gcc, self.rustc, evidence=self.evidence)
        self.report["owned_client_faults"] = owned_client((directory / "translation/source.hepta").read_text(),
            abi, self.rustc, evidence=self.evidence)
        host = self.work / "ring-host"
        supervisor = self.work / "rss-supervisor"
        self.report["host_build"] = self.command([self.gcc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(directory / "original"), HOST_SOURCE, "-pthread", "-ldl", "-o", host], "host.build")
        self.report["supervisor_build"] = self.command([self.gcc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            SUPERVISOR_SOURCE, "-o", supervisor], "rss_supervisor.build")
        layout = self.command([host, migrated, "layout"], "host.original_header_layout")
        self.report["original_header_layout"] = json.loads(layout["stdout"])
        require(self.report["original_header_layout"]["char_min"] == -128, "upstream EOF oracle requires signed char")
        require(self.report["original_header_layout"]["pointer_bytes"] == 8
                and self.report["original_header_layout"]["size_t_bytes"] == 8
                and self.report["original_header_layout"]["char_bits"] == 8
                and self.report["original_header_layout"]["little_endian"] is True, "native ABI is outside qualified LP64 profile")
        self.stage("native_fault_isolation_and_recovery")
        faults = self.command([host, migrated, "faults"], "host.faults")
        fault_report = json.loads(faults["stdout"])
        require([x["case"] for x in fault_report["cases"]] == self.protocol["faults"], "fault inventory mismatch")
        require(all(x["child_signal"] == signal.SIGABRT and x["parent_roundtrip_ok"] is True for x in fault_report["cases"]), "fault/recovery mismatch")
        self.report["fault_recovery"] = {**fault_report, "process_index": faults["process_index"],
            "invalid_original_C_calls_executed": False, "in_process_recovery_claim": False}
        self.stage("native_concurrency_rss_and_batch_tail")
        bindings = {str(p): identity(p) for p in (host, supervisor, original, migrated)}
        self.report["host_artifacts"] = bindings
        expected = {threads: expected_thread_observation(threads, self.protocol["batches_per_thread"],
            self.protocol["transactions_per_batch"]) for threads in (1, 4)}
        samples = self.report["host_samples"]
        serial = 0
        for group in range(self.protocol["paired_groups"]):
            profiles = self.protocol["concurrency_profiles"]
            profiles = profiles[group % len(profiles):] + profiles[:group % len(profiles)]
            for profile in profiles:
                arms = [("original_C", original), ("migrated_Hepta_Rust", migrated)]
                if group % 2:
                    arms.reverse()
                for arm, library in arms:
                    require(all(identity(p) == binding for p, binding in bindings.items()), "host artifact changed before sample")
                    receipt = self.work / f"rss-{serial:04d}.json"
                    serial += 1
                    row = self.command([supervisor, receipt, host, library, "concurrency", str(profile["threads"]),
                        str(int(profile["shared"])), str(self.protocol["batches_per_thread"]), str(self.protocol["transactions_per_batch"])],
                        "host.sample." + profile["name"] + "." + arm)
                    observed = validate_observation(json.loads(row["stdout"]), profile, self.protocol, expected[profile["threads"]])
                    memory = json.loads(receipt.read_text())
                    require(memory["child_exit_code"] == 0 and memory["child_signal"] == 0
                            and memory["child_wait4_ru_maxrss_kib"] > 0, "RSS child did not finish normally")
                    samples.append({"group": group, "profile": profile["name"], "arm": arm,
                        "process_index": row["process_index"], "process_seconds": row["seconds"],
                        "observation": observed, "memory": memory, "memory_receipt": identity(receipt)})
        require(all(identity(p) == binding for p, binding in bindings.items()), "host artifact changed during qualification")
        summaries = []
        for profile in self.protocol["concurrency_profiles"]:
            for arm in ("original_C", "migrated_Hepta_Rust"):
                selected = [x for x in samples if x["profile"] == profile["name"] and x["arm"] == arm]
                require(len(selected) == self.protocol["paired_groups"], "missing paired samples")
                latencies = [value for x in selected for value in x["observation"]["batch_ns"]]
                summaries.append({"profile": profile["name"], "arm": arm, "processes": len(selected),
                    "batch_samples": len(latencies), "median_whole_run_ns": statistics.median(x["observation"]["whole_run_ns"] for x in selected),
                    "batch_p50_ns": quantile(latencies, 50), "batch_p95_ns": quantile(latencies, 95), "batch_p99_ns": quantile(latencies, 99),
                    "per_process_batch_p99_ns": [quantile(x["observation"]["batch_ns"], 99) for x in selected],
                    "peak_rss_kib_samples": [x["memory"]["child_wait4_ru_maxrss_kib"] for x in selected],
                    "maximum_peak_rss_kib": max(x["memory"]["child_wait4_ru_maxrss_kib"] for x in selected),
                    "median_peak_rss_kib": statistics.median(x["memory"]["child_wait4_ru_maxrss_kib"] for x in selected)})
        self.report["host_summary"] = summaries

    def run(self):
        self.report["source_bindings"] = source_bindings()
        actual_sha = self.command(["git", "rev-parse", "HEAD"], "source.git_head", cwd=ROOT)["stdout"].strip()
        self.report["git"] = {"head": actual_sha, "status": self.command(["git", "status", "--short"], "source.git_status", cwd=ROOT)["stdout"]}
        require(self.source_sha is None or self.source_sha == actual_sha, "--source-sha does not match current checkout")
        if self.source_sha is not None:
            self.report["committed_source_inventory"] = verify_committed_sources(self.command, self.report["source_bindings"], self.source_sha)
        require(sys.platform == "linux" and platform.machine() == "x86_64", "only actual Linux x86_64 profile is admitted")
        self.report["host"] = {"system": platform.platform(), "machine": platform.machine(), "uname": list(platform.uname()),
            "logical_cpus_visible": os.cpu_count(), "exclusive_host": False, "physical_device_access_observed": False,
            "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None}
        self.report["tools"] = {}
        for name, path in (("gcc", self.gcc), ("clang", self.clang), ("rustc", self.rustc), ("make", self.make)):
            result = self.command([path, "--version"], "tools." + name)
            self.report["tools"][name] = {**identity(path), "version": result["stdout"]}
        manifest = verify_upstream()
        self.report["upstream_manifest"] = manifest
        for version in manifest["versions"]:
            self.build_version(version)
        self.host_profiles()
        self.stage("maintenance_and_source_revalidation")
        before, after = (self.report["versions"][x] for x in PINNED)
        self.report["maintenance"] = {
            "real_upstream_commits": [PINNED[x][0] for x in PINNED], "changed_upstream_files": ["examples/tail.c"],
            "original_makefile_unchanged": True, "original_public_header_unchanged": True,
            "original_ring_implementation_unchanged": True,
            "generated_hepta_body_sha256_unchanged": before["migration_disposition"]["source"]["sha256"] == after["migration_disposition"]["source"]["sha256"],
            "generated_bridge_sha256_unchanged": before["migration_disposition"]["bridge"]["sha256"] == after["migration_disposition"]["bridge"]["sha256"],
            "before_ff_example_hex": before["original_clients"]["tail_cases"][1]["routes"]["migrated"]["stdout_hex"],
            "after_ff_example_hex": after["original_clients"]["tail_cases"][1]["routes"]["migrated"]["stdout_hex"],
            "regenerated_versions": 2, "manual_migrated_body_edits": 0,
            "manual_contract_authoring_hours": None, "manual_review_hours": None, "human_maintenance_hours": None,
            "human_cost_status": "not measured; automatic stage timings are not human labor estimates"}
        require(self.report["maintenance"]["generated_hepta_body_sha256_unchanged"]
                and self.report["maintenance"]["generated_bridge_sha256_unchanged"], "unchanged implementation generated different bodies")
        require(self.report["maintenance"]["before_ff_example_hex"] == "61"
                and self.report["maintenance"]["after_ff_example_hex"] == "61ff62", "upstream EOF change not exercised")
        require(source_bindings() == self.report["source_bindings"], "qualification source changed during execution")
        self.report["claims"].update(original_upstream_build_executed=True, real_upstream_upgrade_executed=True,
            finite_host_abi_concurrency_and_recovery_observed=True)
        self.report["ok"] = True
        self.stage("complete")
        return self.report


def qualify(output, *, clang, rustc, source_sha=None):
    output = Path(output).absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    protocol = json.loads(PROTOCOL_PATH.read_text())
    with output.open("x", encoding="utf-8") as stream:
        evidence = QualificationEvidence(output, stream)
        report = {"schema": "hepta.ring-maintenance.qualification.v1", "ok": False,
            "stage": "source_and_tool_identity", "protocol": protocol, "protocol_sha256": digest(PROTOCOL_PATH),
            "claims": dict(protocol["claims"]), "versions": {}, "host_samples": [],
            "cost": {"automatic_tool_stages": [], "manual_contract_authoring_hours": None,
                     "manual_review_hours": None, "human_maintenance_hours": None,
                     "scope": "automatic execution wall/CPU only; not human development or review cost"}}
        evidence.write(report)
        try:
            evidence.retained.mkdir()
            evidence.retained_owned = True
            trial = Trial(evidence, report, clang=clang, rustc=rustc, source_sha=source_sha)
            return trial.run()
        except BaseException as error:
            report.update(ok=False, error={"type": type(error).__name__, "message": str(error)}, failed_stage=report["stage"])
            report["claims"] = dict(protocol["claims"])
            checkpoint(report, evidence, "failed")
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang-20")
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    try:
        report = qualify(args.output, clang=args.clang, rustc=args.rustc, source_sha=args.source_sha)
        print(json.dumps({"ok": report["ok"], "output": str(args.output), "maintenance": report["maintenance"],
                          "host_summary": report["host_summary"]}, sort_keys=True, indent=2))
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
