"""Bounded, read-only measurements of exact source admission work.

This is instrumentation, not a product optimization or qualification gate.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import ssl
import sys
import time
import traceback

from diagnose_source_scan import identity, snapshot, write_json, protocol_observation


def map_identity(value):
    return identity((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())


def provider_description(provider):
    value = provider(b"")
    return {
        "function_type": type(provider).__name__,
        "module": provider.__module__,
        "name": provider.__name__,
        "hash_type": type(value).__name__,
        "hash_module": type(value).__module__,
        "digest_size": value.digest_size,
        "block_size": value.block_size,
        "empty_digest": value.hexdigest(),
    }


def capabilities(out):
    import _hashlib
    result = {
        "openssl_version": ssl.OPENSSL_VERSION,
        "openssl_version_info": ssl.OPENSSL_VERSION_INFO,
        "hashlib_sha256": provider_description(hashlib.sha256),
        "hashlib_is_openssl_sha256": hashlib.sha256 is _hashlib.openssl_sha256,
        "OPENSSL_ia32cap": os.environ.get("OPENSSL_ia32cap"),
        "available_cpus": sorted(os.sched_getaffinity(0)),
        "cpu_count": os.cpu_count(),
        "hardware_flags_do_not_prove_runtime_dispatch": True,
    }
    raw = Path("/proc/cpuinfo").read_bytes()
    (out / "CPUINFO.txt").write_bytes(raw)
    result["cpuinfo"] = identity(raw)
    models, vendors, flags = set(), set(), set()
    for line in raw.decode("utf-8", "replace").splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key.strip() == "model name":
            models.add(value.strip())
        elif key.strip() == "vendor_id":
            vendors.add(value.strip())
        elif key.strip() == "flags":
            flags.add(tuple(value.split()))
    result["cpu_models"] = sorted(models)
    result["cpu_vendors"] = sorted(vendors)
    result["cpu_flag_sets"] = [list(row) for row in sorted(flags)]
    modules = {"hashlib": hashlib, "_hashlib": _hashlib, "ssl": ssl}
    try:
        alternative = importlib.import_module("_sha2")
        modules["_sha2"] = alternative
        result["sha2_sha256"] = provider_description(alternative.sha256)
    except ImportError as error:
        alternative = None
        result["sha2_unavailable"] = {"type": type(error).__name__, "message": str(error)}
    result["module_files"] = {}
    for name, module in modules.items():
        path = Path(module.__file__)
        result["module_files"][name] = {"path": str(path), **identity(path.read_bytes())}
    libraries = set()
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith("/") and "libcrypto" in fields[5]:
            libraries.add(fields[5])
    result["mapped_libcrypto_files"] = [
        {"path": name, **identity(Path(name).read_bytes())} for name in sorted(libraries)
    ]
    return result, alternative


class ComponentCalls(ast.NodeTransformer):
    def __init__(self):
        self.counts = {"open": 0, "read": 0, "digest": 0}

    def visit_Call(self, node):
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr == "hexdigest"
                and not node.args and not node.keywords
                and isinstance(fn.value, ast.Call)
                and isinstance(fn.value.func, ast.Name) and fn.value.func.id == "sha256"
                and len(fn.value.args) == 1 and not fn.value.keywords):
            self.counts["digest"] += 1
            # Resolve the original hash provider before evaluating its data, as
            # the original nested call does. All timing remains diagnostic.
            return ast.copy_location(ast.Call(
                func=ast.Name(id="_diag_digest", ctx=ast.Load()),
                args=[copy.deepcopy(fn.value.func), ast.Name(id="path", ctx=ast.Load()),
                      self.visit(fn.value.args[0])], keywords=[]), node)
        if (isinstance(fn, ast.Attribute) and fn.attr == "open"
                and isinstance(fn.value, ast.Name) and fn.value.id == "_source_io"):
            self.counts["open"] += 1
            return ast.copy_location(ast.Call(
                func=ast.Name(id="_diag_open", ctx=ast.Load()),
                args=[copy.deepcopy(fn)] + [self.visit(value) for value in node.args],
                keywords=[self.visit(value) for value in node.keywords]), node)
        if (isinstance(fn, ast.Attribute) and fn.attr == "read"
                and isinstance(fn.value, ast.Name) and fn.value.id == "stream"
                and not node.args and not node.keywords):
            self.counts["read"] += 1
            return ast.copy_location(ast.Call(
                func=ast.Name(id="_diag_read", ctx=ast.Load()),
                args=[copy.deepcopy(fn)], keywords=[]), node)
        return self.generic_visit(node)


class Measurement:
    def __init__(self, contract, out):
        self.rows = []
        self.active_path = None
        self.guard = contract._source_protocol_current
        namespace = dict(vars(contract))
        namespace.update(_source_protocol_current=self.guard_call,
                         _diag_open=self.open_call, _diag_read=self.read_call,
                         _diag_digest=self.digest_call)
        names = ("file_digests", "_source_lexical_read", "_source_relative_name")
        original = "\n\n".join(inspect.getsource(getattr(contract, name)) for name in names)
        (out / "ORIGINAL-FUNCTIONS.py").write_text(original)
        tree = ast.parse(original)
        transform = ComponentCalls()
        transformed = ast.fix_missing_locations(transform.visit(copy.deepcopy(tree)))
        if transform.counts != {"open": 1, "read": 1, "digest": 2}:
            raise ValueError(("unexpected source call shapes", transform.counts))
        (out / "INSTRUMENTED-FUNCTIONS.py").write_text(ast.unparse(transformed) + "\n")
        exec(compile(transformed, "<exact-source-component-diagnostic>", "exec"), namespace)
        self.lexical = namespace["_source_lexical_read"]
        namespace["_source_lexical_read"] = self.lexical_call
        self.file_digests = namespace["file_digests"]
        self.transform_counts = transform.counts

    def call(self, kind, function, args, kwargs, *, path=None):
        begin = time.perf_counter_ns()
        cpu = time.process_time_ns()
        result = function(*args, **kwargs)
        cpu = time.process_time_ns() - cpu
        end = time.perf_counter_ns()
        row = {"kind": kind, "path": self.active_path if path is None else path,
               "begin_ns": begin, "end_ns": end,
               "wall_ns": end - begin, "process_cpu_ns": cpu}
        if kind == "guard":
            row["result"] = result
        elif kind == "read":
            row["bytes"] = len(result)
            row["exact_bytes"] = type(result) is bytes
        self.rows.append(row)
        return result

    def guard_call(self, root):
        return self.call("guard", self.guard, (root,), {})

    def open_call(self, function, *args, **kwargs):
        return self.call("open", function, args, kwargs)

    def read_call(self, function):
        return self.call("read", function, (), {})

    def digest_call(self, provider, path, data):
        begin = time.perf_counter_ns()
        cpu = time.process_time_ns()
        result = provider(data).hexdigest()
        cpu = time.process_time_ns() - cpu
        end = time.perf_counter_ns()
        self.rows.append({"kind": "digest", "path": path,
                          "begin_ns": begin, "end_ns": end,
                          "wall_ns": end - begin, "process_cpu_ns": cpu,
                          "bytes": len(data), "exact_bytes": type(data) is bytes})
        return result

    def lexical_call(self, root, relative, prefix):
        previous = self.active_path
        self.active_path = relative
        try:
            return self.call("lexical_inclusive", self.lexical, (root, relative, prefix), {})
        finally:
            self.active_path = previous


def summarize(rows, expected):
    totals = {}
    by_path = {}
    for row in rows:
        total = totals.setdefault(row["kind"], {"count": 0, "wall_ns": 0, "process_cpu_ns": 0})
        total["count"] += 1
        total["wall_ns"] += row["wall_ns"]
        total["process_cpu_ns"] += row["process_cpu_ns"]
        if row["kind"] == "guard" and row["result"] is not True:
            raise ValueError("standard provider guard changed during observation")
        if row["kind"] in ("read", "digest") and row["exact_bytes"] is not True:
            raise ValueError("non-exact bytes encountered")
        if row["path"] is not None:
            by_path.setdefault(row["path"], {}).setdefault(row["kind"], []).append(row)
    for kind in ("open", "read", "digest", "lexical_inclusive"):
        if totals.get(kind, {}).get("count") != len(expected):
            raise ValueError(("unexpected per-file count", kind, totals.get(kind)))
    if set(by_path) != set(expected):
        raise ValueError("observed path domain differs")
    for path, kinds in by_path.items():
        for kind in ("open", "read", "digest", "lexical_inclusive"):
            if len(kinds[kind]) != 1:
                raise ValueError(("multiple observed operations for file", path, kind))
        opened, read, lexical, digest = (kinds[k][0] for k in ("open", "read", "lexical_inclusive", "digest"))
        if not (lexical["begin_ns"] <= opened["begin_ns"] <= opened["end_ns"]
                <= read["begin_ns"] <= read["end_ns"] <= lexical["end_ns"] <= digest["begin_ns"]):
            raise ValueError(("open/read/lexical-completion/hash order changed", path))
        if read["bytes"] != digest["bytes"]:
            raise ValueError(("read/hash size differs", path))
    file_guard_wall = sum(row["wall_ns"] for row in rows if row["kind"] == "guard" and row["path"] is not None)
    residual = (totals["lexical_inclusive"]["wall_ns"] - file_guard_wall
                - totals["open"]["wall_ns"] - totals["read"]["wall_ns"])
    return {"inclusive_totals": totals,
            "lexical_residual_wall_ns": residual,
            "lexical_residual_includes": "close/context manager, argument dispatch, row allocation and timer overhead; not an exact close timer",
            "all_lexical_completions_precede_hash": True}


def timed_map(name, function, expected, expected_hash):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    actual = function()
    cpu, wall = time.process_time_ns() - cpu, time.perf_counter_ns() - wall
    if list(actual.items()) != list(expected.items()):
        raise ValueError(("map values or insertion order differs", name))
    value = map_identity(actual)
    if value["sha256"] != expected_hash:
        raise ValueError(("map identity differs", name, value))
    return {"kind": name, "wall_ns": wall, "process_cpu_ns": cpu,
            "paths": len(actual), "map": value}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    expected = json.loads(args.inputs.read_text())
    report = {"schema": "hepta.fresh-source-components-diagnostic.v1",
              "status": "INCOMPLETE", "qualification": False, "whole_native": False,
              "python": sys.version, "inputs": expected, "product_tests_executed": 0,
              "native_compilations": 0, "product_policy_edited": False,
              "original_budgets_modified": False, "started_utc_ns": time.time_ns(),
              "methodological_limits": [
                  "Warm source reads: complete source snapshots and two original scans precede measurements.",
                  "Instrumented AST copies run in a private globals dictionary; no product module function/provider is replaced.",
                  "Per-component timers and result bookkeeping perturb execution. Original and instrumented totals are separate.",
                  "Nested totals are inclusive and must not be added as disjoint cost categories.",
                  "Process CPU excludes child processes; this diagnostic starts no product child or compiler.",
                  "Owned-bytes SHA comparisons are pure-computation diagnostics, not permission to reorder production I/O/hash or exceptions.",
                  "CPU flags describe availability, not proof of OpenSSL's selected assembly implementation.",
                  "No cProfile is run here; earlier cProfile observations have a different instrumented scope.",
              ]}
    before = affinity = None
    try:
        if tuple(sys.version_info[:3]) != tuple(expected["python_version"]):
            raise ValueError(("wrong runtime", sys.version))
        sys.dont_write_bytecode = True
        for key in tuple(os.environ):
            if key.startswith("HEPTA_HIA_"):
                del os.environ[key]
        before = snapshot(source, expected)
        report["before"] = write_json(out / "SOURCE-BEFORE.json", before)
        sys.path.insert(0, str(source))
        from tools import hia_selfhost_contract as contract
        report["protocol"] = protocol_observation(contract)
        if report["protocol"]["current"] is not True:
            raise ValueError("actual original standard provider protocol is not admitted")
        report["capabilities"], alternative = capabilities(out)
        affinity = os.sched_getaffinity(0)
        cpu = min(affinity)
        os.sched_setaffinity(0, {cpu})
        report["measurement_cpu"] = cpu
        reference = contract.file_digests()
        if len(reference) != expected["fresh_paths"] or map_identity(reference)["sha256"] != expected["fresh_map_sha256"]:
            raise ValueError("initial full fresh map differs from fixed input")
        if contract.file_digests() != reference:
            raise ValueError("second original warmup map differs")
        report["warmup_original_scans"] = 2
        write_json(out / "REFERENCE-MAP.json", reference)
        observer = Measurement(contract, out)
        report["instrumentation_transform_counts"] = observer.transform_counts
        report["scans"] = []
        for index, name in enumerate(expected["scan_order"]):
            observer.rows = []
            function = contract.file_digests if name == "original" else observer.file_digests
            row = timed_map(name, function, reference, expected["fresh_map_sha256"])
            if name == "instrumented":
                row["components"] = summarize(observer.rows, reference)
                row["events"] = write_json(out / ("COMPONENT-EVENTS-%02d.json" % index), observer.rows)
            report["scans"].append(row)
            write_json(out / ("SCAN-%02d.json" % index), row)
        # These bytes are owned only by the diagnostic. Every product scan
        # above reread all paths in the original read/close/hash order.
        owned = []
        for path, digest in reference.items():
            data = (source / path).read_bytes()
            if type(data) is not bytes or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(("owned input differs", path))
            owned.append((path, data))
        sizes = [{"path": path, "bytes": len(data)} for path, data in owned]
        if sum(row["bytes"] for row in sizes) != expected["fresh_bytes"]:
            raise ValueError("owned complete byte count differs")
        report["file_sizes"] = write_json(out / "FILE-SIZES.json", sizes)
        report["largest_files"] = sorted(sizes, key=lambda row: (-row["bytes"], row["path"]))[:30]
        providers = {"hashlib.sha256": hashlib.sha256}
        if alternative is not None:
            providers["_sha2.sha256"] = alternative.sha256
        report["owned_byte_hash_runs"] = []
        for name in expected["pure_hash_order"]:
            if name not in providers:
                report["owned_byte_hash_runs"].append({"provider": name, "status": "UNAVAILABLE"})
                continue
            provider = providers[name]
            def calculate():
                return {path: provider(data).hexdigest() for path, data in owned}
            row = timed_map(name, calculate, reference, expected["fresh_map_sha256"])
            row.update(provider=name, owned_paths=len(owned), owned_bytes=expected["fresh_bytes"], status="MATCH")
            report["owned_byte_hash_runs"].append(row)
        if contract._source_protocol_current(contract.ROOT) is not True:
            raise ValueError("original provider identity changed")
        report["status"] = "OBSERVATIONS_COMPLETE"
    except BaseException:
        report["status"] = "DIAGNOSTIC_FAILURE"
        report["failure"] = traceback.format_exc()
        (out / "FAILURE.txt").write_text(report["failure"])
    finally:
        if affinity is not None:
            os.sched_setaffinity(0, affinity)
            report["affinity_restored"] = os.sched_getaffinity(0) == affinity
        try:
            after = snapshot(source, expected)
            report["after"] = write_json(out / "SOURCE-AFTER.json", after)
            report["source_unchanged"] = before is not None and before == after
            if not report["source_unchanged"]:
                report["status"] = "DIAGNOSTIC_FAILURE"
        except BaseException:
            report["source_unchanged"] = False
            report["after_failure"] = traceback.format_exc()
            report["status"] = "DIAGNOSTIC_FAILURE"
        report["finished_utc_ns"] = time.time_ns()
        write_json(out / "REPORT.json", report)
        print(json.dumps({key: report.get(key) for key in (
            "status", "python", "source_unchanged", "qualification", "failure",
            "scans", "owned_byte_hash_runs")}, sort_keys=True), flush=True)
    return 0 if report["status"] == "OBSERVATIONS_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
