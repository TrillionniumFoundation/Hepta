"""Composed C++ lifetimes: typed copied edges, real STL, and reverse cleanup."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected
from hepta.cpp_contracts import _Generator, _validate, bridge_cpp_contracts


def parameter(name, typ, mode="value"):
    result = {"name": name, "type": typ, "mode": mode}
    if mode != "value":
        result["retention"] = "call_only"
    return result


def contract():
    handles = []
    for name, cpp in (("Vector", "std::vector"), ("Deque", "std::deque")):
        handles.append({"name": name, "cpp_type": cpp, "template_args": ["i64"],
                        "threading": "serialized", "reentrancy": "reject",
                        "allocator": "cpp_shared_owner", "destruction": "nothrow_defer_inflight",
                        "constructors": [{"name": "filled", "params": [parameter("count", "usize"), parameter("initial", "i64")],
                                          "exception": "catch_status"}],
                        "methods": [{"name": "at", "cpp_method": "at", "const": True,
                                     "params": [parameter("index", "usize")], "returns": "i64",
                                     "return_mode": "copy_from_reference", "exception": "catch_status"}]})
    handles[0]["methods"].append({"name": "append", "cpp_method": "push_back", "const": False,
                                  "params": [parameter("value", "i64", "const_ref")], "returns": "Unit",
                                  "return_mode": "value", "exception": "catch_status"})
    return {"schema": "hepta.cpp-contract.v5", "module": "composed", "pod_types": [], "functions": [],
            "handles": handles, "scopes": [], "pipelines": [{
                "name": "vector_deque", "params": [parameter("count", "usize"), parameter("initial", "i64"),
                    parameter("appended", "i64", "const_ref"), parameter("index", "usize"),
                    parameter("other_count", "usize"), parameter("other_index", "usize")],
                "steps": [
                    {"op": "construct", "name": "source", "handle": "Vector", "constructor": "filled", "args": ["count", "initial"]},
                    {"op": "call", "object": "source", "method": "append", "args": ["appended"], "result": None},
                    {"op": "call", "object": "source", "method": "at", "args": ["index"], "result": "copied"},
                    {"op": "construct", "name": "destination", "handle": "Deque", "constructor": "filled", "args": ["other_count", "copied"]},
                    {"op": "call", "object": "destination", "method": "at", "args": ["other_index"], "result": "answer"},
                ], "return": "answer", "lifetime": "call_scoped_cpp_raii"}]}


class PipelineContractTests(unittest.TestCase):
    def test_v5_is_explicit_and_preserves_old_schema_shapes(self):
        self.assertEqual(_validate(contract())["schema"], "hepta.cpp-contract.v5")
        for schema in ("hepta.cpp-contract.v1", "hepta.cpp-contract.v2", "hepta.cpp-contract.v3", "hepta.cpp-contract.v4"):
            old = contract()
            old["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(MigrationRejected):
                _validate(old)

    def test_lifetime_and_dataflow_refusals(self):
        mutations = {
            "missing_pipelines": lambda c: c.pop("pipelines"),
            "object_escape": lambda c: c["pipelines"][0].update({"return": "source"}),
            "future_reference": lambda c: c["pipelines"][0]["steps"][0].update(args=["count", "copied"]),
            "receiver_before_construct": lambda c: c["pipelines"][0]["steps"][1].update(object="destination"),
            "wrong_type": lambda c: c["pipelines"][0]["steps"][3].update(args=["other_count", "index"]),
            "wrong_input_category": lambda c: c["pipelines"][0]["params"][2].update(mode="value"),
            "object_as_argument": lambda c: c["pipelines"][0]["steps"][3].update(args=["other_count", "source"]),
            "shadow_input": lambda c: c["pipelines"][0]["steps"][2].update(result="initial"),
            "capture_unit": lambda c: c["pipelines"][0]["steps"][1].update(result="unit"),
            "empty_steps": lambda c: c["pipelines"][0].update(steps=[]),
            "too_many_steps": lambda c: c["pipelines"][0].update(steps=c["pipelines"][0]["steps"] * 7),
            "unknown_op": lambda c: c["pipelines"][0]["steps"][0].update(op="raw_cpp"),
            "unknown_field": lambda c: c["pipelines"][0]["steps"][0].update(unsafe=True),
            "unknown_constructor": lambda c: c["pipelines"][0]["steps"][0].update(constructor="missing"),
            "unknown_method": lambda c: c["pipelines"][0]["steps"][1].update(method="missing"),
            "unknown_handle": lambda c: c["pipelines"][0]["steps"][0].update(handle="missing"),
            "escaping_lifetime": lambda c: c["pipelines"][0].update(lifetime="return_object"),
            "code_injection": lambda c: c["pipelines"][0]["steps"][2].update(result="value();"),
            "duplicate_export": lambda c: c["pipelines"][0].update(name="Vector_at"),
        }
        for name, mutate in mutations.items():
            value = contract()
            mutate(value)
            with self.subTest(case=name), self.assertRaises(MigrationRejected):
                _validate(value)


@unittest.skipUnless(shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc")), "native C++ and Rust toolchain required")
class PipelineNativeTests(unittest.TestCase):
    def generate_and_run(self, header_text, candidate, harness):
        with tempfile.TemporaryDirectory(prefix="hepta-pipeline-test-") as temporary:
            root = Path(temporary)
            header = root / "foreign.hpp"
            header.write_text(header_text)
            generated = root / "bridge"
            report = bridge_cpp_contracts(header, candidate, generated, cxx="g++", rustc=os.environ.get("RUSTC"))
            self.assertTrue(report["ok"], report["diagnostics"])
            main = root / "main.cpp"
            main.write_text(harness)
            executable = root / "observe"
            compile = subprocess.run(["g++", "-std=c++20", "-O2", "-pthread", "-I" + str(root), "-I" + str(generated),
                                      str(generated / "bridge.cpp"), str(main), "-o", str(executable)], capture_output=True, text=True)
            self.assertEqual(compile.returncode, 0, compile.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            return report, json.loads(run.stdout)

    def test_caller_mutation_cannot_rebind_native_checked_contract(self):
        candidate = contract()
        original = deepcopy(candidate)
        canonical = json.dumps(original, sort_keys=True, separators=(",", ":")).encode()
        render = _Generator.render
        rendered_cpp = []

        def mutate_after_real_render(generator):
            rendered = render(generator)
            rendered_cpp.append(rendered[0])
            # A and B are both legal but produce different answers. Alter only
            # caller-owned data after the real render, never compiler results.
            candidate["pipelines"][0]["steps"][2]["args"] = ["other_index"]
            candidate["pipelines"][0]["steps"][4]["args"] = ["index"]
            _validate(candidate)
            return rendered

        with tempfile.TemporaryDirectory(prefix="hepta-pipeline-snapshot-") as temporary:
            root = Path(temporary)
            header = root / "foreign.hpp"
            header.write_text("#pragma once\n#include <cstdint>\n#include <vector>\n#include <deque>\n")
            generated = root / "bridge"
            with patch.object(_Generator, "render", mutate_after_real_render):
                report = bridge_cpp_contracts(header, candidate, generated, cxx="g++", rustc=os.environ.get("RUSTC"))
            self.assertTrue(report["ok"], report["diagnostics"])
            self.assertGreater(report["object_bytes"], 0)
            self.assertNotEqual(candidate, original)
            self.assertEqual(json.loads((generated / "contract.json").read_text()), original)
            self.assertEqual(report["contract_sha256"], hashlib.sha256(canonical).hexdigest())
            self.assertEqual((generated / "bridge.cpp").read_text(), rendered_cpp[0])
            for filename, info in report["outputs"].items():
                self.assertEqual(info["sha256"], hashlib.sha256((generated / filename).read_bytes()).hexdigest())
            self.assertEqual(json.loads((generated / "report.json").read_text())["contract_sha256"], report["contract_sha256"])
            main = root / "main.cpp"
            main.write_text('''#include "bridge.h"
#include <cstdint>
int main() {
  std::int64_t result = 991;
  // A selects the appended vector value; B would select the original value 7.
  return hepta_cpp_composed_vector_deque(2, 7, 19, 2, 3, 0, &result) != 0 || result != 19;
}
''')
            executable = root / "observe"
            compiled = subprocess.run(["g++", "-std=c++20", "-O2", "-pthread", "-I" + str(generated),
                                       str(generated / "bridge.cpp"), str(main), "-o", str(executable)],
                                      capture_output=True, text=True, timeout=90)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            observed = subprocess.run([str(executable)], capture_output=True, text=True, timeout=20)
            self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_real_stl_value_flow_and_error_cleanup(self):
        header = "#pragma once\n#include <cstdint>\n#include <vector>\n#include <deque>\n"
        harness = r'''#include "bridge.h"
#include <cstdio>
#include <cstdint>
int main() {
  for (unsigned n = 0; n < 16; ++n) {
    std::int64_t result = 991;
    if (hepta_cpp_composed_vector_deque(n, 7, 19, n, 3, 1, &result) != 0 || result != 19) return 1;
    result = 991;
    if (hepta_cpp_composed_vector_deque(n, 7, 19, n + 1, 3, 1, &result) != 3 || result != 991) return 2;
    if (hepta_cpp_composed_vector_deque(n, 7, 19, n, 0, 0, &result) != 3 || result != 991) return 3;
  }
  if (hepta_cpp_composed_vector_deque(1, 7, 19, 0, 1, 0, nullptr) != 1) return 4;
  std::printf("{\"cases\":49}\n");
}'''
        report, result = self.generate_and_run(header, contract(), harness)
        self.assertEqual(result, {"cases": 49})
        checks = report["pipeline_lifetime_checks"][0]
        self.assertEqual(checks["normal_destruction_order"], ["destination", "source"])
        self.assertFalse(checks["foreign_implementation_rewritten"])

    def test_copy_before_mutation_reverse_unwind_and_publish_after_cleanup(self):
        header = r'''#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>
struct Probe {
  static inline int live=0, order=0;
  static inline const std::int64_t* output=nullptr;
  std::vector<std::int64_t> data;
  std::uint64_t identity;
  Probe(std::int64_t value, std::uint64_t id, std::uint64_t fail):data(3,value),identity(id) {
    if (id==fail) throw std::runtime_error("construction");
    ++live;
  }
  ~Probe() noexcept {
    if (!output || *output!=991) std::abort();
    order=order*10+static_cast<int>(identity); --live;
  }
  const std::int64_t& read() const noexcept {return data[0];}
  void write(std::int64_t value) noexcept {data[0]=value;}
  std::int64_t finish(std::uint64_t fail) const {
    if (identity==fail) throw std::runtime_error("method");
    return data[0];
  }
};'''
        obj = {"name": "Probe", "cpp_type": "Probe", "template_args": [], "threading": "serialized", "reentrancy": "reject",
               "allocator": "cpp_shared_owner", "destruction": "nothrow_defer_inflight",
               "constructors": [{"name": "new", "params": [parameter("value", "i64"), parameter("id", "u64"), parameter("fail", "u64")],
                                 "exception": "catch_status"}],
               "methods": [
                   {"name": "read", "cpp_method": "read", "const": True, "params": [], "returns": "i64", "return_mode": "copy_from_reference", "exception": "noexcept"},
                   {"name": "write", "cpp_method": "write", "const": False, "params": [parameter("value", "i64")], "returns": "Unit", "return_mode": "value", "exception": "noexcept"},
                   {"name": "finish", "cpp_method": "finish", "const": True, "params": [parameter("fail", "u64")], "returns": "i64", "return_mode": "value", "exception": "catch_status"},
               ]}
        candidate = {"schema": "hepta.cpp-contract.v5", "module": "observe", "pod_types": [], "functions": [],
                     "handles": [obj], "scopes": [], "pipelines": [{"name": "run", "lifetime": "call_scoped_cpp_raii",
                        "params": [parameter("initial", "i64"), parameter("replacement", "i64"), parameter("one", "u64"),
                                   parameter("two", "u64"), parameter("constructor_failure", "u64"), parameter("method_failure", "u64")],
                        "steps": [
                            {"op": "construct", "name": "first", "handle": "Probe", "constructor": "new", "args": ["initial", "one", "constructor_failure"]},
                            {"op": "call", "object": "first", "method": "read", "args": [], "result": "saved"},
                            {"op": "call", "object": "first", "method": "write", "args": ["replacement"], "result": None},
                            {"op": "construct", "name": "second", "handle": "Probe", "constructor": "new", "args": ["saved", "two", "constructor_failure"]},
                            {"op": "call", "object": "second", "method": "finish", "args": ["method_failure"], "result": "answer"}],
                        "return": "answer"}]}
        harness = r'''#include "bridge.h"
#include "foreign.hpp"
#include <cstdio>
int main() {
  for (unsigned ctor=0;ctor<3;++ctor) for (unsigned method=0;method<3;++method) {
    std::int64_t out=991; Probe::output=&out; Probe::order=0;
    int status=hepta_cpp_observe_run(7,29,1,2,ctor,method,&out);
    int wanted=(ctor!=0||method==2)?3:0;
    if (status!=wanted || out!=(wanted?991:7) || Probe::live) return 1;
    if (Probe::order!=(ctor==1?0:ctor==2?1:21)) return 2;
  }
  std::printf("{\"cases\":9,\"live\":0}\n");
}'''
        report, result = self.generate_and_run(header, candidate, harness)
        self.assertEqual(result, {"cases": 9, "live": 0})
        self.assertTrue(report["pipeline_lifetime_checks"][0]["output_published_after_all_destructors"])


if __name__ == "__main__":
    unittest.main()
