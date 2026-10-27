import json
from pathlib import Path
import tempfile
import unittest

from hepta.pipeline import analyze, analyze_project
from hepta.source_map import map_diagnostics, source_markers


class SourceMapTests(unittest.TestCase):
    def test_real_rust_borrow_error_points_to_original_imported_statement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            main = root / "main.hepta"
            main.write_text("import worker; fn main() -> Unit effects {write, panic} { worker::bad(); }")
            other = root / "worker.hepta"
            other.write_text("fn pair(a: mut [u8], b: mut [u8]) -> Unit effects {write, panic} { a[0]=1; b[0]=2; }\n"
                             "pub fn bad() -> Unit effects {write, panic} {\n"
                             " let mut data: [u8; 2] = [0,0];\n"
                             " pair(mut data, mut data);\n}")
            result = analyze_project(main)
            self.assertFalse(result.report["ok"])
            diagnostic = next(d for d in result.report["diagnostics"] if d["code"] == "E0499")
            self.assertEqual(diagnostic["span"]["path"], str(other))
            self.assertEqual(diagnostic["span"]["line"], 4)
            self.assertEqual(diagnostic["source_mappings"][0]["precision"], "statement")

    def test_runtime_and_generated_entrypoint_are_not_mapped_to_previous_function(self):
        result = analyze("fn main() -> Unit effects {} {}", native=False, crate_type="bin")
        lines = result.rust.splitlines()
        wrapper = next(i for i, line in enumerate(lines, 1) if line.startswith("fn main()"))
        diagnostic = {"generated_spans": [{"file_name": "program.rs", "line_start": wrapper,
                                            "line_end": wrapper, "is_primary": True}]}
        self.assertNotIn("span", map_diagnostics(result.rust, [diagnostic])[0])

    def test_unbalanced_or_invalid_markers_fail_closed(self):
        span = {"path": "a.hepta", "start": 0, "end": 10, "line": 1, "column": 1}
        begin = "// hepta-source: " + json.dumps({"event": "begin", "kind": "statement", "span": span})
        self.assertEqual(source_markers(begin + "\nlet x = 1;"), [])
        self.assertEqual(source_markers('// hepta-source: {"event":"end"}'), [])

    def test_external_file_with_similar_name_is_not_mapped(self):
        result = analyze("fn sample() -> i32 effects {} { return 3; }", native=False)
        line = next(i for i, text in enumerate(result.rust.splitlines(), 1) if "return 3" in text)
        for filename in ("/foreign/not_program.rs", "/foreign/program.rs"):
            diagnostic = {"generated_spans": [{"file_name": filename, "line_start": line, "line_end": line}]}
            mapped = map_diagnostics(result.rust, [diagnostic], generated_path="/candidate/program.rs")
            self.assertNotIn("span", mapped[0])


if __name__ == "__main__":
    unittest.main()
