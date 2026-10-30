"""New assembly and C++ assignment routes re-enter the shared Core verifier."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from hepta.hia_routes import admit_route, RouteRejected, execute_route
from tests.test_hia_optimization import constant_program


class Round4Routes(unittest.TestCase):
    def program(self):
        doc = constant_program()
        doc["schema"] = "hepta.hia.program.v6"
        return verify_program(doc)

    def test_assembly_exact_core_execution_and_context_refusal(self):
        original = self.program()
        text = render_assembly(original)
        self.assertEqual(admit_route("agent-assembly",text),original)
        self.assertEqual(execute_route("agent-assembly",text,"calculate",[7]),
                         execute_route("standalone-hia",original,"calculate",[7]))
        for context in ({"source":"override"},{"module":"override"},{"path":"override"},
                        {"clangxx":"override"},{"variant":"override"}):
            with self.subTest(context=context),self.assertRaises(RouteRejected):
                admit_route("agent-assembly",text,**context)

    def test_cli_import_render_check_actual_roundtrip_and_no_replace(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source,assembly,back=root/"core.json",root/"program.hiaasm",root/"back.json"
            source.write_text(json.dumps(self.program().as_dict()))
            for argv in (["render-assembly",str(source),"-o",str(assembly)],
                         ["check-assembly",str(assembly)],
                         ["import-assembly",str(assembly),"-o",str(back)]):
                output=io.StringIO()
                with contextlib.redirect_stdout(output):self.assertEqual(main(["hia",*argv]),0)
                result=json.loads(output.getvalue())
                if argv[0]=="check-assembly":
                    self.assertTrue(result["accepted"])
                    self.assertFalse(result["deployment_authority"])
            self.assertEqual(verify_program(back.read_bytes()),self.program())
            before=assembly.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(main(["hia","render-assembly",str(source),"-o",str(assembly)]),0)
            self.assertEqual(assembly.read_bytes(),before)

    def test_bad_assembly_diagnostic_does_not_publish_core(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/"bad.hiaasm"
            source.write_text("hia-asm.v1 unregistered_schema malicious\n")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["hia","check-assembly",str(source)]),1)
            result=json.loads(output.getvalue())
            self.assertFalse(result["accepted"])
            self.assertFalse(result["native_artifact_created"])
            target=Path(td)/"core.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(main(["hia","import-assembly",str(source),"-o",str(target)]),0)
            self.assertFalse(target.exists())

    def test_assignment_routes_validate_all_variants_before_selection(self):
        for route,function in (("cpp-unique-assignment-project","lower_unique_assignment_project"),
                               ("cpp-unique-assignment-matrix","lower_unique_assignment_matrix")):
            matrix=route.endswith("matrix")
            captured=({"variants":[{"name":"selected","program":constant_program()}]} if matrix
                      else {"program":constant_program()})
            argv=["hia","import-"+route,"capture.json"]+(["--variant","selected"] if matrix else [])
            output=io.StringIO()
            with patch("hepta.cpp_unique_project."+function,return_value=captured),contextlib.redirect_stdout(output):
                self.assertEqual(main(argv),0)
            self.assertEqual(verify_program(json.loads(output.getvalue())),verify_program(constant_program()))
        captured={"variants":[{"name":"selected","program":constant_program()},
                              {"name":"other","program":{"schema":"forged-receipt"}}]}
        with patch("hepta.cpp_unique_project.lower_unique_assignment_matrix",return_value=captured):
            with self.assertRaises(ValueError):
                admit_route("cpp-unique-assignment-matrix","capture.json",variant="selected")


if __name__=="__main__":unittest.main()
