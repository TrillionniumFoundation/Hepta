"""Exact ordinary CLI comparisons, native phase lifecycle and original callers."""
from __future__ import annotations

import argparse
import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

from hepta import cli
from hepta.hia_cli_native import (
    NativeCli, CliSession, SOURCES, SELECTOR, STEP_MAGIC, CONTROL_SCHEMA,
    installed_cli, _print_parser_message,
)

ROOT = Path(__file__).resolve().parents[1]
COLD = "HEPTA_HIA_CLI_COLD_REPORT"
DEVELOPMENT = "HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST"
FIXTURE_EVIDENCE = "HEPTA_HIA_CLI_FIXTURE_EVIDENCE"
ENVIRONMENT = {"COLUMNS": "80", "LINES": "24", "TERM": "dumb",
               "PYTHON_COLORS": "0", "NO_COLOR": "", "FORCE_COLOR": ""}


def environment(values=None):
    result = {key: value for key, value in os.environ.items() if not key.startswith("HEPTA_HIA_")}
    result.update(ENVIRONMENT)
    result.update(values or {})
    return result


class Parsed(BaseException):
    def __init__(self, namespace):
        self.namespace = namespace


def parser_outcome(owner, argv, *, selected):
    output, errors = io.StringIO(), io.StringIO()
    real_parse = argparse.ArgumentParser.parse_args
    def stop(parser, *args, **kwargs):
        raise Parsed(real_parse(parser, *args, **kwargs))
    with redirect_stdout(output), redirect_stderr(errors):
        try:
            if selected:
                with patch.object(argparse, "ArgumentParser", side_effect=AssertionError("retained parser entered")):
                    session = owner.prepare(argv, cli)
                    if session.kind == 0:
                        answer = ("namespace", vars(session.namespace))
                    else:
                        first, second = owner.format_result(session)
                        if session.kind == 3:
                            _print_parser_message(first, sys.stderr)
                            _print_parser_message(second, sys.stderr)
                        else:
                            _print_parser_message(first + second, sys.stdout)
                        answer = ("exit", session.exit_code)
            else:
                with patch.object(argparse.ArgumentParser, "parse_args", stop):
                    cli._reference_hia_main(argv)
                raise AssertionError("reference parser did not produce a namespace")
        except Parsed as result:
            answer = ("namespace", vars(result.namespace))
        except SystemExit as error:
            answer = ("exit", error.code)
        except BaseException as error:
            answer = ("error", type(error).__name__, str(error))
    return answer, output.getvalue(), errors.getvalue()


def entry_outcome(argv, manifest=None):
    output, errors = io.StringIO(), io.StringIO()
    with ExitStack() as stack:
        stack.enter_context(redirect_stdout(output))
        stack.enter_context(redirect_stderr(errors))
        if manifest is not None:
            stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
            stack.enter_context(patch.object(cli, "_reference_hia_main",
                                            side_effect=AssertionError("retained CLI entered")))
            stack.enter_context(patch.object(argparse, "ArgumentParser",
                                            side_effect=AssertionError("retained parser entered")))
        try:
            answer = ("return", cli.hia_main(argv))
        except SystemExit as error:
            answer = ("exit", error.code)
        except BaseException as error:
            answer = ("error", type(error).__name__, str(error))
    return answer, output.getvalue(), errors.getvalue()


class CliSourceTests(unittest.TestCase):
    def test_complete_regeneration_and_unchanged_native_profile(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools import generate_hia_cli_control, generate_hia_cli_format
        for name, generator in (("control", generate_hia_cli_control), ("format", generate_hia_cli_format)):
            with self.subTest(kernel=name):
                document = generator.document()
                assembly = render_assembly(document)
                self.assertEqual(SOURCES[name].read_text(), assembly)
                self.assertLessEqual(len(document["functions"]), 128)
                self.assertLessEqual(sum(len(fn["blocks"]) for fn in document["functions"]), 1536)
                self.assertLessEqual(sum(len(block["ops"]) for fn in document["functions"]
                                         for block in fn["blocks"]), 8192)
                for fn in document["functions"]:
                    definitions = {value["name"] for value in fn["params"]}
                    for block in fn["blocks"]:
                        definitions.update(value["name"] for value in block["params"])
                        definitions.update(value["name"] for op in block["ops"] for value in op["out"])
                    self.assertLessEqual(len(fn["blocks"]), 256)
                    self.assertLessEqual(len(definitions), 2048)
                self.assertLessEqual(len(assembly.encode()), 1 << 20)

    def test_matching_cold_build_rejects_before_output_creation(self):
        from tools.build_hia_cli_native import build
        with tempfile.TemporaryDirectory(prefix="hia-cli-bad-cold-") as folder:
            root = Path(folder)
            (root / "compiler").write_bytes(b"unqualified")
            (root / "cold").write_bytes(b"{}")
            with self.assertRaises(ValueError):
                build(root / "output", root / "compiler", root / "cold")
            self.assertFalse((root / "output").exists())

    def test_independent_core_vm_argument_and_error_formatter(self):
        script = r'''
import ctypes,io,json,os,resource
from contextlib import redirect_stdout,redirect_stderr
from unittest.mock import patch
resource.setrlimit(resource.RLIMIT_AS,(384<<20,384<<20))
from hepta import cli
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_cli_native import NativeCli,SOURCES,_print_parser_message
class VM:
 def __init__(self,path):self.program=assemble_program(path.read_bytes());self.calls=0
 def _entry(self,s,ns,o,no,w,nw):
  owners=[_Owner(-1,bytearray(ctypes.string_at(s,ns))),_Owner(-2,bytearray(ctypes.string_at(o,no))),_Owner(-3,bytearray(ctypes.string_at(w,nw)))]
  machine=_Machine(self.program,25000000,64<<20,None,128)
  result=machine.invoke(self.program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
  ctypes.memmove(o,bytes(owners[1].data),no);ctypes.memmove(w,bytes(owners[2].data),nw)
  self.calls+=1
  return result
control,formatter=VM(SOURCES['control']),VM(SOURCES['format'])
owner=NativeCli(control,formatter)
output=io.StringIO();errors=io.StringIO()
with patch.dict(os.environ,{'COLUMNS':'80','LINES':'24','PYTHON_COLORS':'0','TERM':'dumb'},clear=True),redirect_stdout(output),redirect_stderr(errors):
 session=owner.prepare(['build','source.hia'],cli)
 assert session.kind==3 and session.exit_code==2
 first,second=owner.format_result(session)
 _print_parser_message(first,errors);_print_parser_message(second,errors)
 assert 'the following arguments are required: --output/-o' in errors.getvalue()
 assert owner.driver_error('snow 雪 "quoted"\n')==json.dumps({'ok':False,'status':'error','diagnostics':[{'code':'E_DRIVER','message':'snow 雪 "quoted"\n','phase':'driver'}]},ensure_ascii=False,indent=2,sort_keys=True)
print(json.dumps({'control_calls':control.calls,'formatter_calls':formatter.calls,'native_image_loaded':False}))
'''
        process = subprocess.run([sys.executable, "-B", "-c", script], cwd=ROOT,
                                 capture_output=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["control_calls"], 1)
        self.assertEqual(report["formatter_calls"], 3)
        self.assertIs(report["native_image_loaded"], False)


class CliNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise AssertionError("development cannot override current cold selection")
        if not cold and not development:
            raise unittest.SkipTest("requires explicit CLI cold report or development bundle")
        cls.temporary = None
        evidence = os.environ.get(FIXTURE_EVIDENCE)
        if evidence:
            base = Path(evidence).absolute()
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-cli-native-tests-")
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        if cold:
            from tools.build_hia_cli_native import build
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer["nested_report"]).read_bytes())
            cls.compiler = Path(nested["generations"][-1]["produced_image"])
            cls.manifest = build(cls.folder / "qualified", cls.compiler, Path(cold))
            cls.scope = "MATCHING_SOURCE_COLD_BUILD"
        else:
            cls.manifest = Path(development).resolve(strict=True)
            request = json.loads((cls.manifest.parent / "control/cli-control.request.json").read_bytes())
            cls.compiler = Path(request["image"])
            expected = json.loads((cls.manifest.parent / "control/manifest.json").read_bytes())["compiler_sha256"]
            if sha256(cls.compiler.read_bytes()).hexdigest() != expected:
                raise AssertionError("development compiler receipt changed")
            cls.scope = "EXPLICIT_DEVELOPMENT_ONLY"
        cls.owner = installed_cli(str(cls.manifest))
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        (cls.folder / "observations.json").write_text(json.dumps({
            "schema": "hia.cli.native-test-observations.v1", "scope": cls.scope,
            "manifest": str(cls.manifest), "observations": cls.observations,
            "whole_native_delivery_qualified": False,
        }, indent=2, sort_keys=True) + "\n")
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def assert_parse_same(self, argv, variables=None):
        with patch.dict(os.environ, environment(variables), clear=True):
            expected = parser_outcome(self.owner, argv, selected=False)
            actual = parser_outcome(self.owner, argv, selected=True)
        self.observations.append({"test": self.id(), "argv": argv, "environment": variables,
                                  "expected": expected, "actual": actual})
        self.assertEqual(actual, expected, (argv, variables))
        return actual

    def test_selfhost_options_errors_and_complete_argv_preserve_current_entry(self):
        missing = str(self.folder / 'not-a-source.core.hepta')
        prefix = ['build', missing, '-o', str(self.folder / 'not-published.o')]
        tails = [
            ['--backend', 'selfhost'],
            ['--backend', 'selfhost', '--selfhost-manifest', 'compiler.json'],
            ['--backend', 'selfhost', '--selfhost-manifest-sha256', 'a' * 64],
            ['--backend', 'selfhost', '--selfhost-manifest', '', '--selfhost-manifest-sha256', 'a' * 64],
            ['--selfhost-manifest', 'compiler.json'],
            ['--selfhost-manifest', ''],
            ['--backend', 'native', '--selfhost-manifest-sha256', 'a' * 64],
            ['--selfhost', 'ambiguous'],
            ['--backend', 'selfhost', '--selfhost-manifest', 'compiler.json',
             '--selfhost-manifest-sha256', 'a' * 64],
            ['--backend=selfhost', '--selfhost-manifest=compiler.json',
             '--selfhost-manifest-sha256=' + 'b' * 64],
        ]
        for tail in tails:
            argv = prefix + tail
            with self.subTest(argv=argv), patch.dict(os.environ, environment(), clear=True):
                expected = entry_outcome(argv)
                actual = entry_outcome(argv, self.manifest)
                self.assertEqual(actual, expected)
                self.observations.append({'test': self.id(), 'argv': argv,
                                          'expected': expected, 'actual': actual})
        self.assertFalse((self.folder / 'not-published.o').exists())

    def test_hyphenated_build_help_matches_reference_at_every_ordinary_width(self):
        for columns in range(1, 161):
            with self.subTest(columns=columns):
                self.assert_parse_same(['build', '--help'], {'COLUMNS': str(columns)})

    def test_hia_continuation_routes_selfhost_without_entering_direct_emitter(self):
        from tests.test_hia_agent_entry import fixture
        import hepta.hia_program_selfhost as compiler
        import hepta.hia_program_native as direct
        source = self.folder / 'selected-selfhost.core.hepta'
        source.write_text(json.dumps(fixture()))
        argv = ['build', str(source), '-o', str(self.folder / 'selfhost.o'),
                '--backend', 'selfhost', '--selfhost-manifest', 'compiler.json',
                '--selfhost-manifest-sha256', 'c' * 64]
        calls = []
        def observe(program, output, **options):
            calls.append((program.sha256, output, options))
            return {'ok': True, 'scope': 'foreign-effect-transport-control'}
        with patch.dict(os.environ, environment(), clear=True), \
                patch.object(compiler, 'build_program_selfhost', side_effect=observe), \
                patch.object(direct, 'build_program_machine', side_effect=AssertionError('direct emitter fallback')):
            expected = entry_outcome(argv)
            actual = entry_outcome(argv, self.manifest)
        self.assertEqual(actual, expected)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(calls[1][2], {'manifest': 'compiler.json',
                                     'manifest_sha256': 'c' * 64,
                                     'kind': 'object', 'target': 'x86_64-unknown-linux-gnu'})
        self.observations.append({'test': self.id(), 'calls': calls,
                                  'native_build_semantics_qualified_by_this_control': False})

    def test_argparse_order_abbreviation_clusters_repetition_and_sentinel(self):
        cases = [
            [], ["--version"], ["--vers"], ["--version=x"], ["--help=x"], ["-hv"], ["-hh"],
            ["--"], ["--", "verify", "x"], ["-"], [""], ["bogus"],
            ["verify", "x"], ["verify", "--", "-leading"], ["verify", "--", "--"],
            ["verify", "x", "extra"], ["verify", "x", "--", "extra"],
            ["verify", "-1"], ["verify", "-1.5"], ["verify", "-.5"],
            ["verify", "-١"], ["verify", "-1\n"], ["verify", "-1."], ["verify", "-1e2"],
            ["verify", "-1x"], ["verify", "-.1x"], ["verify", "-.1."],
            ["verify", "-.1\n\n"], ["verify", "-1\n\n"], ["verify", "-1\x00"],
            ["verify", "-١e2"], ["verify", "-.١x"], ["verify", "-\U00010d40x"],
            ["verify", "-"], ["verify", "-."], ["verify", "-.x"], ["verify", "-²x"],
            ["verify", "-..1"], ["verify", "--1"], ["verify", "-1\ud800"],
            ["build", "x", "-o", "-1."], ["build", "x", "-o", "-1e2"],
            ["build", "x", "-o", "-.١tail"], ["build", "x", "-o", "-.x"],
            ["--output", "bad", "capabilities"], ["capabilities", "--version"],
            ["catalog", "--schema"], ["catalog", "--schema", "bad"],
            ["catalog", "--sch=hepta.hia.program.v2"],
            ["catalog", "--schema", "hepta.hia.program.v1", "--schema", "hepta.hia.program.v8"],
            ["build", "x"], ["build", "--help", "--backend", "bad"],
            ["build", "--backend", "bad", "--help"], ["build", "x", "-o"],
            ["build", "x", "-oone", "--output=two"], ["build", "x", "-o=-leading"],
            ["build", "x", "-o", "--"], ["build", "x", "-o", "-1"],
            ["build", "x", "--back", "native", "--k", "object", "--t", "x86_64-unknown-linux-gnu", "-o", "o"],
            ["edit-query", "x", "--f", "a"], ["edit-query", "--help", "--f", "a"],
            ["edit-query", "x", "--function", "f", "--block", "b", "--value", "v", "--fields", ""],
            ["edit-query", "x", "--function=f", "--block=b", "--value=v", "--fields=a,,b,"],
            ["edit-apply", "x", "--query=q", "--response=r", "--output=o"],
            ["edit-batch-apply", "x", "--q", "q", "--r", "r"],
            ["impact", "x", "--request", "-not-a-value"], ["patch", "x", "--request=r", "--output", ""],
        ]
        cases += [[action, option] for action in cli.HIA_AGENT_ACTIONS for option in ("-h", "--help", "--he")]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assert_parse_same(argv)

    def test_help_wrapping_columns_and_exact_unicode_repr(self):
        widths = ("1", "2", "3", "18", "20", "39", "40", "80", "120",
                  "0", "-1", "bad", "１２", "  +8_0  ", "1__0", "9" * 5000)
        for width in widths:
            for argv in (["--help"], ["build", "--help"], ["edit-query", "--help"],
                         ["build"], ["--version"]):
                with self.subTest(columns=width[:40], argv=argv):
                    self.assert_parse_same(argv, {"COLUMNS": width})
        for value in ("snow 雪", "emoji 😀", "'", '"', "'\"", "a\nb\tc", "\x00", "\x1f",
                      "\x7f", "\u00a0", "\u2028", "\ud800", "\udfff", "\U0001f979"):
            for argv in ([value], ["catalog", "--schema", value]):
                with self.subTest(argv=argv):
                    self.assert_parse_same(argv)

    def test_python_color_environment_precedence_and_colored_wrapping(self):
        cases = [
            ("python-force-before-no-color", {"PYTHON_COLORS": "1", "NO_COLOR": "1", "TERM": "dumb"}, True),
            ("python-disable-before-force", {"PYTHON_COLORS": "0", "FORCE_COLOR": "1", "TERM": "xterm"}, False),
            ("no-color", {"PYTHON_COLORS": "", "NO_COLOR": "1", "FORCE_COLOR": "1", "TERM": "xterm"}, False),
            ("force-color", {"PYTHON_COLORS": "", "NO_COLOR": "", "FORCE_COLOR": "1", "TERM": "dumb"}, True),
            ("dumb-terminal", {"PYTHON_COLORS": "other", "NO_COLOR": "", "FORCE_COLOR": "", "TERM": "dumb"}, False),
            ("observed-nonterminal", {"PYTHON_COLORS": "other", "NO_COLOR": "", "FORCE_COLOR": "", "TERM": "xterm"}, False),
        ]
        for name, values, colored in cases:
            for argv in (["--help"], ["build", "--help"], ["--version"], ["catalog", "--schema", "bad"]):
                with self.subTest(color_case=name, argv=argv):
                    outcome = self.assert_parse_same(argv, {**values, "COLUMNS": "39"})
                    if argv == ["--help"]:
                        self.assertEqual("\x1b[" in outcome[1],
                                         colored and sys.version_info[:2] == (3, 14))

    def test_error_json_is_native_and_keeps_active_exception_context(self):
        messages = ["ordinary", "snow 雪 😀", '"quoted"\\slash\n\t', "\ud800", "\x00\x1f"]
        from hepta import hia_program_tools
        for message in messages:
            observations = []
            class Failure(ValueError):
                def __str__(self):
                    observations.append(sys.exception() is self)
                    return message
            expected_error, actual_error = Failure(), Failure()
            with patch.dict(os.environ, environment(), clear=True):
                with patch.object(hia_program_tools, "read_bounded", side_effect=expected_error):
                    expected = entry_outcome(["verify", "unused"])
                with (patch.object(hia_program_tools, "read_bounded", side_effect=actual_error),
                      patch.object(cli, "output_json", side_effect=AssertionError("retained E_DRIVER JSON entered"))):
                    actual = entry_outcome(["verify", "unused"], self.manifest)
            self.assertEqual(actual, expected)
            self.assertEqual(observations, [True, True])
            self.assertEqual(actual[0], ("return", 2))

    def test_parser_stream_write_failures_and_missing_stdout_match(self):
        class Stream:
            def __init__(self, error=None):
                self.events = []
                self.error = error
            def write(self, text):
                self.events.append(text)
                if self.error is not None:
                    raise self.error
                return len(text)
        def run(argv, selected, missing, error_type):
            stream = Stream(None if error_type is None else error_type("write stopped"))
            errors = Stream()
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, environment(), clear=True))
                stack.enter_context(patch.object(sys, "stdout", None if missing else stream))
                stack.enter_context(patch.object(sys, "stderr", errors))
                if selected:
                    stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest)}))
                    stack.enter_context(patch.object(argparse, "ArgumentParser", side_effect=AssertionError("retained parser")))
                try:
                    result = ("return", cli.hia_main(argv))
                except SystemExit as error:
                    result = ("exit", error.code)
                except BaseException as error:
                    result = ("raise", type(error).__name__, str(error))
            return result, stream.events, errors.events
        for missing, error_type in ((False, None), (True, None), (False, OSError),
                                   (False, AttributeError), (False, ValueError),
                                   (False, RuntimeError), (False, KeyboardInterrupt)):
            for argv in (["--help"], ["--version"]):
                with self.subTest(missing=missing, error_type=error_type, argv=argv):
                    self.assertEqual(run(argv, True, missing, error_type), run(argv, False, missing, error_type))

    def _prepare_case(self, folder):
        from tests.test_hia_agent_entry import fixture
        from hepta.hia_program import verify_program
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_edit_query import prepare_edit
        from hepta.hia_edit_batch import prepare_batch
        from hepta.hia_program_tools import PATCH_SCHEMA
        folder.mkdir(mode=0o700)
        source = fixture()
        raw = json.dumps(source).encode()
        (folder / "program.core.hepta").write_bytes(raw)
        (folder / "雪.hia").write_bytes(raw)
        (folder / "program.hepta").write_text(render_assembly(source))
        program = verify_program(raw)
        operation = source["functions"][0]["blocks"][0]["ops"][1]
        operation = {**operation, "op": "int.sub.wrap"}
        request = {"schema": PATCH_SCHEMA, "expected_sha256": program.sha256,
                   "edits": [{"action": "replace_operation", "function": "calculate",
                              "block": "entry", "index": 1, "operation": operation}]}
        selections = [{"function": "calculate", "block": "entry", "output": "y", "fields": ["op"]}]
        query = prepare_edit(program, **selections[0])
        batch = prepare_batch(program, selections)
        for name, value in (
            ("patch.json", request), ("selections.json", selections), ("query.json", query),
            ("batch.json", batch), ("response.json", {"op": "int.sub.wrap"}),
            ("batch-response.json", {"edits": [{"site": 0, "changes": {"op": "int.sub.wrap"}}]}),
        ):
            (folder / name).write_text(json.dumps(value))
        return program

    @staticmethod
    def _files(folder):
        result = {}
        for path in sorted(folder.rglob("*")):
            if path.is_dir():
                result[path.relative_to(folder).as_posix() + "/"] = None
            else:
                result[path.relative_to(folder).as_posix()] = (stat.S_IMODE(path.stat().st_mode), path.read_bytes())
        return result

    def test_all_fifteen_real_actions_and_publication_branches(self):
        cases = [
            ["capabilities"], ["catalog"], ["import-assembly", "program.hepta"],
            ["render-assembly", "program.core.hepta"], ["check-assembly", "program.hepta"],
            ["verify", "雪.hia"], ["inspect", "program.core.hepta"], ["normalize", "program.core.hepta"],
            ["build", "program.core.hepta", "-o", "target.o"],
            ["patch", "program.core.hepta", "--request", "patch.json"],
            ["impact", "program.core.hepta", "--request", "patch.json"],
            ["edit-query", "program.core.hepta", "--function", "calculate", "--block", "entry", "--value", "y", "--fields", "op"],
            ["edit-apply", "program.core.hepta", "--query", "query.json", "--response", "response.json"],
            ["edit-batch-query", "program.core.hepta", "--selections", "selections.json"],
            ["edit-batch-apply", "program.core.hepta", "--query", "batch.json", "--response", "batch-response.json"],
        ]
        output_actions = {"import-assembly", "render-assembly", "normalize", "patch",
                          "edit-query", "edit-apply", "edit-batch-query", "edit-batch-apply"}
        cases += [argv + ["-o", "published"] for argv in cases if argv[0] in output_actions]
        method = self.folder / "all-fifteen-actions"
        method.mkdir(mode=0o700)
        entered = []
        real_effect = CliSession._effect
        def effect(session, operation, *args):
            entered.append(operation)
            return real_effect(session, operation, *args)
        original_directory = Path.cwd()
        rows = []
        try:
            for index, argv in enumerate(cases):
                with self.subTest(action=argv[0], argv=argv):
                    pair = []
                    for selected in (False, True):
                        folder = method / "current"
                        self._prepare_case(folder)
                        os.chdir(folder)
                        with (patch.dict(os.environ, environment({"PATH": ""}), clear=True),
                              patch.object(CliSession, "_effect", effect)):
                            outcome = entry_outcome(argv, self.manifest if selected else None)
                        os.chdir(original_directory)
                        files = self._files(folder)
                        destination = method / ("%02d-%s" % (index, "native" if selected else "reference"))
                        folder.rename(destination)
                        pair.append((outcome, files))
                    rows.append({"argv": argv, "expected": pair[0][0], "actual": pair[1][0],
                                 "file_names": sorted(pair[1][1]), "equal": pair[0] == pair[1]})
                    self.assertEqual(pair[1], pair[0])
                    self.assertEqual(pair[1][0][0], ("return", 0))
            self.assertEqual({argv[0] for argv in cases}, set(cli.HIA_AGENT_ACTIONS))
            self.assertTrue((set(range(1, 32)) | set(range(35, 42))) <= set(entered))
            self.observations.append({"test": self.id(), "all_actions": list(cli.HIA_AGENT_ACTIONS),
                                      "cases": rows, "actual_native_effects": entered})
        finally:
            os.chdir(original_directory)
            (method / "comparisons.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")

    def test_output_precedes_result_truth_and_query_read_errors(self):
        from hepta import hia_agent_assembly, hia_program, hia_program_tools, hia_program_native
        for action in ("check-assembly", "build"):
            def run(selected):
                events = []
                result = {"accepted": True} if action == "check-assembly" else {"ok": True}
                def output(value):
                    events.append(("output", dict(value)))
                    if action == "check-assembly":
                        value["accepted"] = False
                    else:
                        value["ok"] = 1
                with (patch.dict(os.environ, environment(), clear=True),
                      patch.object(hia_program_tools, "read_bounded", return_value=b"opaque"),
                      patch.object(hia_program, "verify_program", return_value=object()),
                      patch.object(hia_agent_assembly, "diagnose_assembly", return_value=result),
                      patch.object(hia_program_native, "build_program_machine", return_value=result),
                      patch.object(cli, "output_json", output)):
                    argv = [action, "input"] + (["-o", "output"] if action == "build" else [])
                    outcome = entry_outcome(argv, self.manifest if selected else None)
                return outcome, events
            expected, actual = run(False), run(True)
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0][0], ("return", 1))

        root = self.folder / "query-order"
        self._prepare_case(root)
        (root / "broken.json").write_text("{")
        real_read = hia_program_tools.read_bounded
        for action in ("edit-apply", "edit-batch-apply"):
            def run(selected):
                reads = []
                def read(path, *, limit=8 << 20):
                    reads.append((Path(path).name, limit))
                    return real_read(path, limit=limit)
                with (patch.dict(os.environ, environment(), clear=True),
                      patch.object(hia_program_tools, "read_bounded", read)):
                    outcome = entry_outcome([action, str(root / "program.core.hepta"), "--query",
                                             str(root / "broken.json"), "--response",
                                             str(root / "missing.json")], self.manifest if selected else None)
                return outcome, reads
            expected, actual = run(False), run(True)
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0][0], ("return", 2))
            self.assertEqual(len(actual[1]), 2 if action == "edit-apply" else 3)
            if action == "edit-batch-apply":
                self.assertEqual([limit for _, limit in actual[1]], [8 << 20, 1 << 20, 64 << 10])

    def test_existing_read_ceilings_and_unicode_error_publication(self):
        root = self.folder / "bounded-inputs"
        self._prepare_case(root)
        (root / "oversized").write_bytes(b" " * ((8 << 20) + 1))
        (root / "invalid-utf8").write_bytes(b"\xff")
        (root / "input-link").symlink_to(root / "program.core.hepta")
        for argv in (
            ["verify", str(root / "oversized")],
            ["import-assembly", str(root / "invalid-utf8")],
            ["verify", str(root / "input-link")],
            ["verify", str(root / "missing")],
        ):
            with self.subTest(argv=argv), patch.dict(os.environ, environment(), clear=True):
                expected, actual = entry_outcome(argv), entry_outcome(argv, self.manifest)
                self.assertEqual(actual, expected)
                self.assertEqual(actual[0], ("return", 2))
        for action, query, response, size in (
            ("edit-apply", "query.json", "too-big-single", (16 << 10) + 1),
            ("edit-batch-apply", "batch.json", "too-big-batch", (64 << 10) + 1),
        ):
            (root / response).write_bytes(b" " * size)
            argv = [action, str(root / "program.core.hepta"), "--query", str(root / query),
                    "--response", str(root / response)]
            with patch.dict(os.environ, environment(), clear=True):
                self.assertEqual(entry_outcome(argv, self.manifest), entry_outcome(argv))

    def test_native_ack_refusal_and_no_replay_after_consumed_effect(self):
        with patch.dict(os.environ, environment(), clear=True):
            session = self.owner.prepare(["capabilities"], cli)
        calls = []
        with patch.object(cli, "agent_capabilities", side_effect=lambda: calls.append("called") or {}):
            self.assertEqual(session.step(), 1)
            session.observe()
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(calls, ["called"])
            with self.assertRaises(RuntimeError):
                session.step()

        for defect in ("short", "magic", "sequence", "reserved", "second-argv"):
            with self.subTest(defect=defect), patch.dict(os.environ, environment(), clear=True):
                session = self.owner.prepare(["capabilities"], cli)
                self.assertEqual(session.step(), 1)
                operation, sequence = session.command[:2]
                good = session._packet(sequence, operation, 0, session.register({}), 0, 0)
                bad = bytearray(good)
                if defect == "short":
                    bad = bad[:16]
                elif defect == "magic":
                    struct.pack_into("<Q", bad, 0, 0)
                elif defect == "sequence":
                    struct.pack_into("<Q", bad, 16, sequence + 1)
                elif defect == "reserved":
                    struct.pack_into("<Q", bad, 72, 1)
                else:
                    bad = session.raw
                def native(raw):
                    source = ctypes.create_string_buffer(bytes(raw), len(raw))
                    return self.owner.control._entry(source, len(raw), session.output, len(session.output),
                                                     session.workspace, len(session.workspace))
                self.assertEqual(native(bad), 199)
                self.assertEqual(_q(session.workspace, 2080), 1)
                self.assertEqual(native(good), 199)

    def test_external_baseexception_after_native_return_closes_permission(self):
        class ForeignStop(BaseException):
            pass
        for before in (True, False):
            with patch.dict(os.environ, environment(), clear=True):
                session = self.owner.prepare(["capabilities"], cli)
            original = self.owner.control._entry
            stop = ForeignStop("native boundary stop")
            returns = []
            def interrupted(*args):
                if before:
                    raise stop
                result = original(*args)
                returns.append(result)
                raise stop
            with patch.object(self.owner.control, "_entry", interrupted):
                with self.assertRaises(ForeignStop) as observed:
                    session.step()
                self.assertIs(observed.exception, stop)
            self.assertEqual(returns, [] if before else [1])
            self.assertTrue(session.finished)
            self.assertFalse(session.pending)
            with patch.object(cli, "agent_capabilities", side_effect=AssertionError("stale effect replayed")):
                with self.assertRaises(RuntimeError):
                    session.observe()
                with self.assertRaises(RuntimeError):
                    session.step()

    def test_error_str_baseexception_preserves_object_context_and_closes(self):
        from hepta import hia_program_tools
        class ForeignStop(BaseException):
            pass
        stop = ForeignStop("str callback failed")
        events = []
        class Domain(ValueError):
            def __str__(self):
                events.append(sys.exception() is self)
                raise stop
        error = Domain()
        with patch.dict(os.environ, environment(), clear=True):
            session = self.owner.prepare(["verify", "unused"], cli)
        with patch.object(hia_program_tools, "read_bounded", side_effect=error):
            with self.assertRaises(ForeignStop) as observed:
                session.run()
        self.assertIs(observed.exception, stop)
        self.assertIs(stop.__context__, error)
        self.assertEqual(events, [True])
        self.assertTrue(session.finished)
        self.assertFalse(session.pending)
        with self.assertRaises(RuntimeError):
            session.observe()

    def test_source_bundle_binding_and_selected_fail_closed(self):
        with (patch.dict(os.environ, environment({SELECTOR: str(self.folder / "missing")}), clear=True),
              patch.object(cli, "_reference_hia_main", side_effect=AssertionError("fallback entered"))):
            with self.assertRaises(FileNotFoundError):
                cli.hia_main(["--help"])
        bundle = json.loads(self.manifest.read_bytes())
        copy = self.folder / "drift-bundle"
        shutil.copytree(self.manifest.parent, copy)
        candidate = copy / self.manifest.name
        control_manifest = copy / bundle["control_manifest"]
        metadata = json.loads(control_manifest.read_bytes())
        metadata["source_sha256"] = "0" * 64
        control_manifest.write_text(json.dumps(metadata))
        bundle["control_manifest_sha256"] = sha256(control_manifest.read_bytes()).hexdigest()
        candidate.write_text(json.dumps(bundle))
        with self.assertRaisesRegex(ValueError, "source identity"):
            installed_cli(str(candidate))
        from hepta import hia_cli_native
        bad_source = self.folder / "source-drift.hepta"
        bad_source.write_bytes(SOURCES["control"].read_bytes() + b"\n")
        with patch.dict(hia_cli_native.SOURCES, {"control": bad_source}):
            with self.assertRaisesRegex(ValueError, "source identity"):
                installed_cli(str(self.manifest))
        self.assertIsInstance(installed_cli(str(self.manifest)), NativeCli)

    def test_unchanged_original_agent_entry_suite_with_native_selected(self):
        output = self.folder / "original-agent-entry"
        output.mkdir(mode=0o700)
        script = r'''
import json,os,subprocess,sys,unittest
from pathlib import Path
from tests import test_hia_agent_entry as original
manifest,report_path=sys.argv[1:3]
actual_run=subprocess.run;injected=[]
guard="import argparse\nfrom hepta import cli\ndef reject(*args,**kwargs):raise AssertionError('retained ordinary CLI/parser entered')\ncli._reference_hia_main=reject\nargparse.ArgumentParser=reject\n"
def run(argv,*args,**kwargs):
 if type(argv) is list and len(argv)>3 and argv[:3]==[sys.executable,'-B','-c'] and argv[3]==original.CHILD:
  argv=list(argv);argv[3]=guard+argv[3]
  env=dict(kwargs['env']);env['HEPTA_HIA_CLI_MANIFEST']=manifest;kwargs['env']=env
  injected.append(json.loads(argv[4]))
 return actual_run(argv,*args,**kwargs)
subprocess.run=run
suite=unittest.defaultTestLoader.loadTestsFromModule(original)
def flatten(value):
 for member in value:
  if isinstance(member,unittest.TestSuite):yield from flatten(member)
  else:yield member
loaded=[case.id() for case in flatten(suite)];executed=[]
class Result(unittest.TextTestResult):
 def startTest(self,test):executed.append(test.id());super().startTest(test)
result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
anomalies={'failures':[(t.id(),s) for t,s in result.failures],'errors':[(t.id(),s) for t,s in result.errors],'skipped':[(t.id(),s) for t,s in result.skipped],'expected_failures':[(t.id(),s) for t,s in result.expectedFailures],'unexpected_successes':[t.id() for t in result.unexpectedSuccesses]}
passed=bool(loaded) and len(set(loaded))==len(loaded) and loaded==executed and result.testsRun==len(loaded) and bool(injected) and not any(anomalies.values())
report={'schema':'hia.cli.original-agent-entry-native-selection.v1','status':'PASS' if passed else 'FAIL','loaded_test_ids':loaded,'executed_test_ids':executed,'tests_run':result.testsRun,'selected_child_argv':injected,**anomalies}
Path(report_path).write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
raise SystemExit(0 if passed else 1)
'''
        (output / "controller.py").write_text(script)
        process = subprocess.run([sys.executable, "-B", str(output / "controller.py"),
                                  str(self.manifest), str(output / "report.json")], cwd=ROOT,
                                 env=environment({"PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}),
                                 capture_output=True, timeout=180)
        (output / "stdout.log").write_bytes(process.stdout)
        (output / "stderr.log").write_bytes(process.stderr)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads((output / "report.json").read_bytes())
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["loaded_test_ids"])
        self.assertEqual(report["loaded_test_ids"], report["executed_test_ids"])
        self.assertEqual(report["tests_run"], len(report["loaded_test_ids"]))
        self.assertFalse(any(report[key] for key in
                             ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")))


    def test_actual_installed_wheel_without_retained_cli_or_checkout_resources(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        from tests.test_hia_agent_entry import fixture
        case = self.folder / "installed-control"
        case.mkdir(mode=0o700)
        source, wheels, installed = case / "source", case / "wheels", case / "installed"
        source.mkdir(mode=0o700)
        resources = ((tuple("docs/" + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES
                     + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES)
        required = {
            "control": "examples/hia_bootstrap/cli_control.hepta",
            "format": "examples/hia_bootstrap/cli_format.hepta",
        }
        for name in required.values():
            self.assertIn(name, NATIVE_SOURCE_FILES)
        shutil.copytree(ROOT / "hepta", source / "hepta", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in (*resources, "setup.py", "pyproject.toml", "MANIFEST.in"):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        bundle = case / "bundle"
        shutil.copytree(self.manifest.parent, bundle)
        manifest = bundle / self.manifest.name
        inputs = case / "input.hia"
        inputs.write_text(json.dumps(fixture()))
        packaging_python = os.environ.get("HEPTA_HIA_TEST_PACKAGING_PYTHON", sys.executable)
        records = []
        source_hashes = {name: sha256(path.read_bytes()).hexdigest() for name, path in SOURCES.items()}
        report = {
            "schema": "hepta.hia.cli-installed-control.v1", "status": "HOLD", "scope": self.scope,
            "whole_native_delivery_qualified": False, "source_sha256_before": source_hashes,
            "packaging_uses_declared_resources_only": True, "processes": records,
            "original_manifest": str(self.manifest), "manifest": str(manifest),
        }

        def command(arguments, label, *, env=None):
            result = subprocess.run(arguments, cwd=case, env=env, capture_output=True, timeout=120)
            (case / (label + ".stdout")).write_bytes(result.stdout)
            (case / (label + ".stderr")).write_bytes(result.stderr)
            records.append({"label": label, "argv": arguments, "returncode": result.returncode,
                            "stdout_sha256": sha256(result.stdout).hexdigest(),
                            "stderr_sha256": sha256(result.stderr).hexdigest()})
            (case / "processes.json").write_text(json.dumps(records, sort_keys=True, indent=2) + "\n")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result

        child = r'''
import argparse,importlib.abc,importlib.metadata,io,json,os,sys
from contextlib import redirect_stdout,redirect_stderr
from hashlib import sha256
from pathlib import Path
installed=Path(sys.argv[1]).resolve(strict=True)
manifest=Path(sys.argv[2]).resolve(strict=True)
input_path=Path(sys.argv[3]).resolve(strict=True)
sys.path.insert(0,str(installed))
forbidden_entries={"tools":[],"retained_cli":[],"retained_parser":[]}
class NoTools(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=="tools" or fullname.startswith("tools."):
   forbidden_entries["tools"].append(fullname)
   raise AssertionError("installed native CLI imported authoring tools")
sys.meta_path.insert(0,NoTools())
from hepta import cli
from hepta.hia_cli_native import SOURCES,SELECTOR,installed_cli
def forbidden_cli(*args,**kwargs):
 forbidden_entries["retained_cli"].append(True)
 raise AssertionError("retained CLI body entered")
def forbidden_parser(*args,**kwargs):
 forbidden_entries["retained_parser"].append(True)
 raise AssertionError("retained argparse entered")
cli._reference_hia_main=forbidden_cli
argparse.ArgumentParser=forbidden_parser
entries=[e for e in importlib.metadata.distribution("hia-core").entry_points
         if e.group=="console_scripts" and e.name=="hia"]
assert len(entries)==1 and entries[0].value=="hepta.cli:hia_main"
entry=entries[0].load()
assert entry is cli.hia_main
os.environ[SELECTOR]=str(manifest)
source_bytes={}
for name,path in SOURCES.items():
 assert path.resolve(strict=True)==installed/"hepta/_data/examples/hia_bootstrap"/("cli_"+name+".hepta")
 source_bytes[name]=path.read_bytes()
owner=installed_cli(str(manifest))
native_returns={"control":[],"format":[]}
for name,image in (("control",owner.control),("format",owner.formatter)):
 original=image._entry
 def record(*args,_name=name,_original=original):
  result=_original(*args)
  native_returns[_name].append(int(result))
  return result
 image._entry=record
calls=[]
def call(argv):
 output,errors=io.StringIO(),io.StringIO()
 with redirect_stdout(output),redirect_stderr(errors):
  try:kind,code="return",entry(argv)
  except SystemExit as error:kind,code="exit",error.code
 value={"argv":argv,"kind":kind,"code":code,"stdout":output.getvalue(),"stderr":errors.getvalue()}
 calls.append(value)
 return value
version=call(["--version"])
assert version["kind"]=="exit" and version["code"]==0 and version["stdout"]=="hia "+cli.__version__+"\n" and version["stderr"]==""
help_result=call(["--help"])
assert help_result["code"]==0 and help_result["stderr"]=="" and all(name in help_result["stdout"] for name in cli.HIA_AGENT_ACTIONS)
verified=call(["verify",str(input_path)])
assert verified["kind"]=="return" and verified["code"]==0 and json.loads(verified["stdout"])["status"]=="standalone_core_checked"
capabilities=call(["capabilities"])
assert capabilities["kind"]=="return" and capabilities["code"]==0 and json.loads(capabilities["stdout"])["schema"]=="hepta.hia.agent-entry.v1"
bad=call(["verify"])
assert bad["kind"]=="exit" and bad["code"]==2 and "required: input" in bad["stderr"] and bad["stdout"]==""
missing=call(["verify",str(input_path.with_suffix(".missing"))])
assert missing["kind"]=="return" and missing["code"]==2 and json.loads(missing["stdout"])["diagnostics"][0]["code"]=="E_DRIVER"
refusals=[]
def refuse(label,expected):
 before={name:len(values) for name,values in native_returns.items()}
 output,errors=io.StringIO(),io.StringIO()
 with redirect_stdout(output),redirect_stderr(errors):
  try:entry(["--version"])
  except expected as error:refusals.append({"case":label,"type":type(error).__name__,"message":str(error)})
  else:raise AssertionError("selected invalid installation or bundle was accepted: "+label)
 assert output.getvalue()==errors.getvalue()==""
 assert before=={name:len(values) for name,values in native_returns.items()}
for name,path in SOURCES.items():
 original=source_bytes[name]
 path.write_bytes(original+b"\n")
 try:refuse("changed-installed-"+name,ValueError)
 finally:path.write_bytes(original)
 held=path.with_suffix(path.suffix+".held")
 path.rename(held)
 try:refuse("missing-installed-"+name,FileNotFoundError)
 finally:held.rename(path)
 restored=call(["--version"])
 assert restored["code"]==0
bundle_original=manifest.read_bytes()
metadata=json.loads(bundle_original)
for label,change in (("bundle-schema",{"schema":"unrecognized"}),
                     ("bundle-child-traversal",{"control_manifest":"../outside.json"}),
                     ("bundle-child-hash",{"control_manifest_sha256":"0"*64})):
 manifest.write_text(json.dumps({**metadata,**change}))
 try:refuse(label,ValueError)
 finally:manifest.write_bytes(bundle_original)
os.environ[SELECTOR]=str(manifest.with_suffix(".missing"))
try:refuse("missing-selected-bundle",FileNotFoundError)
finally:os.environ[SELECTOR]=str(manifest)
os.environ[SELECTOR]=""
try:refuse("empty-selected-bundle",OSError)
finally:os.environ[SELECTOR]=str(manifest)
assert all(path.read_bytes()==source_bytes[name] for name,path in SOURCES.items())
assert manifest.read_bytes()==bundle_original
assert all(native_returns.values()) and not any(forbidden_entries.values())
assert not any(name=="tools" or name.startswith("tools.") for name in sys.modules)
assert sys.flags.isolated and sys.flags.no_site and os.environ["PATH"]==""
print(json.dumps({"schema":"hepta.hia.cli-installed-execution.v1",
 "status":"PASS_INSTALLED_NATIVE_CLI_CONTROL","python":sys.version,
 "installed_source_paths":{name:str(path) for name,path in SOURCES.items()},
 "source_sha256":{name:sha256(raw).hexdigest() for name,raw in source_bytes.items()},
 "bundle_sha256":sha256(bundle_original).hexdigest(),"native_returns":native_returns,
 "console_entry_point":entries[0].value,"isolated_without_site":True,"empty_PATH":True,
 "forbidden_entries":forbidden_entries,"calls":calls,"refusals":refusals,
 "sources_and_bundle_restored":True,"whole_native_delivery_qualified":False},sort_keys=True))
'''
        try:
            command([packaging_python, "-B", "-m", "pip", "wheel", "--no-cache-dir", "--no-deps",
                     "--no-index", "--no-build-isolation", "--wheel-dir", str(wheels), str(source)], "wheel-build")
            wheel, = wheels.glob("*.whl")
            with zipfile.ZipFile(wheel) as archive:
                members = archive.namelist()
                for name, resource in required.items():
                    self.assertEqual(archive.read("hepta/_data/" + resource), SOURCES[name].read_bytes())
                self.assertFalse(any(name.startswith(("tools/", "examples/")) for name in members))
            command([packaging_python, "-B", "-m", "pip", "install", "--no-cache-dir", "--no-deps",
                     "--no-index", "--target", str(installed), str(wheel)], "wheel-install")
            script = case / "installed-control.py"
            script.write_text(child)
            env = environment({"PATH": "", "PYTHONPATH": ""})
            result = command([sys.executable, "-I", "-S", "-B", str(script), str(installed),
                              str(manifest), str(inputs)], "installed-execution", env=env)
            observed = json.loads(result.stdout)
            (case / "installed-execution.json").write_text(json.dumps(observed, sort_keys=True, indent=2) + "\n")
            self.assertEqual(observed["schema"], "hepta.hia.cli-installed-execution.v1")
            self.assertEqual(observed["status"], "PASS_INSTALLED_NATIVE_CLI_CONTROL")
            self.assertEqual(observed["source_sha256"], source_hashes)
            self.assertEqual(len(observed["refusals"]), 9)
            self.assertTrue(observed["isolated_without_site"])
            self.assertTrue(observed["empty_PATH"])
            self.assertTrue(all(observed["native_returns"].values()))
            self.assertFalse(any(observed["forbidden_entries"].values()))
            report.update(status="PASS_INSTALLED_NATIVE_CLI_CONTROL",
                          wheel={"path": str(wheel), "bytes": wheel.stat().st_size,
                                 "sha256": sha256(wheel.read_bytes()).hexdigest()},
                          installed_execution=observed)
            self.observations.append({"test": self.id(), "installed_report": str(case / "report.json"),
                                      "native_returns": observed["native_returns"],
                                      "refusal_cases": [row["case"] for row in observed["refusals"]]})
        except BaseException as error:
            report.update(error_type=type(error).__name__, error=str(error))
            raise
        finally:
            report["source_sha256_after"] = {name: sha256(path.read_bytes()).hexdigest()
                                             for name, path in SOURCES.items()}
            report["original_sources_preserved"] = report["source_sha256_after"] == source_hashes
            if not report["original_sources_preserved"]:
                report["status"] = "HOLD"
            (case / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        self.assertTrue(report["original_sources_preserved"])


def _q(buffer, offset):
    return struct.unpack_from("<Q", buffer, offset)[0]


if __name__ == "__main__":
    unittest.main()
