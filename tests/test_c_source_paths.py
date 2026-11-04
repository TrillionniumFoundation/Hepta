"""Real GCC controls for C #line filename encoding, not a debugger claim."""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze_project


ROOT = Path(__file__).resolve().parents[1]
SOURCE = """fn main()->Unit effects {panic} {
let base:i64=7+5;
let answer:i64=base*3;
assert(answer==36);
}
"""


def generated(path, source=SOURCE):
    program = parse(source, path)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return emit_c(program, checked)


class CSourcePathEmissionTests(unittest.TestCase):
    def test_existing_ascii_quotes_and_backslashes_are_unchanged(self):
        path = '/tmp/quoted-"back\\slash.hepta'
        code = generated(path)
        self.assertIn('#line 1 ' + json.dumps(path), code)
        self.assertIn('#line 4 ' + json.dumps(path), code)

    def test_paths_stay_on_single_ascii_physical_lines(self):
        path = '/tmp/😀-\u2028-\u2029-\x85-\x01-\n\r\t-??/-"\\.hepta'
        code = generated(path)
        directives = [line for line in code.splitlines() if line.startswith('#line ')]
        self.assertGreater(len(directives), 4)
        for line in directives:
            self.assertTrue(line.isascii(), repr(line))
            self.assertNotIn('??', line)
            self.assertNotIn('\\u', line)
            self.assertNotIn('\\x', line)
            self.assertTrue(line.endswith('"'), line)

    def test_nul_and_unencodable_paths_are_positioned_errors(self):
        for path in ('/tmp/nul\x00.hepta', '/tmp/high\ud800.hepta', '/tmp/raw\udcff.hepta'):
            with self.subTest(path=repr(path)):
                with self.assertRaises(HeptaError) as caught:
                    generated(path)
                diagnostic = caught.exception.diagnostic
                self.assertEqual(diagnostic.code, 'E_C_SOURCE_PATH')
                self.assertEqual(diagnostic.phase, 'c_backend')
                self.assertEqual(diagnostic.span.path, path)


@unittest.skipUnless(os.name == 'posix' and shutil.which('gcc') and shutil.which('readelf'),
                     'real POSIX GCC and GNU readelf required')
class CSourcePathNativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-c-paths-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def executable(self, code, *, optimize=False, debug=False):
        result = compile_c(code, cc='gcc', output=self.directory / 'program',
                           optimize=optimize, sanitize=True, debug_info=debug)
        self.assertTrue(result['ok'], result['diagnostics'])
        execution = subprocess.run([result['artifact']], capture_output=True, timeout=10)
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertNotIn(b'runtime error:', execution.stderr)
        return result, execution

    def filename_probe(self, path):
        # Probe the actual directive emitted by CEmitter, not a second encoder.
        directive = next(line for line in generated(path).splitlines() if line.startswith('#line '))
        source = '#include <stdio.h>\n' + directive + '\n' + (
            'int main(void) { const char *p=__FILE__; '
            'return __LINE__ != 1 || fwrite(p, 1, sizeof(__FILE__)-1, stdout) '
            '!= sizeof(__FILE__)-1; }\n')
        cfile = self.directory / 'probe.c'
        cfile.write_text(source, encoding='ascii')
        command = ['gcc', '-std=c11', '-trigraphs', '-Wall', '-Wextra', '-Werror',
                   str(cfile), '-o', str(self.directory / 'probe')]
        built = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        result = subprocess.run([str(self.directory / 'probe')], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, path.encode('utf-8'))

    def debug_bytes(self, result):
        raw = subprocess.run(['readelf', '--debug-dump=rawline', result['artifact']],
                             capture_output=True, timeout=10)
        self.assertEqual(raw.returncode, 0, raw.stderr)
        decoded = subprocess.run(['readelf', '--debug-dump=decodedline', result['artifact']],
                                 capture_output=True, timeout=10)
        self.assertEqual(decoded.returncode, 0, decoded.stderr)
        return raw.stdout, decoded.stdout

    def test_all_nine_trigraphs_round_trip_real_preprocessor(self):
        self.filename_probe('/tmp/??(-??)-??<-??>-??=-??/-??\'-??!-??-.hepta')

    def test_astral_bmp_and_unicode_separators_round_trip(self):
        for name in ('emoji-😀.hepta', '中文-é.hepta', 'separator-\u2028-\u2029-\x85.hepta'):
            with self.subTest(name=name):
                self.filename_probe('/tmp/' + name)

    def test_quotes_backslashes_and_escape_following_digits_round_trip(self):
        self.filename_probe('/tmp/quote"-back\\-\x01789-\x7f012-\\u0041-\\077.hepta')

    def test_astral_real_file_builds_with_ubsan_at_o0_and_o3(self):
        source = self.directory / 'program-😀.hepta'
        source.write_text(SOURCE, encoding='utf-8')
        analysis = analyze_project(source, backend='c', crate_type='bin', cc='gcc')
        self.assertTrue(analysis.report['ok'], analysis.report)
        for optimize in (False, True):
            with self.subTest(optimize=optimize):
                self.executable(analysis.c, optimize=optimize)

    def test_control_and_line_separator_debug_filenames_keep_exact_bytes(self):
        # Do not expand __FILE__ for newline filenames: GCC 14 itself has a
        # macro-expansion defect there. Actual Hepta output uses no such macro.
        names = ('control-\x01-\x7f.hepta', 'lines-\n-\r-\t-\v-\f.hepta',
                 'separator-\u2028-\u2029-\x85.hepta')
        for name in names:
            with self.subTest(name=repr(name)):
                source = self.directory / name
                source.write_text(SOURCE, encoding='utf-8')
                result, _ = self.executable(generated(str(source)), debug=True)
                raw, _ = self.debug_bytes(result)
                self.assertIn(name.encode('utf-8'), raw)

    def test_trigraph_debug_filename_does_not_silently_change(self):
        name = "trigraph-??=-??'-??!.hepta"
        result, _ = self.executable(generated(str(self.directory / name)), debug=True)
        raw, _ = self.debug_bytes(result)
        self.assertIn(name.encode('utf-8'), raw)
        self.assertNotIn(b'trigraph-#-^-|.hepta', raw)

    def test_function_and_statement_paths_remain_distinct(self):
        function_path = '/tmp/function-😀.hepta'
        statement_path = '/tmp/statement-??=-😀.hepta'
        program = parse(SOURCE, function_path)
        program.functions[0].body[1].span = replace(program.functions[0].body[1].span,
                                                   path=statement_path, line=23)
        checked = check(program)
        self.assertTrue(checked.ok)
        result, _ = self.executable(emit_c(program, checked), debug=True)
        raw, decoded = self.debug_bytes(result)
        self.assertIn(Path(function_path).name.encode('utf-8'), raw)
        self.assertIn(Path(statement_path).name.encode('utf-8'), raw)
        self.assertRegex(decoded, rb'statement-\?\?=-.*\.hepta\s+23\s')
        self.assertRegex(decoded, rb'function-.*\.hepta\s+4\s')

    def test_filename_preprocessor_text_remains_inert(self):
        path = '/tmp/evil"\n#error INJECTED\n??/\n#define main changed\n\\.hepta'
        result, _ = self.executable(generated(path), debug=True)
        raw, _ = self.debug_bytes(result)
        # Slash in the hostile text separates debug directories; retain the
        # injected marker bytes without turning them into directives.
        self.assertIn(b'#error INJECTED', raw)

    def test_cli_debug_build_retains_generated_source_and_lines(self):
        source = self.directory / 'cli-😀-??=.hepta'
        source.write_text(SOURCE, encoding='utf-8')
        target = self.directory / 'cli-output'
        process = subprocess.run([sys.executable, '-B', '-m', 'hepta', 'build', str(source),
                                  '--backend', 'c', '--debug', '-o', str(target)],
                                 cwd=ROOT, capture_output=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertTrue(report['ok'])
        info = report['build']['debug_info']
        retained = Path(info['source']).read_text(encoding='ascii')
        self.assertEqual(retained, generated(str(source)))
        raw, decoded = self.debug_bytes(report['build'])
        self.assertIn(source.name.encode('utf-8'), raw)
        for line in (2, 3, 4):
            self.assertRegex(decoded, rb'cli-.*\.hepta\s+' + str(line).encode() + rb'\s')
        run = subprocess.run([str(target)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
