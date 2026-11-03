"""Separate compilation must not export implementation-private C symbols."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse

RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')


def source(entry, value):
    return f'''
    fn identity<T:Copy>(value: T) -> T effects {{}} {{ return value; }}
    fn helper(value: i64) -> i64 effects {{panic}} {{
        if value == 0 {{ return {value}; }}
        return peer(value - 1);
    }}
    fn peer(value: i64) -> i64 effects {{panic}} {{ return helper(value); }}
    pub fn ordinary() -> i64 effects {{panic}} {{ return helper(3); }}
    export "C" fn {entry}() -> i64 effects {{panic}} {{
        return identity::<i64>(ordinary());
    }}
    '''


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('gcc') and shutil.which('nm'),
                     'Linux ELF, GCC and nm required')
class CPrivateLinkageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hepta-c-linkage-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def checked(self, text):
        p = parse(text)
        c = check(p)
        self.assertTrue(c.ok, [x.to_dict() for x in c.diagnostics])
        return p, c

    def run_command(self, command):
        r = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('runtime error:', r.stderr)
        return r.stdout

    def build(self, entry, value, kind, optimize, rust=False):
        p, c = self.checked(source(entry, value))
        path = self.root / (entry + ('.so' if kind == 'cdylib' else '.a' if kind == 'staticlib' else '.o'))
        if rust:
            r = compile_rust(emit_rust(p, c, crate_type=kind), rustc=RUSTC,
                             crate_type=kind, output=path, optimize=optimize)
        else:
            r = compile_c(emit_c(p, c, crate_type=kind), crate_type=kind,
                          output=path, optimize=optimize, sanitize=True)
        self.assertTrue(r['ok'], r['diagnostics'])
        return path

    def static_pair(self, kind):
        for optimize in [False, True]:
            with self.subTest(kind=kind, optimize=optimize):
                paths = [self.build('first', 11, kind, optimize), self.build('second', 22, kind, optimize)]
                for entry, path in zip(['first', 'second'], paths):
                    symbols = self.run_command(['nm', '-g', '--defined-only', path])
                    self.assertIn(entry, symbols)
                    self.assertNotIn('__hepta_cb_', symbols)
                caller = self.root / 'caller.c'
                caller.write_text('#include <stdint.h>\nextern int64_t first(void), second(void);\nint main(void) { return first()!=11 || second()!=22; }\n')
                exe = self.root / 'caller'
                self.run_command(['gcc', '-fsanitize=undefined', '-fno-sanitize-recover=all', caller, *paths, '-o', exe])
                self.run_command([exe])

    def test_separate_objects_with_private_generic_and_recursive_functions(self):
        self.static_pair('obj')

    def test_separate_static_libraries_with_real_c_caller(self):
        self.static_pair('staticlib')

    def shared_pair(self, rust=False):
        for optimize in [False, True]:
            paths = [self.build('first', 11, 'cdylib', optimize, rust), self.build('second', 22, 'cdylib', optimize, rust)]
            for entry, path in zip(['first', 'second'], paths):
                symbols = self.run_command(['nm', '-D', '--defined-only', path])
                self.assertIn(entry, symbols)
                self.assertNotIn('__hepta_cb_', symbols)
            # RTLD_GLOBAL makes accidental private symbol interposition observable.
            caller = self.root / 'dynamic.c'
            caller.write_text('''#include <dlfcn.h>
#include <stdint.h>
int main(int argc, char **argv) {
 if(argc!=3)return 9;
 void *a=dlopen(argv[1],RTLD_NOW|RTLD_GLOBAL);
 void *b=dlopen(argv[2],RTLD_NOW|RTLD_GLOBAL);
 if(!a||!b)return 8;
 int64_t (*first)(void)=(int64_t(*)(void))dlsym(a,"first");
 int64_t (*second)(void)=(int64_t(*)(void))dlsym(b,"second");
 if(!first||!second)return 7;
 int result=first()!=11||second()!=22;
 dlclose(b);dlclose(a);return result;
}
''')
            exe = self.root / 'dynamic'
            self.run_command(['gcc', '-fsanitize=undefined', caller, '-ldl', '-o', exe])
            self.run_command([exe, *paths])

    def test_shared_libraries_do_not_interpose_private_functions(self):
        self.shared_pair()

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), 'actual Rust required')
    def test_actual_rust_shared_library_reference(self):
        self.shared_pair(rust=True)

    def test_extern_and_export_symbols_remain_external(self):
        # A public Hepta declaration is not a C export; explicit export is.
        text = '''extern "C" fn host_value() -> i64 effects {ffi};
        fn internal() -> i64 effects {ffi,unsafe} { unsafe { return host_value(); } }
        export "C" fn exported() -> i64 effects {ffi,unsafe} { unsafe { return internal(); } }
        '''
        p, c = self.checked(text)
        for optimize in [False, True]:
            obj = self.root / 'foreign.o'
            r = compile_c(emit_c(p,c,crate_type='obj'),crate_type='obj',output=obj,optimize=optimize,sanitize=True)
            self.assertTrue(r['ok'],r['diagnostics'])
            symbols=self.run_command(['nm','-g',obj])
            self.assertIn(' U host_value',symbols)
            self.assertIn(' T exported',symbols)
            self.assertNotIn('__hepta_cb_',symbols)
            caller=self.root/'host.c'
            caller.write_text('#include <stdint.h>\nint64_t host_value(void){return 73;}\nextern int64_t exported(void);\nint main(void){return exported()!=73;}\n')
            exe=self.root/'host'
            self.run_command(['gcc','-fsanitize=undefined',caller,obj,'-o',exe])
            self.run_command([exe])

    def test_same_translation_unit_addressable_helpers_remain_callable(self):
        p, c = self.checked(source('entry', 19))
        generated = emit_c(p, c, crate_type='obj')
        # Existing native test harnesses append C to the emitted translation unit.
        # Local linkage does not make helper addresses inaccessible there.
        generated += "\nint main(void) { int64_t (*callback)(int64_t) = __hepta_cb_fn_helper; return callback(2)!=19 || entry()!=19; }\n"
        for optimize in [False, True]:
            exe = self.root / 'callback'
            r = compile_c(generated, output=exe, optimize=optimize, sanitize=True)
            self.assertTrue(r['ok'], r['diagnostics'])
            self.run_command([exe])

    def test_duplicate_explicit_c_exports_still_fail_linking(self):
        first = self.build('same_entry', 11, 'obj', False)
        retained = self.root / 'first.o'
        first.rename(retained)
        second = self.build('same_entry', 22, 'obj', False)
        caller = self.root / 'duplicate.c'
        caller.write_text('int main(void) {return 0;}\n')
        r = subprocess.run(['gcc', '-fsanitize=undefined', str(caller), str(retained), str(second),
                            '-o', str(self.root/'duplicate')], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('same_entry', r.stderr)
        self.assertIn('multiple definition', r.stderr)

    def test_public_import_alias_is_resolved_before_local_linkage(self):
        from hepta.pipeline import analyze_project
        (self.root/'math.hepta').write_text('module math; fn hidden() -> i64 effects {} {return 37;} pub fn answer() -> i64 effects {} {return hidden();}')
        entry = self.root/'main.hepta'
        entry.write_text('import math as m; export "C" fn visible() -> i64 effects {} {return m::answer();}')
        result = analyze_project(entry, backend='c', crate_type='obj')
        self.assertTrue(result.report['ok'], result.report)
        self.assertEqual(len(result.report['project']['sources']), 2)
        obj = self.root/'module.o'
        r = compile_c(result.c, crate_type='obj', output=obj, optimize=False, sanitize=True)
        self.assertTrue(r['ok'], r['diagnostics'])
        symbols = self.run_command(['nm', '-g', '--defined-only', obj])
        self.assertIn(' T visible', symbols)
        self.assertNotIn('__hepta_cb_', symbols)
        caller = self.root/'module-caller.c'
        caller.write_text('#include <stdint.h>\nextern int64_t visible(void);\nint main(void){return visible()!=37;}\n')
        exe = self.root/'module-caller'
        self.run_command(['gcc', '-fsanitize=undefined', caller, obj, '-o', exe])
        self.run_command([exe])
