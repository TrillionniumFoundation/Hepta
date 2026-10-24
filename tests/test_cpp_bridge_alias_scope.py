"""An alias spelling cannot silently change meaning at the wrapper scope."""
from pathlib import Path
import tempfile
import unittest
from hepta.cpp_bridge import bridge_cpp

class AliasScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def convert(self,body):
        src=self.root/'Sample.hpp';cpp=self.root/'bridge.cpp';hp=self.root/'bridge.hepta'
        cpp.unlink(missing_ok=True);hp.unlink(missing_ok=True)
        src.write_text('#include "types.hpp"\nstruct Sample { '+body+' };\n')
        return bridge_cpp(src,'Sample',cpp,hp),cpp,hp
    def reject_alias(self,body):
        r,cpp,hp=self.convert(body)
        self.assertFalse(r['ok'],r)
        self.assertIn('E_CPP_ALIAS_SCOPE',[d['code'] for d in r['diagnostics']],r)
        self.assertFalse(cpp.exists());self.assertFalse(hp.exists())
    def test_included_alias_return_only_cannot_narrow_to_global_uint32(self):
        (self.root/'types.hpp').write_text('using Value = long long;\n')
        self.reject_alias('using uint32_t = Value; Sample(){} ~Sample() noexcept {} uint32_t value(){return 4294967297LL;}')
    def test_private_typedef_in_public_return_is_still_detected(self):
        (self.root/'types.hpp').write_text('typedef long long Value;\n')
        self.reject_alias('private: typedef Value uint32_t; public: Sample(){} ~Sample() noexcept {} uint32_t value(){return 4294967297LL;}')
    def test_parameter_only_and_both_positions(self):
        (self.root/'types.hpp').write_text('using Value = unsigned char;\n')
        for method in ['int value(uint64_t x){return x;}','uint64_t value(uint64_t x){return x;}']:
            with self.subTest(method=method):
                self.reject_alias('using uint64_t = Value; Sample(){} ~Sample() noexcept {} '+method)
    def test_all_four_previously_supported_names_are_guarded(self):
        (self.root/'types.hpp').write_text('using Value = unsigned char;\n')
        for name in ['int32_t','uint32_t','int64_t','uint64_t']:
            with self.subTest(name=name):
                self.reject_alias(f'typedef Value {name}; Sample(){{}} ~Sample() noexcept {{}} {name} value(){{return 7;}}')
    def test_standard_header_types_and_unused_local_alias_stay_supported(self):
        (self.root/'types.hpp').write_text('#include <cstdint>\n')
        r,cpp,hp=self.convert('using uint64_t = unsigned char; Sample(){} ~Sample() noexcept {} int32_t value(int32_t x){return x;}')
        self.assertTrue(r['ok'],r);self.assertTrue(cpp.exists());self.assertIn('arg0: i32',hp.read_text())
