"""Pure parser/checker/emitter controls; no compiler or executable launch."""
import unittest
from unittest.mock import patch
from hepta.ast import Type
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import CEmitter, emit_c
from tools.probe_c_typedef_alignment import packet_layout_binding

SOURCE='''module binding;
repr(C) struct C_Packet { f_lead: i8, f_value: i32, f_tail: i8, }
pub fn c_probe(p_p: C_Packet) -> i32 effects {} { return p_p.f_value; }
'''

class LayoutBindingTests(unittest.TestCase):
    def emit(self, decoy=False):
        source=SOURCE.replace('repr(C) struct C_Packet','repr(C) struct Decoy { x: u64, }\nrepr(C) struct C_Packet') if decoy else SOURCE
        program=parse(source);checked=check(program);self.assertTrue(checked.ok)
        emitter=CEmitter(program,checked,'obj');generated=emitter.emit()
        self.assertEqual(generated,emit_c(program,checked,crate_type='obj'))
        return emitter,generated

    def test_actual_active_mapping_binds_packet(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No native launch')) as forbidden:
            emitter,generated=self.emit();binding=packet_layout_binding(emitter,generated)
            self.assertEqual(binding['c_type'],emitter.types[Type('C_Packet')])
            self.assertEqual(binding['c_type'],'__hepta_cb_aggregate_0')
            self.assertEqual(forbidden.call_count,0)

    def test_packet_after_decoy_does_not_select_first_aggregate(self):
        emitter,generated=self.emit(True);binding=packet_layout_binding(emitter,generated)
        self.assertEqual(binding['c_type'],'__hepta_cb_aggregate_1')
        self.assertNotEqual(binding['c_type'],emitter.types[Type('Decoy')])

    def test_wrong_record_mapping_rejected(self):
        emitter,generated=self.emit(True);emitter.types[Type('C_Packet')]=emitter.types[Type('Decoy')]
        with self.assertRaises(RuntimeError):packet_layout_binding(emitter,generated)

    def test_unmapped_old_hardcoded_name_rejected(self):
        emitter,generated=self.emit();emitter.types[Type('C_Packet')]='__hepta_cb_type_C_Packet'
        with self.assertRaises(RuntimeError):packet_layout_binding(emitter,generated)

    def test_wrong_field_and_duplicate_declaration_rejected(self):
        emitter,generated=self.emit();declaration=emitter.declarations[0]
        for text in (generated.replace('int32_t h_f_value','int64_t h_f_value'),generated+'\n'+declaration):
            with self.subTest(text=text):
                with self.assertRaises(RuntimeError):packet_layout_binding(emitter,text)

    def test_wrong_scientific_function_parameter_rejected(self):
        emitter,generated=self.emit(True)
        bad=generated.replace('__hepta_cb_fn_c_probe(__hepta_cb_aggregate_1','__hepta_cb_fn_c_probe(__hepta_cb_aggregate_0')
        with self.assertRaises(RuntimeError):packet_layout_binding(emitter,bad)

    def test_same_instance_mapping_supports_nonordinal_spelling(self):
        emitter,generated=self.emit();old=emitter.types[Type('C_Packet')];new='reviewed_packet_name'
        emitter.types[Type('C_Packet')]=new
        emitter.declarations=[d.replace(old,new)for d in emitter.declarations]
        binding=packet_layout_binding(emitter,generated.replace(old,new))
        self.assertEqual(binding['c_type'],new)

if __name__=='__main__':unittest.main()
