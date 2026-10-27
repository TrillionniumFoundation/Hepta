"""Real Cortex-M4 boot plus adversarial checks on retained board evidence."""
import base64
import copy
import unittest

from tools.validate_board import qualify, validate_report, elf_evidence, validate_elf


class SystemBoardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing emulator is a failed qualification, never an object-only pass.
        cls.report=qualify()

    def test_actual_system_emulator_runs_boot_mmio_external_irq_and_controls(self):
        validate_report(self.report)
        self.assertEqual(self.report['denominator']['cold_boot_executions'],6)
        for case in self.report['cases']:
            self.assertEqual(len(case['hsir']['volatile_accesses']),14)
            raw=base64.b64decode(case['elf_base64'],validate=True)
            self.assertEqual(elf_evidence(raw),case['elf'])
            validate_elf(case['elf'])
        self.assertFalse(self.report['claims']['physical_board_qualified'])

    def test_mutated_reports_cannot_promote_compile_only_or_incomplete_execution(self):
        mutations={
            'physical_claim': lambda r:r['claims'].__setitem__('physical_board_qualified',True),
            'dma_claim': lambda r:r['claims'].__setitem__('dma_qualified',True),
            'missing_boot': lambda r:r['cases'][0]['runs'].pop(),
            'missing_case': lambda r:r['cases'].pop(),
            'missing_trace': lambda r:r['commands'].pop(),
            'renamed_control': lambda r:r['cases'][1].__setitem__('name','correct'),
            'frontend_only': lambda r:r['cases'][0]['frontend'].__setitem__('status','frontend_only'),
            'frontend_proof': lambda r:r['cases'][0]['frontend']['claims'].__setitem__('whole_language_soundness_proved',True),
            'frontend_schema': lambda r:r['cases'][0]['frontend'].__setitem__('schema','unbound'),
            'frontend_version': lambda r:r['cases'][0]['frontend'].__setitem__('compiler_version','0'),
            'scope_overclaim': lambda r:r['limitations'].__setitem__(0,'Physical hardware and DMA proven'),
            'toolchain_unpinned': lambda r:r['rustc'].__setitem__('version','rustc 1.91.0 (unqualified)\nrelease: 1.91.0'),
            'additional_claim': lambda r:r.__setitem__('all_hardware_proven',True),
            'unchecked_native': lambda r:r['cases'][0]['native_library'].__setitem__('check_only',True),
            'host_target': lambda r:r['cases'][0]['native_library'].__setitem__('target','x86_64-unknown-linux-gnu'),
            'source_changed': lambda r:r['cases'][1].__setitem__('source_sha256','0'*64),
            'startup_changed': lambda r:r['cases'][3].__setitem__('startup_sha256','0'*64),
            'unbound_codegen': lambda r:r['cases'][0].__setitem__('generated_rust_sha256','0'*64),
            'lost_mmio_sites': lambda r:r['cases'][0]['hsir']['volatile_accesses'].clear(),
            'forged_ir_proof': lambda r:r['cases'][0]['hsir']['claims'].__setitem__('whole_language_soundness_proved',True),
            'compile_failed': lambda r:r['cases'][0]['link'].__setitem__('returncode',1),
            'no_negative_flag': lambda r:r['cases'][2]['link']['argv'].remove('disable_timer_irq'),
            'host_emulation': lambda r:r['cases'][0]['runs'][0]['command']['argv'].__setitem__(0,'qemu-arm'),
            'wrong_machine': lambda r:r['cases'][0]['runs'][0]['command']['argv'].__setitem__(2,'virt'),
            'wrong_irq_summary': lambda r:r['cases'][0]['runs'][0]['observation'].__setitem__('irq_count',0),
            'wrong_checksum': lambda r:r['cases'][0]['runs'][0]['observation'].__setitem__('checksum',0),
            'negative_as_success': lambda r:r['cases'][1]['runs'][0]['command'].__setitem__('returncode',0),
            'boolean_count': lambda r:r['denominator'].__setitem__('compiled_negative_controls',True),
            'boolean_exit': lambda r:r['cases'][0]['runs'][0]['command'].__setitem__('returncode',False),
            'truncated_elf': lambda r:r['cases'][0].__setitem__('elf_base64','f0VMRg=='),
            'artifact_digest': lambda r:r['cases'][0]['elf'].__setitem__('sha256','0'*64),
            'wrong_vector': lambda r:r['cases'][0]['elf']['vectors'].__setitem__(24,0),
            'folded_data': lambda r:r['cases'][0]['elf']['sections']['.data'].__setitem__('bytes',0),
            'raw_output_missing': lambda r:r['cases'][0]['runs'][0]['command'].__setitem__('stdout',''),
            'negative_watchdog': lambda r:r['cases'][2]['runs'][0]['observation'].__setitem__('watchdog_ticks',0),
            'bad_emulator': lambda r:r['qemu'].__setitem__('version','QEMU emulator version 9.0.0 '),
            'changed_memory_map': lambda r:r['board_profile']['timer0'].__setitem__('irq',9),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                report=copy.deepcopy(self.report);mutate(report)
                with self.assertRaises(ValueError):validate_report(report)

    def test_raw_uart_and_summary_changed_together_still_fail_actual_oracle(self):
        report=copy.deepcopy(self.report)
        run=report['cases'][0]['runs'][0]
        original=run['command']['stdout']
        run['observation']['checksum']=56
        run['command']['stdout']=original.replace('"checksum":55','"checksum":56')
        for command in report['commands']:
            if command['stdout']==original:command['stdout']=run['command']['stdout']
        with self.assertRaises(ValueError):validate_report(report)

    def test_duplicate_uart_json_keys_and_wrong_elf_machine_rejected(self):
        report=copy.deepcopy(self.report)
        run=report['cases'][0]['runs'][0]
        run['command']['stdout']=run['command']['stdout'].replace('"code":0','"code":0,"code":0')
        with self.assertRaises(ValueError):validate_report(report)
        raw=bytearray(base64.b64decode(self.report['cases'][0]['elf_base64']))
        raw[18]=62  # x86_64 rather than ARM, without executing changed bytes.
        with self.assertRaises(ValueError):elf_evidence(bytes(raw))

    def test_malformed_top_levels_fail_closed(self):
        for value in ({},None,[],{'schema':'hepta.system-board.v1','status':'passed'}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):validate_report(value)


if __name__=='__main__':unittest.main()
