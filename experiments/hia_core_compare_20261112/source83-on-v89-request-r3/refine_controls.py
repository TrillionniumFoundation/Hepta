from pathlib import Path
import ast
root=Path('core-numeric-source83-on-v89-r3')
p=root/'negative_admission_fragment.py'
s=p.read_text()
s=s.replace("        process = self.original_popen(*arguments, **keywords)\n        permit['process'] = process","        process = self.original_popen(*arguments, **keywords)\n        permit['process'] = process",1)
s=s.replace("                   'directory_before': directory_before, 'cold_before': cold_before,","                   'temporary_parent': str(cwd.parent),\n                   'directory_before': directory_before, 'cold_before': cold_before,",1)
s=s.replace("                   'original_run_returned': False, 'original_process_context_closed': False,","                   'original_run_called': False, 'original_run_returned': False,\n                   'original_process_context_closed': False,",1)
s=s.replace("                                         'binding_sources_before', 'directory_before', 'cold_before',","                                         'binding_sources_before', 'temporary_parent', 'directory_before', 'cold_before',",1)
s=s.replace("            observed = self.original_run(*arguments, **keywords)","            row['original_run_called'] = True\n            observed = self.original_run(*arguments, **keywords)",1)
start=s.index("        finally:\n            self.pending = None")
end=s.index("\n    def complete(self):",start)
s=s[:start]+'''        finally:
            self.pending = None
            cleanup_error = None
            try:
                if row is not None:
                    process = None if permit is None else permit['process']
                    if process is not None:
                        row['returncode_after_original_run'] = process.returncode
                        row['original_process_context_closed'] = (
                            type(process.returncode) is int
                            and process.stdout is not None and process.stdout.closed
                            and process.stderr is not None and process.stderr.closed)
                    row['ended_monotonic_ns'] = time.monotonic_ns()
                    save(stem.with_suffix('.receipt.json'), dict(row))
                    row['receipt_original'] = pin(stem.with_suffix('.receipt.json'))
            except BaseException as error:
                cleanup_error = error
                if row is not None:
                    row['status'] = 'HOLD'
                    row.setdefault('preservation_errors', []).append(traceback.format_exc())
            for descriptor in (cold_fd, directory_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if cleanup_error is None:
                            cleanup_error = error
                        if row is not None:
                            row['status'] = 'HOLD'
                            row.setdefault('preservation_errors', []).append(traceback.format_exc())
            # An observation or close error must never replace the exception
            # raised by the original run(), including its TimeoutExpired.
            if original_exception is None and cleanup_error is not None:
                raise cleanup_error
''' + s[end:]
ast.parse(s)
p.write_text(s)
w=root/'control/worker.py'; old=Path('core-numeric-source83-on-v89-r2/control/worker.py').read_text()
new=old.replace('LOCAL_EXACT_PARTIAL_SOURCE_GENERATION_AND_SOURCE_VM_CONTROLS_ONLY','LOCAL_EXACT_PARTIAL_SOURCE_GENERATION_SOURCE_VM_AND_FOUR_NEGATIVE_ADMISSION_COMMANDS',1)
new=new.replace("        'cold_executed': False, 'installed_executed': False, 'remote_triggered': False}","        'cold_executed': False, 'installed_executed': False, 'remote_triggered': False,\n        'source_child_process_policy': policy['source_child_process_policy'],\n        'allowed_negative_processes': 0, 'forbidden_attempts': [],\n        'zero_process_scope_claimed': False}",1)
new=new.replace("                'complete source test IDs differ at final readback')","                'complete source test IDs differ at final readback')\n        require(type(observed['allowed_negative_processes']) is int\n                and observed['allowed_negative_processes'] == 4\n                and observed['forbidden_attempts'] == [] and observed['forbidden_attempt_count'] == 0\n                and observed['source_child_process_policy'] == policy['source_child_process_policy']\n                and observed['zero_process_scope_claimed'] is False,\n                'four original negative command permissions differ')\n        report['allowed_negative_processes'] = observed['allowed_negative_processes']\n        report['forbidden_attempts'] = observed['forbidden_attempts']",1)
ast.parse(new); w.write_text(new)
l=root/'control/launch.py';old=Path('core-numeric-source83-on-v89-r2/control/launch.py').read_text()
new=old.replace("        'cold_executed': False, 'installed_executed': False}","        'cold_executed': False, 'installed_executed': False,\n        'source_child_process_policy': policy['source_child_process_policy'],\n        'allowed_negative_processes': None, 'forbidden_attempts': None,\n        'zero_process_scope_claimed': False}",1)
new=new.replace("        final['status'] = 'SOURCE_INTEGRATION_PASS'","        require(type(tests['allowed_negative_processes']) is int\n                and tests['allowed_negative_processes'] == report['allowed_negative_processes'] == 4\n                and tests['forbidden_attempts'] == report['forbidden_attempts'] == []\n                and tests['forbidden_attempt_count'] == 0\n                and tests['zero_process_scope_claimed'] is report['zero_process_scope_claimed'] is False\n                and tests['source_child_process_policy'] == report['source_child_process_policy']\n                    == policy['source_child_process_policy'],\n                'source final negative-command scope differs')\n        final['allowed_negative_processes'] = tests['allowed_negative_processes']\n        final['forbidden_attempts'] = tests['forbidden_attempts']\n        final['status'] = 'SOURCE_INTEGRATION_PASS'",1)
ast.parse(new); l.write_text(new)

