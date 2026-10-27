"""Adversarial report mutations shared by the independent validator audit."""
from copy import deepcopy


MUTATIONS = {
    "memory": [
        ("missing_kernel_output", [(('kernel_output',), None)]),
        ("empty_kernel_output", [(('kernel_output',), '')]),
        ("false_kernel_output", [(('kernel_output',), 'proofs passed')]),
        ("wrong_lean_version", [(('lean',), 'Lean version 0.0.0')]),
        ("missing_scope", [(('scope',), None)]),
        ("upgraded_scope", [(('scope',), {'memory': 'all foreign pointers proved safe'})]),
        ("boolean_claim_as_integer", [(('claims','abstract_provenance_theorems_checked'), 1)]),
        ("false_claim_as_integer", [(('claims','production_type_system_soundness_proved'), 0)]),
        ("erased_axiom_dependencies", [(('theorems','Hepta.Memory.reuse_does_not_revive_old_pointer'), [])]),
        ("duplicate_dependencies", [(('theorems','Hepta.Memory.admission_preserves_exclusivity'), ['propext','propext'])]),
        ("missing_negative_log", [(('negative_mutations',0,'log'), None)]),
        ("negative_exit_is_boolean", [(('negative_mutations',0,'returncode'), True)]),
        ("wrong_source_hash", [(('source_sha256',), '0'*64)]),
        ("wrong_checker_hash", [(('lean_binary_sha256',), '0'*64)]),
    ],
    "host": [
        ("missing_host", [(('host',), {})]),
        ("wrong_host_system", [(('host','system'), 'Windows')]),
        ("wrong_host_machine", [(('host','machine'), 'aarch64')]),
        ("emulator_claimed_as_host", [(('host','execution'), 'qemu')]),
        ("missing_c_compiler", [(('c_compiler',), {})]),
        ("missing_header_hash", [(('header_sha256',), None)]),
        ("missing_commands", [(('commands',), [])]),
        ("wrong_compile_command", [(('commands',2,'argv'), ['true'])]),
        ("unexecuted_native_driver", [(('commands',3,'returncode'), 1)]),
        ("missing_executable_hashes", [(('executable_sha256s',), [])]),
        ("missing_object_hashes", [(('native_object','artifact_sha256'), None),(('native_object','validation_artifact_sha256'), None)]),
        ("missing_object_source", [(('native_object','rust_sha256'), None)]),
        ("missing_frontend_validation", [(('frontend',), {'ok':True})]),
        ("wrong_negative_source", [(('negative_control','source_sha256'), '0'*64)]),
        ("missing_negative_artifact", [(('negative_control','artifact_sha256'), None)]),
        ("boolean_claim_as_integer", [(('claims','actual_reported_host_executed'), 1)]),
        ("foreign_calls_as_float", [(('executions',0,'observed','foreign_calls'), 181.0)]),
        ("native_returncode_as_boolean", [(('executions',0,'returncode'), False)]),
        ("wrong_compiler", [(('compiler_sha256',), '0'*64)]),
    ],
    "debug": [
        ("missing_debugger_identity", [(('debugger',), {})]),
        ("missing_source_map", [(('results',0,'mapping'), {})]),
        ("missing_step_file", [(('results',0,'observation','step_file'), None)]),
        ("missing_step_line", [(('results',0,'observation','step_line'), None)]),
        ("false_step_line", [(('results',0,'observation','step_line'), 999999)]),
        ("false_step_file", [(('results',0,'observation','step_file'), '/tmp/false.rs')]),
        ("counterfeit_breakpoint", [(('results',0,'source_breakpoint','native_path'), '/tmp/fake.rs'),(('results',0,'observation','file'), '/tmp/fake.rs'),(('results',0,'source_breakpoint','native_line'), 991), (('results',0,'observation','line'), 991)]),
        ("missing_artifact_hashes", [(('results',0,'build','build','artifact_sha256'), None),(('results',0,'build','build','validation_artifact_sha256'), None)]),
        ("missing_generated_source_hash", [(('results',0,'build','build','rust_sha256'), None)]),
        ("missing_retained_debug_source", [(('results',0,'build','build','debug_info'), {})]),
        ("missing_frontend_validation", [(('results',0,'build','validation'), {'ok':True})]),
        ("wrong_stack_frames", [(('results',0,'observation','frames'), ['invented','caller'])]),
        ("locals_values_as_float", [(('results',0,'observation','locals','h_base'), 12.0)]),
        ("boolean_claim_as_integer", [(('claims','both_backends_executed'), 1)]),
        ("wrong_compiler", [(('compiler_sha256',), '0'*64)]),
        ("debugger_return_as_boolean", [(('results',0,'debugger_returncode'), False)]),
        ("missing_debug_flags", [(('results',0,'build','build','flags'), [])]),
    ],
}


def alter(report, changes):
    value = deepcopy(report)
    for path, replacement in changes:
        target = value
        for key in path[:-1]:
            target = target[key]
        if path == ('host', 'system') and target[path[-1]] == replacement:
            replacement = 'Linux'
        if path == ('host', 'machine') and target[path[-1]] == replacement:
            replacement = 'x86_64'
        target[path[-1]] = deepcopy(replacement)
    return value


def audit(validators, reports):
    results = []
    for family, cases in MUTATIONS.items():
        validators[family](reports[family])
        for name, changes in cases:
            try:
                validators[family](alter(reports[family], changes))
            except Exception as error:
                results.append({'family':family,'case':name,'rejected':True,'error_type':type(error).__name__})
            else:
                results.append({'family':family,'case':name,'rejected':False})
    return {'cases':len(results),'unexpected_acceptances':sum(not r['rejected'] for r in results),'results':results}
