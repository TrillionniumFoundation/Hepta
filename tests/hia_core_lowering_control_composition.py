"""Actual six-owner emission, capture, freshness and proof-consumption controls.

The second image is a valid independently mapped executable with an unreachable
NOP suffix. It is an identity fault control, not qualified compiler output.
"""
from contextlib import ExitStack
from hashlib import sha256
import importlib
import inspect
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

DEPENDENCIES = ('machine_encoding', 'machine_state', 'machine_instructions',
                'machine_elf', 'machine_plan')
ENV = 'HEPTA_HIA_CORE_LOWERING_CONTROL_COMPOSITION_MANIFESTS'



def _dependency_module(label):
    # Existing input-map labels stay unchanged; each label names one explicit ABI.
    modules = {
        'machine_plan': 'hepta.hia_machine_plan_control_selection',
        'core_lowering': 'hepta.hia_core_lowering_control_native',
    }
    return importlib.import_module(modules.get(label, 'hepta.hia_' + label + '_native'))


def _dependency_builder(label):
    modules = {
        'machine_plan': 'tools.build_hia_machine_plan_control',
        'core_lowering': 'tools.build_hia_core_lowering_control',
    }
    return importlib.import_module(modules.get(label, 'tools.build_hia_' + label))


def prepare_dependencies(test, core_manifest, directory):
    cold = os.environ.get('HEPTA_HIA_CORE_LOWERING_CONTROL_COLD_REPORT')
    development = os.environ.get(ENV)
    if cold and development:
        raise AssertionError('development dependencies cannot override current cold builders')
    modules = {label: _dependency_module(label)
               for label in DEPENDENCIES}
    if cold:
        from tools.build_hia_json_preflight import admit_cold_build
        outer = json.loads(Path(cold).read_bytes())
        nested = json.loads(Path(outer['nested_report']).read_bytes())
        compiler = Path(nested['generations'][-1]['produced_image'])
        admit_cold_build(compiler.read_bytes(), Path(cold).read_bytes())
        directory.mkdir(mode=0o700)
        manifests = {label: _dependency_builder(label).build(
            directory / label, compiler, Path(cold)) for label in DEPENDENCIES}
        scope = 'MATCHING_SOURCE_COLD_INDEPENDENT_BUILDERS'
    else:
        if not development:
            raise AssertionError('six-owner controls require explicit development dependencies or cold')
        value = json.loads(Path(development).read_bytes())
        test.assertIs(type(value), dict)
        test.assertEqual(set(value), set(DEPENDENCIES))
        test.assertTrue(all(type(v) is str for v in value.values()))
        manifests = {label: Path(value[label]).resolve(strict=True) for label in DEPENDENCIES}
        scope = 'EXPLICIT_RETAINED_COMPILER_DEVELOPMENT_ONLY'
    expected_compiler = json.loads(Path(core_manifest).read_bytes())['compiler_sha256']
    inputs = []
    for label, manifest in manifests.items():
        raw = manifest.read_bytes();record = json.loads(raw)
        image_path = manifest.parent / record['image_path'];image = image_path.read_bytes()
        owner = getattr(modules[label], 'installed_' + label)(str(manifest))
        test.assertEqual(record['compiler_sha256'], expected_compiler)
        test.assertEqual(owner.image_sha256, sha256(image).hexdigest())
        test.assertEqual(owner.admitted_source_sha256, sha256(modules[label].SOURCE.read_bytes()).hexdigest())
        inputs.extend(((manifest, raw), (image_path, image)))
    return manifests, modules, inputs, scope


def _copy_image(original, folder, suffix=b''):
    folder.mkdir(mode=0o700)
    record = json.loads(original.read_bytes())
    image = (original.parent / record['image_path']).read_bytes() + suffix
    record['image_path'] = 'machine_plan.image.bin'
    record['image_sha256'] = sha256(image).hexdigest()
    (folder / record['image_path']).write_bytes(image)
    manifest = folder / 'manifest.json'
    manifest.write_text(json.dumps(record, sort_keys=True) + '\n')
    return manifest


def controls(test, core_manifest, evidence):
    from hepta import hia_program as program, hia_program_native as backend
    from hepta import hia_machine_plan as plans, hia_machine_plan_control_selection as selection
    from hepta import hia_machine_x64 as encoding, hia_machine_elf as elf
    from hepta import hia_core_lowering_control_selection as core_selection
    from hepta import hia_checker_identity as identity
    from hepta.hia_proof_contract import proof_result
    from hepta.hia_agent_store import AgentRejected
    from tests.test_hia_program_native import minimal_document
    from tools.qualify_hia_machine_registers import explicit_plan
    from tests.test_hia_core_lowering_control_native import selected_guard, comparable
    from hepta.hia_machine_plan_control_native import PlanFrame

    manifests, modules, inputs, scope = prepare_dependencies(
        test, core_manifest, evidence / 'composition-build')
    env = {modules[label].SELECTOR: str(path) for label, path in manifests.items()}
    env[core_selection.SELECTOR] = str(core_manifest)
    checked = program.verify_program(minimal_document())
    plan = explicit_plan(checked)
    report = {'scope': scope, 'second_image_is_identity_fault_not_qualified_compiler': True,
              'input_bindings': [{'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                                 for path, raw in inputs], 'cases': []}
    with tempfile.TemporaryDirectory(prefix='hia-core-six-owner-') as temporary:
        root = Path(temporary)
        second = _copy_image(manifests['machine_plan'], root / 'B', b'\x90')
        a_sha = json.loads(manifests['machine_plan'].read_bytes())['image_sha256']
        b_owner = selection.installed_machine_plan(str(second))
        b_sha = b_owner.image_sha256
        test.assertNotEqual(a_sha, b_sha)
        test.assertEqual(b_owner.code_options(None), {})  # Actual executable B.
        with patch.dict(os.environ, env):
            baseline = backend.emit_program_machine(checked, machine_plan=plan)
        original_verify, original_inspect = program.verify_program, backend._inspect_object

        def proof(evidence_value, object_sha):
            return proof_result(claim='encoding_check', status='proved',
                domain='actual six-owner object rederivation and captured machine-plan identity',
                subject={'kind': 'native_artifact', 'candidate_core_sha256': checked.sha256,
                         'base_core_sha256': None, 'native_artifact': {'sha256': object_sha}},
                profile={}, installation={}, evidence=evidence_value)

        for initial, replacement in ((str(manifests['machine_plan']), ''),
                                     (str(manifests['machine_plan']), str(second)),
                                     ('', str(second))):
            calls, owners, old_calls, held_evidence = {}, {}, [], []
            verifies = []
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {**env, selection.SELECTOR: initial}))
                stack.enter_context(selected_guard(core_manifest))
                # Existing Code and ELF retained owners must not supply policy.
                for name, method in encoding.Code.__dict__.items():
                    if inspect.isfunction(method) and name != '__new__':
                        stack.enter_context(patch.object(encoding.Code, name,
                            side_effect=AssertionError('retained Code entered: ' + name)))
                stack.enter_context(patch.object(elf, '_reference_write_elf_object',
                    side_effect=AssertionError('retained ELF entered')))
                for name in ('_reference_validate_plan', '_reference_register_assignment_witness',
                             '_reference_code_options', '_reference_preservation_checks'):
                    original = getattr(plans, name)
                    def reference(*args, _name=name, _original=original, **kwargs):
                        old_calls.append(_name)
                        if initial:
                            raise AssertionError('selected Plan entered retained policy: ' + _name)
                        return _original(*args, **kwargs)
                    stack.enter_context(patch.object(plans, name, reference))
                def verify(value):
                    result = original_verify(value)
                    if not verifies:
                        byte_owner = encoding._selected_owner()
                        state_owner = encoding._selected_state_owner(byte_owner)
                        owners.update(machine_encoding=byte_owner, machine_state=state_owner,
                            machine_instructions=encoding._selected_instruction_owner(byte_owner, state_owner),
                            machine_elf=elf._selected_elf_owner(),
                            machine_plan=selection.selected_machine_plan(),
                            core_lowering=core_selection.active_core_lowering())
                        for label, owner in owners.items():
                            if owner is None:
                                continue
                            original = owner._entry;calls[label] = 0
                            def entry(*args, _label=label, _entry=original):
                                result = _entry(*args);calls[_label] += 1;return result
                            stack.enter_context(patch.object(owner, '_entry', entry))
                        os.environ[selection.SELECTOR] = replacement
                    verifies.append(result.sha256)
                    return result
                def inspect_object(data, exports):
                    result = original_inspect(data, exports)
                    selected = identity.checker_native_selection()
                    wanted = a_sha if initial else None
                    test.assertEqual(None if selected[selection.SELECTOR] is None else
                        selected[selection.SELECTOR]['images']['image']['image_sha256'], wanted)
                    item = {'method': 'complete_native_rederivation',
                            'actual_sha256': sha256(data).hexdigest(),
                            'bytes_equal': data == baseline.object_bytes,
                            'object_identity_equal': True,
                            'native_checker_selection': selected}
                    held_evidence.append((item, proof(item, item['actual_sha256'])))
                    return result
                stack.enter_context(patch.object(program, 'verify_program', verify))
                stack.enter_context(patch.object(backend, '_inspect_object', inspect_object))
                actual = backend.emit_program_machine(checked, machine_plan=plan)
                test.assertEqual(comparable(actual), comparable(baseline))
                test.assertEqual(len(held_evidence), 1)
                test.assertEqual(selection.captured_checker_owner(), (False, None))
                for label in ('machine_encoding', 'machine_state', 'machine_instructions',
                              'machine_elf', 'core_lowering'):
                    test.assertGreater(calls[label], 0)
                if initial:
                    test.assertEqual(old_calls, [])
                    test.assertGreater(calls['machine_plan'], 0)
                    test.assertEqual(owners['machine_plan'].image_sha256, a_sha)
                else:
                    test.assertIsNone(owners['machine_plan'])
                    test.assertNotIn('machine_plan', calls)
                    test.assertEqual(old_calls, ['_reference_validate_plan',
                        '_reference_register_assignment_witness', '_reference_code_options'])
                with test.assertRaisesRegex(AgentRejected, 'native checker selection differs'):
                    proof(held_evidence[0][0], actual.sha256)
                fresh = identity.checker_native_selection()[selection.SELECTOR]
                test.assertEqual(None if fresh is None else fresh['images']['image']['image_sha256'],
                                 b_sha if replacement else None)
                report['cases'].append({'initial': 'A' if initial else None,
                    'replacement': 'B' if replacement else None,
                    'held_native_frames': calls,
                    'held_image_sha256': {label: None if owner is None else owner.image_sha256
                                         for label, owner in owners.items()},
                    'old_plan_entries': old_calls, 'object_sha256': actual.sha256,
                    'implementation_sha256': actual.implementation_sha256,
                    'stale_proof_refused': True})
        with patch.dict(os.environ, {**env, selection.SELECTOR: str(second)}):
            alternative = backend.emit_program_machine(checked, machine_plan=plan)
            test.assertEqual(alternative.object_bytes, baseline.object_bytes)
            test.assertNotEqual(alternative.implementation_sha256, baseline.implementation_sha256)
        # Actual source / same-path image changes are fresh-admission failures.
        source = root / 'changed-source.hiaasm'
        source.write_bytes(selection.SOURCE.read_bytes() + b'\n')
        effects = []
        original_invoke = PlanFrame._invoke
        def invoked(frame, *args, **kwargs):
            effects.append(frame.mode);return original_invoke(frame, *args, **kwargs)
        with patch.object(PlanFrame, '_invoke', invoked):
            with patch.object(selection, 'SOURCE', source):
                with test.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    selection.installed_machine_plan(str(manifests['machine_plan']))
            changed = _copy_image(manifests['machine_plan'], root / 'same-path')
            warm = selection.installed_machine_plan(str(changed))
            record = json.loads(changed.read_bytes());image = changed.parent / record['image_path']
            raw = image.read_bytes();image.write_bytes(raw + b'\x90')
            with test.assertRaisesRegex(ValueError, 'executable identity mismatch'):
                selection.installed_machine_plan(str(changed))
            record['image_sha256'] = sha256(image.read_bytes()).hexdigest()
            changed.write_text(json.dumps(record, sort_keys=True) + '\n')
            new = selection.installed_machine_plan(str(changed))
            test.assertIsNot(new, warm)
            test.assertNotEqual(new.image_sha256, warm.image_sha256)
        test.assertEqual(effects, [])
        # A real native return followed by interruption cannot leak either scope.
        failure = KeyboardInterrupt('after actual Plan return in complete emit')
        returned = []
        with patch.dict(os.environ, env), selection.native_machine_plan_scope():
            held = selection.selected_machine_plan();original = held._entry
            def interrupted(*args):
                returned.append(original(*args));raise failure
            with patch.object(held, '_entry', interrupted):
                with test.assertRaises(KeyboardInterrupt) as seen:
                    backend.emit_program_machine(checked, machine_plan=plan)
            test.assertIs(seen.exception, failure)
            test.assertEqual(len(returned), 1)
        test.assertEqual(selection.captured_checker_owner(), (False, None))
        test.assertEqual(core_selection.captured_checker_owner(), (False, None))
        test.assertIsNone(plans._NATIVE_OWNER.get())
        with patch.dict(os.environ, {**env, selection.SELECTOR: str(second)}):
            recovered = backend.emit_program_machine(checked, machine_plan=plan)
            test.assertEqual(recovered, alternative)
        for malformed in ((1, None), (True, {}), (False, object())):
            with patch.object(selection, 'captured_checker_owner', return_value=malformed):
                with test.assertRaises(ValueError):identity.checker_native_selection()
        with patch.dict(os.environ, env), selection.native_machine_plan_scope():
            capability = selection.captured_checker_owner()[1]
            with test.assertRaises(ValueError):
                identity.checker_native_selection(held_owners=(capability,))
        # Interrupt the actual POP_TOP immediately after ContextVar.set:
        # its side effect happened even though its return was not retained.
        import dis
        import sys
        interruptions = []
        for target, call in ((plans.code_options, lambda: plans.code_options(None)),
                (selection.native_machine_plan_scope.__wrapped__,
                 lambda: selection.native_machine_plan_scope().__enter__())):
            instructions = list(dis.get_instructions(target))
            set_position = next(i for i, item in enumerate(instructions)
                                if item.opname in ('LOAD_ATTR', 'LOAD_METHOD') and item.argval == 'set')
            offset = next(item.offset for item in instructions[set_position:]
                          if item.opname == 'POP_TOP')
            fired = []
            interrupt = KeyboardInterrupt('actual selection set result was not acknowledged')
            def trace(frame, event, arg):
                if frame.f_code is target.__code__:
                    frame.f_trace_opcodes = True
                    if event == 'opcode' and frame.f_lasti == offset and not fired:
                        fired.append(offset)
                        raise interrupt
                return trace
            with patch.dict(os.environ, env):
                before_trace = sys.gettrace()
                try:
                    sys.settrace(trace)
                    with test.assertRaises(KeyboardInterrupt) as seen:
                        call()
                finally:
                    sys.settrace(before_trace)
                test.assertIs(seen.exception, interrupt)
                test.assertEqual(fired, [offset])
                test.assertIsNone(plans._NATIVE_OWNER.get())
                test.assertEqual(selection.captured_checker_owner(), (False, None))
                test.assertEqual(plans.code_options(None), {})
            interruptions.append({'function': target.__qualname__, 'offset': offset})
        report['actual_ContextVar_set_ack_interruptions'] = interruptions
        report.update(A_image_sha256=a_sha, B_image_sha256=b_sha,
                      source_and_same_path_image_fresh_admission=True,
                      forged_capability_and_ambient_override_refused=True,
                      actual_unknown_return_scope_restored=True,
                      first_unknown_return_status=returned[0])
    test.assertTrue(all(path.read_bytes() == raw for path, raw in inputs))
    (evidence / 'six-owner-composition.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
