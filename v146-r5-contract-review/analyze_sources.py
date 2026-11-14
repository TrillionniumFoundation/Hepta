"""Static source readback only; no project import, function execution, or test."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def check(raw, expected):
    actual = pin(raw)
    for key, value in actual.items():
        assert value == expected[key], (key, value, expected[key])
    return actual


def function(relative, name, parent=None):
    nodes = ast.parse((ROOT / relative).read_bytes(), filename=relative).body
    if parent is not None:
        matches = [n for n in nodes if isinstance(n, ast.ClassDef) and n.name == parent]
        assert len(matches) == 1
        nodes = matches[0].body
    matches = [n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(matches) == 1, (relative, name)
    return matches[0]


def excerpt(relative, first, last):
    raw = (ROOT / relative).read_bytes()
    lines = raw.decode().splitlines(keepends=True)
    assert 1 <= first <= last <= len(lines)
    text = ''.join(lines[first - 1:last])
    return {'source': relative, 'full_source_pin': pin(raw), 'first_line': first,
            'last_line': last, 'text': text, 'excerpt_pin': pin(text.encode())}


def full_function(relative, name, parent=None):
    node = function(relative, name, parent)
    return excerpt(relative, min([node.lineno] + [n.lineno for n in node.decorator_list]), node.end_lineno)


def main():
    mapraw = (ROOT / 'author/PROJECTED-SOURCE-MAP.json').read_bytes()
    check(mapraw, {'bytes': 779234, 'git_blob': 'f400270fe733603befffde0006fb11f306cde2ea',
                  'sha256': 'e53dc50aabb24c464bff34ada1ae8b96a90a1e98ccfc5fce77cf719495912c79'})
    source_map = json.loads(mapraw)
    mappings = {
        'hepta/hia_program_tools.py': 'source/hia_program_tools_r5.py',
        'hepta/hia_program.py': 'source/hia_program.py',
        'hepta/hia_schema.py': 'source/hia_schema.py',
        'hepta/hia_front_continuation.py': 'source/hia_front_continuation.py',
        'hepta/hia_front_runtime.py': 'source/hia_front_runtime.py',
        'hepta/hia_inspect_program_native.py': 'source/hia_inspect_program_native.py',
        'hepta/hia_inspect_program_ports.py': 'source/hia_inspect_program_ports.py',
        'hepta/hia_cli_native.py': 'source/hia_cli_native.py',
        'hepta/hia_cli_inspect_native.py': 'source/hia_cli_inspect_native.py',
        'tests/test_hia_program.py': 'source/test_hia_program.py',
        'tools/hia_inspect_program_policy.py': 'source/hia_inspect_program_policy.py',
        'tools/generate_hia_inspect_program.py': 'source/generate_hia_inspect_program.py',
    }
    sources = []
    for logical, relative in mappings.items():
        raw = (ROOT / relative).read_bytes()
        actual = check(raw, source_map[logical])
        ast.parse(raw, filename=logical)
        sources.append({'logical': logical, 'recovery_path': relative, 'pin': actual, 'R5_map_exact': True})
    planraw = (ROOT / 'author/PROPOSED-EXECUTION-PLAN.json').read_bytes()
    check(planraw, {'bytes': 28945, 'git_blob': 'fc2619602ffbaf2ac9baf93aa31435eb8d3d46b9',
                   'sha256': '963925bdb8846346e3b70e313db0489e17c65467a008e2a3eeb93fd6c493151a'})
    plan = json.loads(planraw)
    test = 'author/test_inspect_cli_witness_controls.py'
    support = 'author/inspect_cli_control_support.py'
    for relative in (test, support):
        check((ROOT / relative).read_bytes(), plan['controls'][Path(relative).name]['pin'])
        ast.parse((ROOT / relative).read_bytes(), filename=relative)
    before = (ROOT / 'source/hia_program_tools.py').read_bytes()
    after = (ROOT / 'source/hia_program_tools_r5.py').read_bytes()
    assert after[:len(before)] == before and len(after) - len(before) == 744
    original_functions = []
    for name in ('function_signature', 'inspect_program'):
        a = function('source/hia_program_tools_r5.py', name)
        b = function('source/hia_inspect_program_policy.py', name)
        assert ast.dump(a, include_attributes=False) == ast.dump(b, include_attributes=False)
        left = ast.get_source_segment(after.decode(), a)
        right = ast.get_source_segment((ROOT / 'source/hia_inspect_program_policy.py').read_text(), b)
        assert left == right
        original_functions.append({'name': name, 'whole_text_and_AST_equal': True, 'text_pin': pin(left.encode())})
    witness = function(test, 'test_entry_error_busy_unknown_no_retry', 'InspectCliWitnessControls')
    callback = next(n for n in witness.body if isinstance(n, ast.FunctionDef) and n.name == 'reenter')
    assert [type(n).__name__ for n in callback.body] == ['Assign', 'With', 'Expr', 'Expr', 'Expr', 'Return']
    assert ast.unparse(callback.body[-1]) == 'return real_verify(document)'
    body = ast.get_source_segment((ROOT / test).read_text(), witness)
    assert 'lambda: c.owner.finish(frame)' in body
    assert "self.assertEqual(reentries, ['refused-without-machine-entry'])" in body
    assert body.count("reentries.append('refused-without-machine-entry')") == 1
    getter = function('source/hia_program.py', 'normalization_report', 'VerifiedProgram')
    assert ast.unparse(getter.body[0]) == 'checked = verify_program(self)'
    inspect = function('source/hia_program_tools_r5.py', 'inspect_program')
    assert ast.unparse(inspect.body[0]) == 'from .hia_program import verify_program'
    assert ast.unparse(inspect.body[1]) == 'verified = verify_program(document)'
    schema_tree = ast.parse((ROOT / 'source/hia_schema.py').read_bytes())
    schema = next(n.value for n in schema_tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'SCHEMA' for t in n.targets))
    assert ast.literal_eval(schema) == 'hepta.hia.program.v1'
    excerpts = {
        'original_test_entire_method': full_function(test, witness.name, 'InspectCliWitnessControls'),
        'original_inspect_policy': full_function('source/hia_program_tools_r5.py', 'inspect_program'),
        'original_normalization_property': full_function('source/hia_program.py', 'normalization_report', 'VerifiedProgram'),
        'verified_type_and_defaults': excerpt('source/hia_program.py', 380, 398),
        'original_verifier': excerpt('source/hia_program.py', 984, 1018),
        'actual_public_verifier_wrapper': excerpt('source/hia_program.py', 1045, 1076),
        'R3_drive': full_function('source/hia_inspect_program_native.py', 'drive', 'InspectProgramFrame'),
        'R3_machine_lease': excerpt('source/hia_inspect_program_native.py', 35, 64),
        'actual_prepare': full_function('source/hia_inspect_program_native.py', 'prepare', 'NativeInspectProgram'),
        'constructor_has_no_policy_execution': excerpt('source/hia_front_continuation.py', 84, 137),
        'original_pending_guard': excerpt('source/hia_front_continuation.py', 232, 255),
        'effect_service': full_function('source/hia_front_continuation.py', 'service', 'ContinuationFrame'),
        'finish': full_function('source/hia_front_runtime.py', 'finish', 'NativeFrontImage'),
        'real_component_admission': excerpt(support, 88, 117),
        'fixed_primitive_fixture': full_function(support, 'fixture', 'ActualComponents'),
        'changed_attr_scope': full_function(support, 'changed_attr'),
        'observation_calls_once': full_function(support, 'observe', 'ActualComponents'),
        'CLI_adapter_is_session_only': excerpt('source/hia_cli_inspect_native.py', 65, 107),
        'fixture_module': excerpt('source/test_hia_program.py', 30, 40),
    }
    report = {
        'schema': 'hepta.hia.inspect-cli-witness10-source-review.v2',
        'status': 'SOURCE_CONTRACT_CONFLICT_RECONFIRMED_NO_COMPLIANT_WRAPPER_ONLY_PATCH',
        'scope': 'Post-reset readback/AST analysis, not a new runtime result or original-stat restoration.',
        'project_imports': 0, 'products': 0, 'tests': 0, 'binders': 0, 'CI': 0,
        'test_changes': 0, 'budget_changes': 0, 'old_R5_gate': 'HISTORICAL_FAIL_UNCHANGED',
        'source_tree_from_R5_author_plan': plan['source_tree'], 'source_map_pin': pin(mapraw),
        'source_rows': sources, 'author_plan_pin': pin(planraw),
        'test_pin': pin((ROOT / test).read_bytes()), 'support_pin': pin((ROOT / support).read_bytes()),
        'witness_group': plan['groups']['witness-10'], 'original_limits': plan['limits'],
        'body_preservation': {'entire_R20_prefix_exact': True, 'R20_pin': pin(before),
                              'R5_pin': pin(after), 'appended_anchor_bytes': 744,
                              'HIA_policy_complete_functions': original_functions},
        'authority': {
            'repository': 'TrillionniumFoundation/Hepta',
            'stable_commit': '26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d',
            'R5_author_recipe': '8d24df97c067381c8bca3937184bc5793a1fadb9',
            'R5_source_recipe': 'affd38ca5c772d995d2e00a4597449fa91bae80f',
            'R5_author_core': 'd605885ff5367f536d38cfca7d9e101177ab8d10',
            'R5_source_transport': 'c34aa38e26b0de176f83651e71e17fb3311e3358',
            'R5_full_author_manifest': '0df2be56852f3091cef48367e46e77a15a00db6a',
            'R5_full_author_decoded': pin((ROOT / 'decoded/r5-full-author.json').read_bytes()),
            'initial_source_recipe': '004e6c02042385bf4f94d980f37a610e8a73da59',
            'initial_source_transport': '8e91c8be30734df36217b5d37f7f226b5abbb154',
            'R3_drive_recipe': '389ffce406540a63ef8ea39b0db38d8f406f021a',
            'R3_drive_author_capsule': '651102e1d05f5854271d7f2f0a4404ca159dd057',
            'full_readback_member_counts': {'R5_core': 20, 'R5_source': 25, 'R5_full_author': 33, 'R3_drive': 19},
            'boundary': 'Restored exact author/plan/source identities. Does not claim original R5 frame archive recovered or a new 3191-file installation.'},
        'required_call_sequence': [
            'prepare: actual Inspect frame construction; no policy/provider execution',
            'changed_attr installs reenter for entire synchronous finish',
            'inspect imports current verify_program and calls reenter(original document)',
            'callback: RuntimeError refusal, unchanged entry count, executed/notcompleted, append1, real_verify(document)',
            'normalization_report property dynamically resolves verify_program and calls reenter(VerifiedProgram)',
            'callback: RuntimeError refusal, unchanged entry count, executed/notcompleted, append2, real_verify(VerifiedProgram)',
            'normal finish; provider restored; error is None; singleton-list assertion fails'],
        'conditional_conclusion': 'For this unchanged primitive fixture with current providers and both successful effects, two legitimate refused reentries and two appends are required. This is not a universal count for all inspect inputs or error paths.',
        'proof_of_incompatibility': 'Both required callback invocations execute the same append only after all three local assertions pass. Preserving both observations, those assertions, and error=None implies len(reentries)=2, contradicting the original expected singleton. The tested call bypasses CLI wrappers.',
        'decision': 'No implementation patch under the current contract. Preserve old failure and exact test. Only an explicitly versioned new observer baseline can admit the two-marker result without dropping original global reverify.',
        'historical_runtime_boundary': {
            'source': 'Prior Root/peer terminal statements; no new raw-frame replay.',
            'session': 63905, 'exit_code': 1, 'elapsed_seconds': 69.814360769,
            'reported': 'First13 groups PASS; group14 witness10 errors0/failures1 at singleton marker assertion.',
            'prior_frame_link_claim': 'OBSERVATION-0002: indices19..540, 522 calls, 3132 spans, 10298016 bytes were read before reset. Payloads not recovered here.',
            'hash_only_old_diagnosis': {'HANDOFF': '51abfb8fcde5ac22508d8dae7a8484192bea5798',
                                       'REPORT': 'ad755fa360ad4c9dde4880d3ad75a20d356a550b',
                                       'FRAME_LINKS': '70d16aeeecddcf1252ccdf66499dc29f6c123a04'},
            'missing': 'Original R5 execution large raw and prior diagnosis payloads were not completely remote-sealed before reset. This source report does not fill that gap.',
            'not_reached': 'Lost-real-claim/unknown-frame assertions below line463 in the same method were not established by its failed run.'},
        'new_reader_errors': [
            'Drive capsule first assumed text instead of base64: KeyError before restore. Actual base64 schema and all full member pins then verified.',
            'One display requested support through264 but file has261 lines: IndexError after display, no project execution.',
            'Computed direct blob IDs returned404 for some objects; exact content recovered from sealed capsules and matched to those IDs.'],
        'excerpts': excerpts,
        'analyzer_pin': pin(Path(__file__).read_bytes()),
    }
    raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    with (ROOT / 'SOURCE-REVIEW.json').open('xb') as out:
        out.write(raw)
    print(json.dumps({'status': report['status'], 'source_rows': len(sources), 'products': 0,
                      'report_pin': pin(raw)}, sort_keys=True))


if __name__ == '__main__':
    main()
