"""Read-only packet/AST review; never imports or executes product modules."""
from __future__ import annotations
import ast
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/dda74a4fae35')
HERE = ROOT / 'v110-portable-report-review-r1'
PACKET = ROOT / 'v95-audit-mount-r1/v110-component-custody/portable-source/SOURCE-DECODED.json'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def tree(raw):
    return ast.parse(raw)


def structural(node):
    return ast.dump(node, include_attributes=False)


def definitions(raw):
    return {n.name: n for n in tree(raw).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}


def inventory(raw, name):
    found = [n.value for n in tree(raw).body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    assert len(found) == 1, name
    return ast.literal_eval(found[0])


def method_ids(path, raw):
    module = path[:-3].replace('/', '.')
    return [module + '.' + node.name + '.' + child.name
            for node in tree(raw).body if isinstance(node, ast.ClassDef)
            for child in node.body if isinstance(child, ast.FunctionDef) and child.name.startswith('test_')]


def main():
    packet_raw = PACKET.read_bytes()
    packet = json.loads(packet_raw)
    assert len(packet['changes']) == 13 and packet['deleted_paths'] == []
    base = Path(packet['base']['path'])
    records = []
    changed = {}
    for row in packet['changes']:
        path = row['after']['path']
        changed[path] = row
        sides = {}
        for side in ('before', 'after'):
            value = row[side]
            if value is None:
                sides[side] = None
                continue
            raw = value['text'].encode('utf-8')
            actual = pin(raw)
            assert all(actual[key] == value[key] for key in actual), (path, side)
            assert value['mode'] == '100644'
            assert (HERE / side / path).read_bytes() == raw, (path, side, 'review-copy')
            if side == 'before':
                assert (base / path).read_bytes() == raw, (path, 'packet-base')
            sides[side] = actual
        records.append({'path': path, **sides})

    cli_path = 'hepta/hia_cli_native.py'
    cli_before = (HERE / 'before' / cli_path).read_bytes()
    cli_after = (HERE / 'after' / cli_path).read_bytes()
    old_tree, new_tree = tree(cli_before), tree(cli_after)
    schema = 'hepta.hia.cli-verified-report-bundle.v1'
    projected = copy.deepcopy(new_tree)
    removed = []
    for fn in projected.body:
        if isinstance(fn, ast.FunctionDef) and fn.name in ('installed_cli', 'installed_cli_strict'):
            matches = [node for node in fn.body if isinstance(node, ast.If)
                       and any(isinstance(v, ast.Constant) and v.value == schema for v in ast.walk(node.test))]
            assert len(matches) == 1
            branch = matches[0]
            assert len(branch.body) == 2 and isinstance(branch.body[0], ast.ImportFrom)
            assert branch.body[0].module == 'hia_cli_verified_report_native'
            assert [(a.name, a.asname) for a in branch.body[0].names] == [('installed_bundle', None)]
            call = branch.body[1].value
            assert isinstance(branch.body[1], ast.Return) and isinstance(call, ast.Call)
            assert isinstance(call.func, ast.Name) and call.func.id == 'installed_bundle'
            assert [a.id for a in call.args] == ['path', 'raw', 'bundle']
            expected_keywords = [] if fn.name == 'installed_cli' else [('strict', True)]
            assert [(k.arg, ast.literal_eval(k.value)) for k in call.keywords] == expected_keywords
            removed.append({'function': fn.name, 'line': branch.lineno, 'body': ast.unparse(branch)})
            fn.body.remove(branch)
    assert len(removed) == 2 and structural(projected) == structural(old_tree)

    retained_path = 'tests/fixtures/hia_cli_routing_retained.json'
    old = json.loads((HERE / 'before' / retained_path).read_bytes())
    new = json.loads((HERE / 'after' / retained_path).read_bytes())
    assert set(old) == set(new)
    for key in ('schema', 'control_adaptation', 'original_tests', 'original_ids'):
        assert old[key] == new[key], key
    assert len(new['original_ids']) == len(set(new['original_ids'])) == 43
    assert old['integration_projections'].keys() == new['integration_projections'].keys()
    for path, current in new['integration_projections'].items():
        previous = old['integration_projections'][path]
        if path != cli_path:
            assert current == previous
        else:
            assert current['before'] == previous['before']
            assert current['after']['text'].encode() == cli_after
            history = current['approved_later_byte_streams']
            assert len(history) == 1 and history[0]['previous'] == previous['after']
            assert set(current) == set(previous) | {'approved_later_byte_streams'}
            for key in set(previous) - {'after'}:
                assert current[key] == previous[key]
    originals = []
    for path, value in new['original_tests'].items():
        raw = value['text'].encode()
        assert len(raw) == value['bytes'] and hashlib.sha256(raw).hexdigest() == value['sha256']
        assert (base / path).read_bytes() == raw
        assert path not in changed
        originals.append({'path': path, **pin(raw), 'unchanged_packet_and_base': True})

    report_fixture = json.loads((HERE / 'after/tests/fixtures/hia_verified_report_retained.json').read_bytes())
    assert report_fixture['original_cli_ids'] == new['original_ids']
    assert len(report_fixture['case_names']) == len(set(report_fixture['case_names'])) == 140
    for key in ('original_class', 'original_external_driver'):
        value = report_fixture[key]
        assert all(pin(value['text'].encode())[k] == value[k] for k in ('bytes', 'sha256', 'git_blob'))
    original_class = ast.parse(report_fixture['original_class']['text']).body[0]
    actual_class = definitions((base / 'hepta/hia_program.py').read_bytes())['VerifiedProgram']
    assert structural(original_class) == structural(actual_class)
    policy = definitions((base / 'tools/hia_verified_report_policy.py').read_bytes())
    assert list(policy) == report_fixture['methods'] and len(policy) == 7
    for name in report_fixture['methods']:
        method = copy.deepcopy(next(n for n in original_class.body if isinstance(n, ast.FunctionDef) and n.name == name))
        method.decorator_list = []
        assert structural(method) == structural(policy[name])

    contract_path = 'hepta/hia_agent_contract.py'
    before_contract = (HERE / 'before' / contract_path).read_bytes()
    after_contract = (HERE / 'after' / contract_path).read_bytes()
    native_before = inventory(before_contract, 'NATIVE_SOURCE_FILES')
    native_after = inventory(after_contract, 'NATIVE_SOURCE_FILES')
    entry_before = inventory(before_contract, 'ENTRY_BUILD_FILES')
    entry_after = inventory(after_contract, 'ENTRY_BUILD_FILES')
    resource = 'examples/hia_bootstrap/verified_report.hepta'
    assert native_after == native_before + (resource,) and entry_before == entry_after
    support = 'tools/hia_selfhost_contract.py'
    support_before = inventory((HERE / 'before' / support).read_bytes(), 'SOURCE_FILES')
    support_after = inventory((HERE / 'after' / support).read_bytes(), 'SOURCE_FILES')
    assert support_after[:len(support_before)] == support_before
    assert len(support_after) == len(set(support_after))

    source6 = []
    for path in ('tests/test_hia_verified_report_source.py', 'tests/test_hia_linux_file_roundtrip_source.py'):
        raw = (ROOT / 'v109-union-r17/source-r2' / path).read_bytes()
        assert path not in changed
        ids = method_ids(path, raw)
        assert len(ids) == 3
        source6.append({'path': path, **pin(raw), 'ids': ids,
                        'packet_has_no_delta': True, 'integration_preservation_required': True})

    return {
        'schema': 'hepta.portable-report.independent-source-review.v1',
        'status': 'REVIEW_COMPLETE_WITH_REGISTRATION_BLOCKER',
        'scope': 'READ_ONLY_PACKET_AST_AND_CUSTODY_SOURCE_REVIEW',
        'product_executions': 0, 'native_compiles': 0, 'cold_positive_executed': False,
        'qualification_transfer': False, 'packet': {'path': str(PACKET), **pin(packet_raw)},
        'base': packet['base'], 'changes': records,
        'checks': {
            'all_13_before_after_identities_match': True,
            'all_existing_before_bytes_match_exact_packet_base': True,
            'two_schema_branches_removed_give_exact_entire_original_module_AST': True,
            'original43_test_files_and_ordered_ids_unchanged': True,
            'retained_before_identities_and_other_projections_unchanged': True,
            'only_cli_after_identity_and_exact_previous_after_history_added': True,
            'complete_verified_program_class_and_seven_method_AST_retained': True,
            'retained140_names_unique': True,
            'source_inventory_is_exact_append_with_no_duplicates': True,
        },
        'dispatch_branches': removed, 'original43_files': originals,
        'registration': {'native_before': len(native_before), 'native_after': len(native_after),
                         'entry_before': len(entry_before), 'entry_after': len(entry_after),
                         'source_additions': list(support_after[len(support_before):]),
                         'resource': resource},
        'blocking_findings': [{
            'id': 'DEFAULT_FIXED_PROFILE_RESOURCE_CONFLICT',
            'fact': 'Packet appends verified_report.hepta to NATIVE_SOURCE_FILES (92 to 93); its new Source assertion requires that global membership and forbids ENTRY aliasing.',
            'original_constraints': ['tests/test_hia_installed_fixture_resources.py:73 native count 92',
                                     'tests/test_hia_installed_fixture_resources.py:118 resource count 210',
                                     'tests/test_hia_linux_stdio_cold.py:74 exact original ENTRY tuple'],
            'impact': 'This optional packet cannot be integrated as an expansion of the unchanged default fixed profile and simultaneously satisfy the original assertions. Prior R16 optional ENTRY expansion also fails its fixed tuple/allowlist.',
            'resolution_boundary': 'Preserve original tests/default profile and introduce an explicit versioned optional inventory/source closure/installation selection; revise only the new component role assertion in an independently recorded successor. No test-name detection, arbitrary allowlist widening, inferred counts, or transferred qualification.'}],
        'cold_review': {
            'result': 'NO_ADDITIONAL_CONCRETE_COLD_AUTHORITY_BYPASS_FOUND_IN_REVIEWED_SOURCE',
            'real_authority_chain': ['original current-source cold outer+owner180/3 completion+cleanup',
                'actual nested cold report and B1/B2/B3 byte hashes/lengths',
                'complete current_sources equality plus all report owner files',
                'five actual companion builds and one actual report compile',
                'strict child request keys/limits and stdout-to-receipt equality',
                'full 1MiB compile output prefix-to-image plus manifest/compiler/source binding',
                'fixture/source/build input bindings rechecked before and after groups'],
            'original43_provider': 'Two actual six-image builds admitted against the same real cold authority plus one original invalid-cold refusal; original test bodies remain unchanged.',
            'success_conditions': 'Exact loaded/started/stopped/run IDs and exact-int counts; no fail/error/skip/expected-failure/unexpected-success; original180+3 owners and cleanup; final current-source guard.',
            'not_established': ['matching-current-source cold positive on integrated R18/R19',
                'new versioned profile installation completeness', 'whole CLI or whole verify native delivery']},
        'source6_to_preserve': source6,
        'limits': ['Only frozen packet and listed inherited custody sources reviewed; no product/test/VM executed.',
                   'Current R17/r18 integration source was not modified; six original Source method IDs and complete source bytes must remain independently registered.',
                   'Warm admitted mapping behavior and strict disk readback remain intentionally distinct; no new proof is claimed by this review.']}


if __name__ == '__main__':
    value = main()
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    target = HERE / 'REVIEW.json'
    with target.open('xb') as stream:
        stream.write(raw)
    assert target.read_bytes() == raw
    print(json.dumps({'status': value['status'], 'report': str(target), **pin(raw)}))
