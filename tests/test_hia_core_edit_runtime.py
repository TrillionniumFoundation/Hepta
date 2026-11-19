"""Compare installed native Core edit and impact commands with the ordinary APIs."""

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import zlib

from hepta.hia_agent_store import wire as canonical_wire
from hepta.hia_edit_batch import apply_batch, prepare_batch
from hepta.hia_edit_query import apply_edit, prepare_edit
from tests.test_hia_edit_batch import loans, selected, swaps
from tests.test_hia_edit_query import fixture
from hepta.hia_patch_impact import analyze_patch_impact
from tests.test_hia_patch_impact import (
    append_wrapper, isolated_program, move_program, patch_initial_byte, patch_packet,
)
from tests.test_hia_program_tools import add_two_patch, scalar_program


def wire(value, *, pretty=False):
    formatting = {'sort_keys': True, 'indent': 2} if pretty else {'separators': (',', ':')}
    return (json.dumps(value, ensure_ascii=False, **formatting) + ('\n' if pretty else '')).encode()


def check_release(release):
    passed = 0

    def case(command, payload, expected=None, *, status=0, args=(), compact=False):
        nonlocal passed
        raw = payload if type(payload) is bytes else wire(payload)
        run = subprocess.run([release / command, *args], input=raw, capture_output=True,
                             env={'PATH': ''}, timeout=20, check=False)
        output = b'' if status and expected is None else (canonical_wire(expected) if compact else wire(expected, pretty=True))
        if (run.returncode, run.stdout, run.stderr) != (status, output, b''):
            raise AssertionError((command, status, run.returncode, run.stdout[:200], run.stderr))
        passed += 1
        return json.loads(run.stdout) if not status else None

    for version in range(1, 9):
        document = scalar_program()
        document['schema'] = 'hepta.hia.program.v' + str(version)
        site = selected('answer', 'attrs', 'increment')
        expected = prepare_edit(document, **site)
        case('hia-prepare-edit-query', [document, site], expected)
        case('hia-prepare-edit-query', [document, site], expected,
             args=('--agent-compact',), compact=True)

    from hepta.hia_program import verify_program
    from tests.test_hia_program_composite import stored_loan_program
    nominal = verify_program(stored_loan_program())
    core = nominal.as_dict()
    fn = core['functions'][0]
    block = next(value for value in fn['blocks'] if value['id'] == fn['entry'])
    out = next(op['out'][0]['name'] for op in block['ops'] if op['out'])
    site = {'function': fn['name'], 'block': block['id'], 'output': out,
            'fields': ['op', 'args', 'attrs']}
    expected = prepare_edit(nominal, **site)
    assert expected['base_sha256'] != expected['input_sha256']
    case('hia-prepare-edit-query', [core, site], expected,
         args=('--agent-compact', nominal.input_sha256), compact=True)
    for invalid in ('a' * 63, 'A' * 64, 'a' * 65):
        case('hia-prepare-edit-query', [core, site], args=('--agent-compact', invalid), status=64)


    document = fixture()
    site = selected('y', 'op', 'calculate')
    query = case('hia-prepare-edit-query', [document, site], prepare_edit(document, **site))
    edit = {'op': 'int.sub.wrap'}
    candidate, receipt = apply_edit(document, query, edit)
    result = {**receipt, 'program': candidate.as_dict()}
    case('hia-apply-edit', [document, {'query': query, 'response': edit}], result)
    case('hia-apply-edit', [document, {'query': query, 'response': wire(edit).decode()}], result)
    changed = deepcopy(document)
    changed['functions'][0]['blocks'][0]['ops'][0]['attrs']['value'] = 2
    def edit_rejection(message):
        return {'diagnostics': [{'code': 'E_DRIVER', 'message': 'E_HIA_QUERY: ' + message, 'phase': 'driver'}],
                'ok': False, 'status': 'error'}

    case('hia-apply-edit', [changed, {'query': query, 'response': edit}],
         edit_rejection('stale or modified edit query'), status=2)
    case('hia-apply-edit', [document, {'query': query, 'response': {'out': []}}],
         edit_rejection('response may replace only the selected instruction fields'), status=2)

    document = loans()
    sites = [selected('reader'), selected('writer')]
    query = case('hia-prepare-edit-batch', [document, {'selections': sites}], prepare_batch(document, sites))
    overlap = {'diagnostics': [{'code': 'E_DRIVER', 'phase': 'driver',
                                'message': 'E_HIA_EDIT_BATCH: selections overlap one instruction'}],
               'ok': False, 'status': 'error'}
    case('hia-prepare-edit-batch', [document, {'selections': sites[:1] * 2}], overlap, status=2)
    response = swaps()
    candidate, receipt = apply_batch(document, query, response)
    result = {**receipt, 'program': candidate.as_dict()}
    case('hia-apply-edit-batch', [document, {'query': query, 'response': response}], result)
    query_text, response_text = wire(query, pretty=True).decode(), wire(response).decode()
    candidate, receipt = apply_batch(document, query_text, response_text)
    case('hia-apply-edit-batch', [document, {'query': query_text, 'response': response_text}],
         {**receipt, 'program': candidate.as_dict()})
    changed = deepcopy(response)
    changed['edits'][1]['changes']['args'] = ['missing']
    case('hia-apply-edit-batch', [document, {'query': query, 'response': changed}], status=2)
    for command in ('hia-prepare-edit-query', 'hia-prepare-edit-batch', 'hia-apply-edit', 'hia-apply-edit-batch'):
        case(command, b'[{},{}]invalid', status=2)
        case(command, b'', args=('unexpected',), status=64)
    for version in range(1, 9):
        source = scalar_program()
        source['schema'] = 'hepta.hia.program.v' + str(version)
        request = add_two_patch(source)
        _, receipt, impact = analyze_patch_impact(source, request)
        case('hia-impact-core-json', [source, request], {
            'schema': 'hepta.hia.impact-query.v1', 'ok': True, 'status': 'verified_unpublished',
            'patch': receipt, 'impact': impact,
        }, args=('v1',))
    source = move_program()
    append_wrapper(source, 'wrapper', 'move_bytes')
    append_wrapper(source, 'top', 'wrapper')
    isolated_program(source)
    request = patch_packet(source, patch_initial_byte(source))
    _, receipt, impact = analyze_patch_impact(source, request)
    case('hia-impact-core-json', [source, request], {
        'schema': 'hepta.hia.impact-query.v1', 'ok': True, 'status': 'verified_unpublished',
        'patch': receipt, 'impact': impact,
    }, args=('v2',))
    stale = {**request, 'expected_sha256': '0' * 64}
    case('hia-impact-core-json', [source, stale], {
        'diagnostics': [{'code': 'E_DRIVER', 'message': 'E_HIA_EDIT: stale base snapshot', 'phase': 'driver'}],
        'ok': False, 'status': 'error',
    }, status=2, args=('v2',))
    case('hia-impact-core-json', wire([source, request]) + b'junk', status=2, args=('v2',))
    case('hia-impact-core-json', [source, request], status=64, args=('v3',))
    return passed


def check_agent_diagnostics(executable):
    from hepta.hia_agent_edit_query_native import NativeAgentEditQuery
    from hepta.hia_agent_service import HIAAgentService
    from tests.test_hia_program_composite import stored_loan_program
    from tools.hia_agent_native_qualification import Session, ToolClient, exhaustive_u8_workload

    query = NativeAgentEditQuery(SimpleNamespace(raw=executable.read_bytes()))
    passed = 0
    with tempfile.TemporaryDirectory(prefix='hia-query-agent-') as directory:
        service = HIAAgentService(Path(directory) / 'state')
        try:
            session = Session(ToolClient(service.call))
            session.freeze(exhaustive_u8_workload())
            for document in (scalar_program(), stored_loan_program()):
                program = session.artifact(document)
                args = session.arguments(mutable=False, program=program, view='dependencies')
                fn = service._program(program).as_dict()['functions'][0]
                block = next(row for row in fn['blocks'] if row['id'] == fn['entry'])
                output = next(operation['out'][0]['name'] for operation in block['ops'] if operation['out'])
                site = {'function': fn['name'], 'block': block['id'], 'output': output}
                candidates = [site, *(site | {field: 'unlisted'} for field in site)]
                for index, selector in enumerate(candidates):
                    arguments = args | {'selector': selector}
                    expected = service.call('hia_inspect', arguments)
                    assert expected['status'] == ('rejected' if index else 'completed'), expected
                    with (patch.object(service, '_native_edit_query', query),
                          patch('hepta.hia_edit_query.prepare_edit',
                                side_effect=AssertionError('host query diagnostics entered'))):
                        actual = service.call('hia_inspect', arguments)
                    assert actual == expected, (actual, expected)
                    passed += 1
        finally:
            service.close()
    return passed


def check_object_builds(release):
    from hepta.hia_program import verify_program
    from hepta.hia_program_native import build_program_machine
    from tests.test_hia_composite_constructor_native import simple
    from tests.test_hia_composite_returned_loans import pair_program

    executable = release / 'hia'
    launcher = (release / 'hia-build-object').read_bytes()
    marker = b'HIAECP01'
    assert launcher.count(marker) == 1
    offset = launcher.index(marker) + len(marker)
    expanded_size, = struct.unpack_from('<Q', launcher, offset)
    offset += 8
    expanded = bytearray()
    while offset < len(launcher):
        stored_size, decoded_size = struct.unpack_from('<2Q', launcher, offset)
        offset += 16
        assert 0 < decoded_size <= 512 * 1024
        assert 0 < stored_size <= len(launcher) - offset
        decoder = zlib.decompressobj(wbits=-15)
        decoded = decoder.decompress(launcher[offset:offset + stored_size], decoded_size + 1)
        assert len(decoded) == decoded_size and decoder.eof and not decoder.unused_data
        expanded.extend(decoded)
        offset += stored_size
    assert len(expanded) == expanded_size and expanded.startswith(b'\x7fELF')
    implementation = sha256(expanded).hexdigest()
    documents = [scalar_program(), *(simple(version=v) for v in range(1, 5)), pair_program()]
    with tempfile.TemporaryDirectory(prefix='hia-public-object-') as directory:
        folder = Path(directory)

        def build(source, destination):
            return subprocess.run(
                [executable, 'build', source, '-o', destination], capture_output=True,
                env={'PATH': ''}, check=False, timeout=30)

        for index, document in enumerate(documents):
            source = folder / f'{index}.hepta'
            source.write_bytes(wire(document))
            expected = verify_program(document)
            reference = folder / f'{index}-reference.o'
            build_program_machine(expected, reference, kind='object')
            output = folder / f'{index}.o'
            result = build(source, output)
            assert result.returncode == 0 and not result.stderr, result
            report = json.loads(result.stdout)
            artifact = output.read_bytes()
            assert artifact == reference.read_bytes()
            assert report['core_sha256'] == expected.sha256
            assert report['input_sha256'] == expected.input_sha256
            assert report['implementation_sha256'] == implementation
            assert report['artifact_sha256'] == sha256(artifact).hexdigest()
            assert build(source, output).returncode != 0
            assert output.read_bytes() == artifact

        invalid = pair_program()
        invalid['functions'][-1]['entry'] = 'absent'
        source.write_bytes(wire(invalid))
        refused = folder / 'refused.o'
        result = build(source, refused)
        assert result.returncode == 2 and not refused.exists(), result
        source.write_bytes(wire(pair_program()))
        link = folder / 'source-link.hepta'
        link.symlink_to(source)
        result = build(link, refused)
        assert result.returncode != 0 and not refused.exists(), result
    return 2 * len(documents) + 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    args = parser.parse_args()
    print(f'{check_release(args.release)} installed native Core edit and impact comparisons passed')
    print(f'{check_object_builds(args.release)} installed native object build comparisons passed')
    print(f'{check_agent_diagnostics(args.release / "hia-prepare-edit-query")} installed Agent query comparisons passed')
