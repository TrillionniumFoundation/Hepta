"""Compare the installed native Core CLI with ordinary hia."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from hepta.cli import HIA_AGENT_ACTIONS, _reference_hia_main
from hepta.hia_agent_assembly import diagnose_assembly, render_assembly
from hepta.hia_edit_batch import prepare_batch
from hepta.hia_edit_query import prepare_edit
from hepta.hia_program import verify_program
from hepta.hia_program_native import build_program_machine
from hepta.hia_program_selfhost import build_program_selfhost
from tests.test_hia_core_edit_runtime import (
    nominal_query_fixtures, packed_implementation_sha256, wire,
)
from tests.test_hia_edit_batch import loans, selected, swaps
from tests.test_hia_program_tools import add_two_patch, scalar_program


def reference_cli(arguments):
    report = StringIO()
    with redirect_stdout(report):
        try:
            status = _reference_hia_main(arguments)
        except SystemExit as error:
            status = error.code
    assert status == 0, (arguments[0], report.getvalue())
    return report.getvalue().encode()


def check_assembly_rejections(release, directory):
    header = 'hia-asm.v1 hepta.hia.program.v8 m\n'
    function = 'fn f() -> () effects() entry(b)\n'
    body = header + function + 'block b()\n'
    node_payload = ','.join(['0'] * 2046)
    large_body = ('_ = opaque() {"payload":[' + node_payload + ']}\n') * 128
    cases = {
        'utf8': b'\xff',
        'bom': b'\xef\xbb\xbf',
        'bare-cr': b'one\rtwo',
        'line-count': b'\n' * 16384,
        'line-bytes': b'x' * 16385,
        'source-bytes': b'x' * 1048577,
        'empty': b'',
        'header': b'not assembly',
        'unterminated': (header + function).encode(),
        'empty-list': (body + 'ret(a,)\n').encode(),
        'malformed-attributes': (body + 'x:u32 = const() []\n').encode(),
        'invalid-instruction': (body + 'not an instruction\n').encode(),
        'no-functions': header.encode(),
        'unknown-opcode': (body + '_ = opaque()\nret()\nend\n').encode(),
        'undefined': (body + 'ret(undefined)\nend\n').encode(),
        'constant-type': (body + 'y:bool = const() {"value":1}\nret()\nend\n').encode(),
        'node-budget': (body + large_body + 'ret()\nend\n').encode(),
    }
    for label, raw in cases.items():
        path = directory / (label + '.hepta')
        path.write_bytes(raw)
        expected = wire(diagnose_assembly(raw), pretty=True)
        result = subprocess.run([release / 'hia', 'check-assembly', path], input=b'ignored stdin',
                                capture_output=True, env={'PATH': ''}, timeout=20, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (1, expected, b''), (
            label, result.returncode, result.stdout, result.stderr)
        target = directory / (label + '-output') / 'program.hepta'
        for output in ([], ['-o', str(target)]):
            arguments = ['import-assembly', str(path), *output]
            reference_stdout = StringIO()
            reference_stderr = StringIO()
            with redirect_stdout(reference_stdout), redirect_stderr(reference_stderr):
                reference_status = _reference_hia_main(arguments)
            assert reference_status == 2, label
            result = subprocess.run([release / 'hia', *arguments], input=b'ignored stdin',
                                    capture_output=True, env={'PATH': ''}, timeout=20, check=False)
            assert (result.returncode, result.stdout, result.stderr) == (
                reference_status, reference_stdout.getvalue().encode(),
                reference_stderr.getvalue().encode()), (label, output, result.returncode, result.stdout, result.stderr)
            assert not target.parent.exists(), label
        assert path.read_bytes() == raw, label
    return len(cases) * 3


def check_import_existing_destinations(release, source, directory):
    ordinary = directory / 'ordinary'
    ordinary.write_bytes(b'retained original')
    folder = directory / 'folder'
    folder.mkdir()
    link = directory / 'link'
    link.symlink_to(ordinary)
    missing = directory / 'missing'
    dangling = directory / 'dangling'
    dangling.symlink_to(missing)
    fifo = directory / 'fifo'
    os.mkfifo(fifo)
    targets = (ordinary, folder, link, dangling, fifo)

    def identity(path):
        info = path.lstat()
        return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    before = [identity(path) for path in targets]
    for target in targets:
        args = ['import-assembly', source, '-o', str(target)]
        reference_stdout = StringIO()
        with redirect_stdout(reference_stdout):
            code = _reference_hia_main(args)
        assert code == 2, target
        result = subprocess.run([release / 'hia', *args], capture_output=True,
                                env={'PATH': ''}, timeout=20, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (
            code, reference_stdout.getvalue().encode(), b''), (target, result)
    assert [identity(path) for path in targets] == before
    assert ordinary.read_bytes() == b'retained original' and not missing.exists()
    assert set(directory.iterdir()) == set(targets)
    return len(targets)


def check_selected_selfhost(release, directory):
    manifest = release / 'compiler-manifest.json'
    manifest_pin = sha256(manifest.read_bytes()).hexdigest()
    selector = ['--selfhost-manifest', str(manifest), '--selfhost-manifest-sha256', manifest_pin]
    program = scalar_program()
    program['schema'] = 'hepta.hia.program.v8'
    source = directory / 'program.hepta'
    raw = wire(program)
    source.write_bytes(raw)
    dashed = directory / '-program.hepta'
    dashed.write_bytes(raw)
    reference = directory / 'reference.o'
    expected = build_program_selfhost(raw, reference, manifest=manifest, manifest_sha256=manifest_pin)
    expected['claims']['hosted_cli_and_publication'] = False
    switch = ['--backend', 'selfhost', *selector]
    cases = (
        ('absolute', [str(source), *switch, '--output', str(directory / 'absolute.o')]),
        ('relative', [source.name, *switch, '--output', './relative.o']),
        ('attached', ['--backend=selfhost', '--kind=object', '--target=x86_64-unknown-linux-gnu',
                      f'--selfhost-manifest={manifest}', f'--selfhost-manifest-sha256={manifest_pin}',
                      '-oattached.o', source.name]),
        ('separator', [*switch, '--output', 'separator.o', '--', dashed.name]),
    )
    for label, arguments in cases:
        result = subprocess.run([release / 'hia', 'build', *arguments], cwd=directory,
                                input=b'unrelated stdin', capture_output=True, env={'PATH': ''},
                                timeout=35, check=False)
        assert (result.returncode, result.stderr) == (0, b''), (
            label, result.returncode, result.stdout, result.stderr)
        target = directory / (label + '.o')
        assert target.read_bytes() == reference.read_bytes(), label
        actual = json.loads(result.stdout)
        expected['output'] = str(target)
        expected['capture']['wall_seconds'] = actual['capture']['wall_seconds']
        assert 0 <= expected['capture']['wall_seconds'] <= 30, label
        assert (len(actual), result.stdout) == (23, wire(expected, pretty=True)), label
    wrong_schema = directory / 'not-v8.hepta'
    wrong_schema.write_bytes(wire({**program, 'schema': 'hepta.hia.program.v7'}))
    negative = (
        ('pin', source, ['--backend=selfhost', *selector[:-1], '0' * 64], 'E_HIA_SELFHOST_PIN'),
        ('profile', wrong_schema, switch, 'E_HIA_SELFHOST_PROFILE'),
        ('missing-pin', source, ['--backend=selfhost', *selector[:2]], None),
        ('native-with-pin', source, ['--backend=native', *selector], None),
    )
    for label, path, options, error in negative:
        target = directory / (label + '.o')
        arguments = ['build', path, *options, '--output', target]
        environment = {'PATH': '', 'LC_ALL': 'C.UTF-8', 'NO_COLOR': '1'}
        result = subprocess.run([release / 'hia', *arguments],
                                cwd=directory, input=b'ignored', capture_output=True, env=environment,
                                timeout=35, check=False)
        if error:
            assert (result.returncode, result.stderr) == (2, b''), label
            diagnostic, = json.loads(result.stdout)['diagnostics']
            assert diagnostic['code'] == 'E_DRIVER' and diagnostic['message'].startswith(error + ':'), label
        else:
            reference_env = {**environment, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
            reference = subprocess.run(
                [sys.executable, '-c',
                 'from hepta.cli import _reference_hia_main; raise SystemExit(_reference_hia_main())', *arguments],
                cwd=directory, capture_output=True, env=reference_env, timeout=10, check=False)
            assert reference.returncode == 2 and not reference.stdout and reference.stderr
            assert (result.returncode, result.stdout, result.stderr) == (
                reference.returncode, reference.stdout, reference.stderr), label
        assert not target.exists(), label
    assert source.read_bytes() == dashed.read_bytes() == raw
    assert sha256(manifest.read_bytes()).hexdigest() == manifest_pin
    return len(cases) + len(negative)


def check_batch_apply_refusals(release, directory):
    program = loans()
    query = prepare_batch(program, [selected('reader'), selected('writer')])
    response = swaps()
    site = query['sites'][0]
    first, second = response['edits']
    cases = (
        ('scalar query', True, response),
        ('unknown schema', {**query, 'schema': 'hepta.hia.edit-batch-query.v1'}, response),
        ('wrong sites type', {**query, 'sites': None}, response),
        ('empty sites', {**query, 'sites': []}, response),
        ('malformed site', {**query, 'sites': [False]}, response),
        ('site identity type', {**query, 'sites': [{**site, 'site': False}]}, response),
        ('nested query type', {**query, 'sites': [{**site, 'query': []}]}, response),
        ('missing nested selector', {**query, 'sites': [{**site, 'query': {}}]}, response),
        ('stale digest', {**query, 'base_sha256': '0' * 64}, response),
        ('null response', query, None),
        ('wrong response key', query, {'alternate': []}),
        ('response site count', query, {'edits': [first]}),
        ('extra edit key', query, {'edits': [{**first, 'extra': True}, second]}),
        ('duplicate response site', query, {'edits': [first, first]}),
        ('invalid response site', query, {'edits': [{**first, 'site': False}, second]}),
        ('unselected changes', query, {'edits': [{**first, 'changes': {'op': 'owner.move'}}, second]}),
    )
    original, request, reply = (directory / name for name in ('source.hepta', 'query.json', 'response.json'))
    original.write_bytes(wire(program))
    target = directory / 'unpublished' / 'target.hepta'
    for label, query_input, response_input in cases:
        request.write_bytes(wire(query_input))
        reply.write_bytes(wire(response_input))
        arguments = ['edit-batch-apply', str(original), '--query', str(request), '--response', str(reply)]
        for options in ([], ['-o', str(target)]):
            reference = StringIO()
            with redirect_stdout(reference):
                code = _reference_hia_main([*arguments, *options])
            result = subprocess.run([release / 'hia', *arguments, *options], input=b'ignored',
                                    capture_output=True, env={'PATH': ''}, timeout=20, check=False)
            assert (code, result.returncode, result.stdout, result.stderr) == (
                2, 2, reference.getvalue().encode(), b''), (label, options, result)
            assert not target.parent.exists(), (label, options)
    assert original.read_bytes() == wire(program)
    return len(cases) * 2


def check_nominal_queries(release, directory):
    passed = 0
    for index, (document, site, query) in enumerate(nominal_query_fixtures()):
        source = directory / f'{index}.hepta'
        source.write_bytes(wire(document, pretty=True))
        arguments = ['edit-query', str(source), '--function', site['function'],
                     '--block', site['block'], '--value', site['output'],
                     '--fields', ','.join(site['fields'])]
        executable = release / 'hia'
        result = subprocess.run([executable, *arguments], capture_output=True,
                                env={'PATH': ''}, timeout=20, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (
            0, wire(query, pretty=True), b''), result

        reference = directory / f'reference-{index}.json'
        expected = json.loads(reference_cli([*arguments, '-o', str(reference)]))
        target = directory / f'native-{index}.json'
        expected['output'] = str(target)
        command = [executable, *arguments, '-o', target]
        result = subprocess.run(command, capture_output=True, env={'PATH': ''}, timeout=20)
        assert (result.returncode, result.stdout, result.stderr) == (
            0, wire(expected, pretty=True), b''), result
        assert target.read_bytes() == reference.read_bytes()
        pinned = target.stat()
        replay = subprocess.run(command, capture_output=True, env={'PATH': ''}, timeout=20)
        assert replay.returncode != 0 and not replay.stdout and not replay.stderr, replay
        assert target.stat().st_ino == pinned.st_ino and target.read_bytes() == reference.read_bytes()
        passed += 3
    return passed


def check_nominal_batch_queries(release, directory):
    passed = 0
    for index, (document, site, single_query) in enumerate(nominal_query_fixtures()):
        source = directory / f'{index}.hepta'
        source.write_bytes(wire(document, pretty=True))
        request = directory / f'{index}.json'
        request.write_bytes(wire([site]))
        arguments = ['edit-batch-query', str(source), '--selections', str(request)]
        executable = release / 'hia'
        result = subprocess.run([executable, *arguments], capture_output=True,
                                env={'PATH': ''}, timeout=20)
        expected = prepare_batch(document, [site])
        assert (result.returncode, result.stdout, result.stderr) == (0, wire(expected, pretty=True), b''), result
        assert expected['input_sha256'] == single_query['input_sha256'] != expected['base_sha256']
        assert expected['sites'][0]['query']['input_sha256'] == expected['input_sha256']

        reference = directory / f'{index}.reference'
        target = directory / f'{index}.target'
        receipt = json.loads(reference_cli([*arguments, '-o', str(reference)]))
        receipt['output'] = str(target)
        command = [executable, *arguments, '-o', target]
        result = subprocess.run(command, capture_output=True, env={'PATH': ''}, timeout=20)
        assert (result.returncode, result.stdout, result.stderr) == (0, wire(receipt, pretty=True), b''), result
        assert target.read_bytes() == reference.read_bytes()
        pinned = target.stat()
        replay = subprocess.run(command, capture_output=True, env={'PATH': ''}, timeout=20)
        assert replay.returncode != 0 and not replay.stdout and not replay.stderr, replay
        assert target.stat().st_ino == pinned.st_ino and target.read_bytes() == reference.read_bytes()

        request.write_bytes(wire([site, site]))
        absent = directory / f'{index}.absent'
        report = StringIO()
        with redirect_stdout(report):
            status = _reference_hia_main(arguments)
        for options in ([], ['-o', str(absent)]):
            refusal = subprocess.run([executable, *arguments, *options], capture_output=True,
                                     env={'PATH': ''}, timeout=20)
            assert (status, refusal.returncode, refusal.stdout, refusal.stderr) == (
                2, 2, report.getvalue().encode(), b''), refusal
            assert not absent.exists()
        passed += 5
    return passed


def check_nominal_patches(release, directory):
    passed = 0
    for index, (document, _, query) in enumerate(nominal_query_fixtures()):
        source = directory / f'{index}.hepta'
        source.write_bytes(wire(document, pretty=True))
        verified = verify_program(document)
        function, block, offset, operation = next(
            (function, block, offset, operation)
            for function in verified.as_dict()['functions']
            for block in function['blocks']
            for offset, operation in enumerate(block['ops'])
            if operation['op'] == 'const' and type(operation['attrs']['value']) is int
        )
        replacement = {**operation, 'attrs': {**operation['attrs'], 'value': operation['attrs']['value'] + 1}}
        for version in (1, 2):
            name = f'{index}-v{version}'
            request = {'schema': f'hepta.hia.patch.v{version}', 'expected_sha256': verified.sha256,
                       'edits': [{'action': 'replace_operation', 'function': function['name'],
                                  'block': block['id'], 'index': offset, 'operation': replacement}]}
            if version == 2:
                request['interface_policy'] = 'preserve'
            patch = directory / f'{name}.json'
            patch.write_bytes(wire(request, pretty=True))
            reference = directory / f'{name}.reference'
            target = directory / f'{name}.target'
            for action, publish in (('patch', False), ('impact', False), ('patch', True)):
                arguments = [action, str(source), '--request', str(patch)]
                expected = reference_cli([*arguments, '-o', str(reference)] if publish else arguments)
                if publish:
                    receipt = json.loads(expected)
                    receipt['publication']['output'] = str(target)
                    expected = wire(receipt, pretty=True)
                    arguments.extend(('-o', str(target)))
                result = subprocess.run([release / 'hia', *arguments], capture_output=True,
                                        env={'PATH': ''}, timeout=20)
                assert (result.returncode, result.stdout, result.stderr) == (0, expected, b''), result
                if publish:
                    assert target.read_bytes() == reference.read_bytes()
                passed += 1

            patch.write_bytes(wire({**request, 'expected_sha256': query['input_sha256']}))
            absent = directory / f'{name}.absent'
            for arguments in (['patch'], ['impact'], ['patch', '-o', str(absent)]):
                action, *options = arguments
                result = subprocess.run([release / 'hia', action, source, '--request', patch, *options],
                                        capture_output=True, env={'PATH': ''}, timeout=20)
                assert result.returncode == 2 and not result.stderr and not absent.exists(), result
                passed += 1
    return passed


def check_release(release, directory):
    program = scalar_program()
    program['schema'] = 'hepta.hia.program.v8'
    program_wire = wire(program)
    assembly = render_assembly(program).encode()
    request = add_two_patch(program)
    request_v2 = {**request, 'schema': 'hepta.hia.patch.v2', 'interface_policy': 'preserve'}
    site = selected('one', 'attrs', 'increment')
    query = prepare_edit(program, **site)
    batch_query = prepare_batch(program, [site])
    edit = {'attrs': {'value': 2}}
    batch_response = {'edits': [{'site': 0, 'changes': edit}]}

    def saved(name, value):
        path = directory / name
        path.write_bytes(value if type(value) is bytes else wire(value))
        return str(path)

    source = saved('source.hepta', program_wire)
    assembly_source = saved('assembly.hepta', assembly)
    request_file = saved('patch.json', request)
    request_v2_file = saved('patch-v2.json', request_v2)
    query_file = saved('query.json', query)
    edit_file = saved('edit.json', edit)
    selections_file = saved('selections.json', [site])
    batch_query_file = saved('batch-query.json', batch_query)
    batch_response_file = saved('batch-edit.json', batch_response)
    inputs = {path.name: path.read_bytes() for path in directory.iterdir()}
    cases = (
        ('program', 'normalize', source, (), program_wire, ()),
        ('import', 'import-assembly', assembly_source, (), assembly, ()),
        ('assembly', 'render-assembly', source, (), program_wire, ()),
        ('patch', 'patch', source, ('--request', request_file), wire([program, request]), ('v1',)),
        ('patch-v2', 'patch', source, ('--request', request_v2_file), wire([program, request_v2]), ('v2',)),
        ('edit', 'edit-apply', source, ('--query', query_file, '--response', edit_file),
         wire([program, {'query': query, 'response': wire(edit).decode()}]), ()),
        ('query', 'edit-query', source, ('--function', 'increment', '--block', 'entry',
                                        '--value', 'one', '--fields', 'attrs'),
         wire([program, site]), ()),
        ('batch-query', 'edit-batch-query', source, ('--selections', selections_file),
         wire([program, {'selections': [site]}]), ()),
        ('batch', 'edit-batch-apply', source, ('--query', batch_query_file, '--response', batch_response_file),
         wire([program, {'query': wire(batch_query).decode(), 'response': wire(batch_response).decode()}]), ()),
    )
    arguments_by_action = {action: [input_path, *arguments]
                           for name, action, input_path, arguments, _, _ in cases if name != 'patch-v2'}
    arguments_by_action.update(
        capabilities=[], catalog=[], verify=[source], inspect=[source],
        impact=[source, '--request', request_file], build=[source],
    )
    arguments_by_action['check-assembly'] = [assembly_source]
    assert set(arguments_by_action) == set(HIA_AGENT_ACTIONS)
    build_target = directory / 'native-build' / 'target.o'
    build_target.parent.mkdir()
    checked_actions = 0
    for action, arguments in arguments_by_action.items():
        if action == 'build':
            original = directory / 'reference-build' / 'target.o'
            original.parent.mkdir()
            receipt = build_program_machine(program, original, kind='object')
            receipt['output'] = str(build_target)
            receipt['implementation_sha256'] = packed_implementation_sha256(release / 'hia-build-object')
            expected = wire(receipt, pretty=True)
            arguments += ['--output', str(build_target)]
        else:
            expected = reference_cli([action, *arguments])
        normal = subprocess.run([release / 'hia', action, *arguments], input=b'ignored stdin',
                                capture_output=True, env={'PATH': ''}, timeout=20, check=False)
        assert (normal.returncode, normal.stdout, normal.stderr) == (0, expected, b''), (
            action, normal.returncode, normal.stdout, normal.stderr)
        if action == 'build':
            assert build_target.read_bytes() == original.read_bytes()
        checked_actions += 1
    for action in ('patch', 'impact'):
        arguments = [action, source, '--request', request_v2_file]
        result = subprocess.run([release / 'hia', *arguments], input=b'ignored',
                                capture_output=True, env={'PATH': ''}, timeout=20, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (0, reference_cli(arguments), b''), (
            action, result.returncode, result.stdout, result.stderr)
        checked_actions += 1
    for flag in ('--help', '--version'):
        result = subprocess.run([release / 'hia', flag], input=b'', capture_output=True,
                                env={'PATH': ''}, timeout=20, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (0, reference_cli([flag]), b''), flag
        checked_actions += 1

    for name, action, input_path, arguments, raw, native_options in cases:
        reference = directory / 'reference' / name / 'target'
        target = directory / 'native' / name / 'target'
        command_args = [action, input_path, *arguments, '--output']
        expected = json.loads(reference_cli([*command_args, str(reference)]))
        published = expected if 'output' in expected else expected['publication']
        published['output'] = str(target)
        command = [release / 'hia', *command_args, target]
        raw_name = 'patch' if name == 'patch-v2' else name
        raw_command = ([release / 'hia-import-assembly', '--publish'] if name == 'import'
                       else [release / ('hia-publish-' + raw_name), *native_options])
        for executable, payload in ((command, b'ignored stdin'),
                                    ([*raw_command, directory / 'raw' / name], raw)):
            published['output'] = str(executable[-1])
            result = subprocess.run(executable, input=payload, capture_output=True, env={'PATH': ''},
                                    timeout=20, check=False)
            assert (result.returncode, result.stdout, result.stderr) == (0, wire(expected, pretty=True), b''), (
                action, result.returncode, result.stdout, result.stderr)
            assert Path(executable[-1]).read_bytes() == reference.read_bytes(), action
        assert target.read_bytes() == reference.read_bytes(), action
        actual_stat, reference_stat = target.lstat(), reference.lstat()
        assert (actual_stat.st_mode, actual_stat.st_uid, actual_stat.st_nlink) == (
            reference_stat.st_mode, reference_stat.st_uid, 1), action
        assert stat.S_ISREG(actual_stat.st_mode) and list(target.parent.iterdir()) == [target], action

        replay = subprocess.run(command, input=b'ignored stdin', capture_output=True, env={'PATH': ''},
                                timeout=20, check=False)
        if name in {'import', 'assembly'}:
            refusal = StringIO()
            with redirect_stdout(refusal):
                code = _reference_hia_main([*command_args, str(target)])
            assert (replay.returncode, replay.stdout, replay.stderr) == (
                code, refusal.getvalue().encode(), b''), (action, replay)
        else:
            assert replay.returncode > 0 and not replay.stdout and not replay.stderr, (action, replay)
        assert actual_stat.st_ino == target.stat().st_ino and target.read_bytes() == reference.read_bytes()
        assert list(target.parent.iterdir()) == [target], action
    assert {name: (directory / name).read_bytes() for name in inputs} == inputs
    diagnostics = directory / 'diagnostics'
    diagnostics.mkdir()
    selfhost = directory / 'selfhost'
    selfhost.mkdir()
    destinations = directory / 'destinations'
    destinations.mkdir()
    batch = directory / 'batch-refusals'
    batch.mkdir()
    nominal = directory / 'nominal-queries'
    nominal.mkdir()
    nominal_batch = directory / 'nominal-batch-queries'
    nominal_batch.mkdir()
    patches = directory / 'nominal-patches'
    patches.mkdir()
    return (len(cases) * 3 + checked_actions + check_assembly_rejections(release, diagnostics)
            + check_nominal_queries(release, nominal) + check_nominal_patches(release, patches)
            + check_nominal_batch_queries(release, nominal_batch)
            + check_import_existing_destinations(release, assembly_source, destinations)
            + check_selected_selfhost(release, selfhost) + check_batch_apply_refusals(release, batch))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='hia-core-publication-runtime-') as root:
        print(f'{check_release(args.release.resolve(), Path(root))} native CLI, publication and diagnostic checks passed')
