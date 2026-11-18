"""Compare the installed native Core CLI with ordinary hia."""

import argparse
from contextlib import redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import stat
import subprocess
import tempfile

from hepta.cli import HIA_AGENT_ACTIONS, _reference_hia_main
from hepta.hia_agent_assembly import diagnose_assembly, render_assembly
from hepta.hia_edit_batch import prepare_batch
from hepta.hia_edit_query import prepare_edit
from hepta.hia_program_native import build_program_machine
from hepta.hia_program_selfhost import build_program_selfhost
from tests.test_hia_core_edit_runtime import wire
from tests.test_hia_edit_batch import selected
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
        assert path.read_bytes() == raw, label
    return len(cases)


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
        result = subprocess.run([release / 'hia', 'build', path, *options, '--output', target],
                                cwd=directory, input=b'ignored', capture_output=True, env={'PATH': ''},
                                timeout=35, check=False)
        assert (result.returncode, result.stderr) == (2 if error else 64, b''), label
        if error:
            diagnostic, = json.loads(result.stdout)['diagnostics']
            assert diagnostic['code'] == 'E_DRIVER' and diagnostic['message'].startswith(error + ':'), label
        else:
            assert result.stdout == b'', label
        assert not target.exists(), label
    assert source.read_bytes() == dashed.read_bytes() == raw
    assert sha256(manifest.read_bytes()).hexdigest() == manifest_pin
    return len(cases) + len(negative)


def check_release(release, directory):
    program = scalar_program()
    program['schema'] = 'hepta.hia.program.v8'
    program_wire = wire(program)
    assembly = render_assembly(program).encode()
    request = add_two_patch(program)
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
                           for _, action, input_path, arguments, _, _ in cases}
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
            receipt['implementation_sha256'] = sha256((release / 'hia-build-object').read_bytes()).hexdigest()
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
        for executable, payload in ((command, b'ignored stdin'), (
                [release / ('hia-publish-' + name), *native_options, directory / 'raw' / name], raw)):
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
        assert replay.returncode > 0 and not replay.stdout and not replay.stderr, (action, replay)
        assert actual_stat.st_ino == target.stat().st_ino and target.read_bytes() == reference.read_bytes()
        assert list(target.parent.iterdir()) == [target], action
    assert {name: (directory / name).read_bytes() for name in inputs} == inputs
    diagnostics = directory / 'diagnostics'
    diagnostics.mkdir()
    selfhost = directory / 'selfhost'
    selfhost.mkdir()
    return (len(cases) * 3 + checked_actions + check_assembly_rejections(release, diagnostics)
            + check_selected_selfhost(release, selfhost))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='hia-core-publication-runtime-') as root:
        print(f'{check_release(args.release.resolve(), Path(root))} native CLI, publication and diagnostic checks passed')
