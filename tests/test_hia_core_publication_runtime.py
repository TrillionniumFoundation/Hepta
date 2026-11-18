"""Check the eight native Core file publication routes against ordinary hia."""

import argparse
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import stat
import subprocess
import tempfile

from hepta.cli import _reference_hia_main
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_edit_batch import prepare_batch
from hepta.hia_edit_query import prepare_edit
from tests.test_hia_core_edit_runtime import wire
from tests.test_hia_edit_batch import selected
from tests.test_hia_program_tools import add_two_patch, scalar_program


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
    for name, action, input_path, arguments, raw, native_options in cases:
        reference = directory / 'reference' / name / 'target'
        target = directory / 'native' / name / 'target'
        report = StringIO()
        with redirect_stdout(report):
            status = _reference_hia_main([action, input_path, *arguments, '--output', str(reference)])
        assert status == 0, (action, report.getvalue())
        expected = json.loads(report.getvalue())
        published = expected if 'output' in expected else expected['publication']
        published['output'] = str(target)
        command = [release / ('hia-publish-' + name), *native_options, target]
        result = subprocess.run(command, input=raw, capture_output=True, env={'PATH': ''},
                                timeout=20, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (0, wire(expected, pretty=True), b''), (
            action, result.returncode, result.stdout, result.stderr)
        assert target.read_bytes() == reference.read_bytes(), action
        actual_stat, reference_stat = target.lstat(), reference.lstat()
        assert (actual_stat.st_mode, actual_stat.st_uid, actual_stat.st_nlink) == (
            reference_stat.st_mode, reference_stat.st_uid, 1), action
        assert stat.S_ISREG(actual_stat.st_mode) and list(target.parent.iterdir()) == [target], action

        replay = subprocess.run(command, input=raw, capture_output=True, env={'PATH': ''},
                                timeout=20, check=False)
        assert replay.returncode > 0 and not replay.stdout and not replay.stderr, (action, replay)
        assert actual_stat.st_ino == target.stat().st_ino and target.read_bytes() == reference.read_bytes()
        assert list(target.parent.iterdir()) == [target], action
    assert {name: (directory / name).read_bytes() for name in inputs} == inputs
    return len(cases) * 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='hia-core-publication-runtime-') as root:
        print(f'{check_release(args.release.resolve(), Path(root))} native file publication checks passed')
