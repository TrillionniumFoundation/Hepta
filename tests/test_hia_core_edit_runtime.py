"""Compare the four installed native edit commands with the ordinary APIs."""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import subprocess

from hepta.hia_edit_batch import apply_batch, prepare_batch
from hepta.hia_edit_query import apply_edit, prepare_edit
from tests.test_hia_edit_batch import loans, selected, swaps
from tests.test_hia_edit_query import fixture
from tests.test_hia_program_tools import scalar_program


def wire(value, *, pretty=False):
    formatting = {'sort_keys': True, 'indent': 2} if pretty else {'separators': (',', ':')}
    return (json.dumps(value, ensure_ascii=False, **formatting) + ('\n' if pretty else '')).encode()


def check_release(release):
    passed = 0

    def case(command, payload, expected=None, *, status=0, args=()):
        nonlocal passed
        raw = payload if type(payload) is bytes else wire(payload)
        run = subprocess.run([release / command, *args], input=raw, capture_output=True,
                             env={'PATH': ''}, timeout=20, check=False)
        output = b'' if status else wire(expected, pretty=True)
        if (run.returncode, run.stdout, run.stderr) != (status, output, b''):
            raise AssertionError((command, status, run.returncode, run.stdout[:200], run.stderr))
        passed += 1
        return json.loads(run.stdout) if not status else None

    for version in range(1, 9):
        document = scalar_program()
        document['schema'] = 'hepta.hia.program.v' + str(version)
        site = selected('answer', 'attrs', 'increment')
        case('hia-prepare-edit-query', [document, site], prepare_edit(document, **site))

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
    case('hia-apply-edit', [changed, {'query': query, 'response': edit}], status=2)
    case('hia-apply-edit', [document, {'query': query, 'response': {'out': []}}], status=2)

    document = loans()
    sites = [selected('reader'), selected('writer')]
    query = case('hia-prepare-edit-batch', [document, {'selections': sites}], prepare_batch(document, sites))
    case('hia-prepare-edit-batch', [document, {'selections': sites[:1] * 2}], status=2)
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
    return passed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    args = parser.parse_args()
    print(f'{check_release(args.release)} installed native Core edit comparisons passed')
