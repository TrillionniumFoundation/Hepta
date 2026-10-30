"""Prepare one additive docs/evidence delivery; preserve the tested source ref."""
from pathlib import Path
import ast
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'hia-github-publication-20261030'
REPO = ROOT / 'hepta-integration'
BASE = '953fa62dee5aa563551d57b1374ab95b6d548b45'
TARGET = 'delivery/hia-p0-p7-953fa62-20261030'
sys.path.insert(0, str(HERE))
from prepare_exact_transfer import prepare


def main():
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=REPO)
    head = git('rev-parse', 'HEAD').decode().strip()
    if head == BASE:
        raise ValueError('delivery has not been committed')
    rows = git('diff', '--name-status', BASE, head).decode().splitlines()
    if not rows:
        raise ValueError('empty delivery')
    for row in rows:
        status, name = row.split('\t')
        if status != 'A' or not (name.startswith('evidence/hia_next2_') or
                name == 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md'):
            raise ValueError('delivery must only add registered inert documentation/evidence')
    if git('rev-list', '--count', head, '^' + BASE).decode().strip() != '1':
        raise ValueError('exactly one docs/evidence child expected')
    summary = prepare(BASE, head)
    short = head[:7]
    for prefix in ('TRANSFER', 'REMOTE-MANIFEST'):
        path = HERE / f'{prefix}-{short}.json'
        value = json.loads(path.read_bytes())
        value.update(target_branch=TARGET,
            transfer_scope='additive docs/evidence-only child; tested implementation branch remains at registered base',
            request_qualification=False)
        path.write_text(json.dumps(value, indent=2) + '\n')
    path = HERE / f'restore-{short}.py'
    source = path.read_text()
    anchor = 'BRANCH = "work/hia-p0-p7-integrated-20261030"'
    if source.count(anchor) != 1:
        raise ValueError('unexpected target constant')
    source = source.replace(anchor, 'BRANCH = ' + repr(TARGET))
    anchor = '        target = "refs/heads/" + BRANCH\n'
    if source.count(anchor) != 1:
        raise ValueError('unexpected publication anchor')
    source = source.replace(anchor,
        '        source_ref = "refs/heads/work/hia-p0-p7-integrated-20261030"\n'
        '        source_before = git("ls-remote", "--heads", "origin", source_ref)\n'
        '        receipt["tested_implementation_ref_before"] = source_before\n'
        '        if not source_before or source_before.split()[0] != BASES[0]:\n'
        '            raise ValueError("Tested implementation ref changed before evidence publication")\n' + anchor)
    start = source.index('        # GITHUB_TOKEN pushes do not recursively trigger ordinary push jobs.')
    end = source.index('    except BaseException as error:', start)
    source = source[:start] + (
        '        # This child adds inert evidence and documentation only.\n'
        '        # The completed qualification remains pinned to BASES[0].\n'
        '        receipt["qualification_dispatch_intentionally_not_requested"] = True\n'
        '        source_after = git("ls-remote", "--heads", "origin", source_ref)\n'
        '        receipt["tested_implementation_ref_after"] = source_after\n'
        '        if not source_after or source_after.split()[0] != BASES[0]:\n'
        '            raise ValueError("Tested implementation ref changed after evidence publication")\n'
    ) + source[end:]
    source = source.replace('import urllib.request\n', '')
    ast.parse(source)
    if 'HEPTA_TRANSFER_ACTIONS_TOKEN' in source or '/dispatches' in source:
        raise ValueError('unexpected workflow dispatch code')
    path.write_text(source)
    workflow_path = HERE / f'hepta-object-transfer-{short}.yml'
    workflow = workflow_path.read_text()
    workflow = workflow.replace('name: Restore authorized original HIA integration commits',
                                'name: Publish authorized HIA evidence delivery')
    workflow = workflow.replace('  actions: write\n', '')
    workflow = workflow.replace('publish exact commit and request qualification', 'publish exact evidence commit')
    workflow = workflow.replace('        env:\n          HEPTA_TRANSFER_ACTIONS_TOKEN: ${{ github.token }}\n', '')
    workflow_path.write_text(workflow)
    summary.update(target_branch=TARGET, tested_source_branch_unchanged=True,
        dispatch_requested=False, additive_files=len(rows),
        helper_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        workflow_sha256=hashlib.sha256(workflow_path.read_bytes()).hexdigest())
    with (HERE / f'PREPARE-DELIVERY-{short}.json').open('x') as output:
        json.dump(summary, output, indent=2)
        output.write('\n')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
