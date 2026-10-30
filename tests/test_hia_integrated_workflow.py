"""Check actual CI argv and shell failure/source isolation without qualification."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_integrated as integrated


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/hepta-qualification.yml'
STEP = 'Qualify all eight integrated gates from a clean exact source'


def step_lines(source, name):
    """Read this workflow's fixed step layout, not arbitrary YAML."""
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines)
              if line == '      - name: ' + name]
    if len(starts) != 1:
        raise ValueError('expected one named workflow step')
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith('      - ')), len(lines))
    return lines[start:end]


def integration_script(source):
    lines = step_lines(source, STEP)
    if lines.count('        run: |') != 1 or '        shell: bash' not in lines:
        raise ValueError('expected literal bash integration script')
    body = lines[lines.index('        run: |') + 1:]
    if any(line and not line.startswith('          ') for line in body):
        raise ValueError('invalid integration script indentation')
    return '\n'.join(line[10:] for line in body) + '\n'


def invocation(script, environment):
    statements = script.replace('\\\n', ' ').splitlines()
    commands = [line.strip() for line in statements
                if line.strip().startswith('python tools/qualify_hia_integrated.py')]
    if len(commands) != 1:
        raise ValueError('expected one actual integrated qualifier invocation')
    tokens = shlex.split(commands[0])
    if tokens[-4:] != ['2>&1', '|', 'tee', '$RUNNER_TEMP/hepta-integrated.log']:
        raise ValueError('expected retained qualification console stream')
    def bind(token):
        value = re.sub(r'\$([A-Za-z_][A-Za-z_0-9]*)',
                       lambda match: environment[match[1]], token)
        if '$' in value or '`' in value:
            raise ValueError('unsupported workflow substitution')
        return value
    return [bind(token) for token in tokens[2:-4]]


def environment(workspace, temporary, head):
    values = {'GITHUB_WORKSPACE': str(workspace), 'RUNNER_TEMP': str(temporary),
              'HEPTA_QUALIFICATION_HEAD_SHA': head,
              'RUSTC': str(workspace.parent / 'toolchains/rust-1.90.0/bin/rustc'),
              'FINITE_NDU_CARGO': str(temporary / 'finite-toolchain/bin/cargo'),
              'FINITE_NDU_RUSTC': str(temporary / 'finite-toolchain/bin/rustc'),
              'HEPTA_NDU_BRIDGE': str(temporary / 'hepta-ndu-target/debug/hia-ndu-bridge'),
              'HEPTA_NDU_BUILD': str(temporary / 'hepta-ndu-build'),
              'HEPTA_NDU_UPSTREAM': str(temporary / 'hepta-ndu-source')}
    for prefix, directory in [('HEPTA_RECURSIVE_NDU', 'recursive'),
                              ('HEPTA_FINITE_NDU', 'finite'),
                              ('HEPTA_NDU_STREAM', 'stream')]:
        build = temporary / ('hepta-' + directory + '-ndu-build')
        values[prefix + '_BRIDGE'] = str(build / 'native/hepta-hia-ndu-bridge')
        values[prefix + '_IDENTITY'] = str(build / 'identity.json')
    return values


class IntegratedWorkflowContractTests(unittest.TestCase):
    def test_actual_cli_receives_all_four_native_profiles_and_external_paths(self):
        workspace = Path('/unexecuted/source workspace')
        temporary = Path('/unexecuted/runner temp')
        env = environment(workspace, temporary, 'ab' * 20)
        argv = invocation(integration_script(WORKFLOW.read_text()), env)
        receipt = dict(ok=True, status='mocked_cli_only', source_unchanged=True,
                       external_inputs_unchanged=True)
        with patch.object(integrated, 'qualify', return_value=receipt) as qualify, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(integrated.main(argv), 0)
        qualify.assert_called_once()
        options = qualify.call_args.args[0]
        self.assertEqual(options.expected_head, env['HEPTA_QUALIFICATION_HEAD_SHA'])
        self.assertEqual(options.timeout, 3600)
        self.assertEqual(options.finite_cargo, env['FINITE_NDU_CARGO'])
        self.assertEqual(options.finite_rustc, env['FINITE_NDU_RUSTC'])
        self.assertEqual(options.ranking_bridge, Path(env['HEPTA_NDU_BRIDGE']))
        self.assertEqual(options.ranking_build_receipt, Path(env['HEPTA_NDU_BUILD']) / 'build-receipt.json')
        self.assertEqual(options.ranking_upstream, Path(env['HEPTA_NDU_UPSTREAM']))
        for name, prefix in [('recursive', 'HEPTA_RECURSIVE_NDU'),
                             ('finite', 'HEPTA_FINITE_NDU'), ('stream', 'HEPTA_NDU_STREAM')]:
            self.assertEqual(getattr(options, name + '_bridge'), Path(env[prefix + '_BRIDGE']))
            self.assertEqual(getattr(options, name + '_identity'), Path(env[prefix + '_IDENTITY']))
            self.assertEqual(getattr(options, name + '_upstream'), temporary / ('hepta-' + name + '-ndu-source'))
        clean_source = workspace.parent / 'hepta-integrated-source'
        for path in [options.output_directory, options.cargo_target_dir]:
            self.assertTrue(path.is_relative_to(temporary))
            self.assertFalse(path.is_relative_to(clean_source))
        for required in ['--stream-bridge', '--stream-identity', '--stream-upstream']:
            with self.subTest(missing=required):
                position = argv.index(required)
                incomplete = argv[:position] + argv[position + 2:]
                with patch.object(integrated, 'qualify') as qualify, \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        integrated.main(incomplete)
                self.assertEqual(error.exception.code, 2)
                qualify.assert_not_called()

    def test_real_shell_preserves_failure_and_qualifies_a_clean_exact_sibling(self):
        # The small committed producer only records the shell invocation. It
        # does not claim to run a native gate or produce qualification evidence.
        producer = '''import json, os, pathlib, subprocess, sys
def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args]).decode().strip()
print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),
    'head': git('rev-parse', 'HEAD'), 'status': git('status', '--porcelain'),
    'marker': pathlib.Path('marker.txt').read_text(), 'qualification_executed': False}), flush=True)
print('fixture qualifier stderr retained', file=sys.stderr, flush=True)
raise SystemExit(int(os.environ['HEPTA_WORKFLOW_FIXTURE_EXIT']))
'''
        script = integration_script(WORKFLOW.read_text())
        for exit_code in [0, 7]:
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory(prefix='hepta-ci-wiring-') as directory:
                root = Path(directory)
                workspace, temporary = root / 'source workspace', root / 'runner temp'
                (workspace / 'tools').mkdir(parents=True)
                temporary.mkdir()
                (workspace / 'tools/qualify_hia_integrated.py').write_text(producer)
                (workspace / 'marker.txt').write_text('committed source')
                def git(*args):
                    return subprocess.check_output(['git', '-C', str(workspace), *args], stderr=subprocess.PIPE).decode().strip()
                git('init', '--quiet')
                git('config', 'user.name', 'CI wiring fixture')
                git('config', 'user.email', 'fixture@example.invalid')
                git('add', '.')
                git('commit', '--quiet', '-m', 'exact fixture source')
                head = git('rev-parse', 'HEAD')
                (workspace / 'marker.txt').write_text('earlier gate modified this checkout')
                (workspace / 'legacy-observation.json').write_text('{"retained":true}')
                env = dict(os.environ)
                env.update(environment(workspace, temporary, head),
                           HEPTA_WORKFLOW_FIXTURE_EXIT=str(exit_code), PYTHONDONTWRITEBYTECODE='1')
                run = subprocess.run(['bash', '--noprofile', '--norc', '-c', script],
                                     cwd=workspace, env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(run.returncode, exit_code, run.stdout + run.stderr)
                log = (temporary / 'hepta-integrated.log').read_text()
                self.assertIn('fixture qualifier stderr retained', log)
                record = next(json.loads(line) for line in log.splitlines() if line.startswith('{'))
                self.assertFalse(record['qualification_executed'])
                self.assertEqual(record['head'], head)
                self.assertEqual(record['status'], '')
                self.assertEqual(record['marker'], 'committed source')
                self.assertEqual(Path(record['cwd']), root / 'hepta-integrated-source')
                self.assertEqual(record['argv'], invocation(script, env))
                self.assertEqual((workspace / 'marker.txt').read_text(), 'earlier gate modified this checkout')
                self.assertTrue((workspace / 'legacy-observation.json').exists())
                self.assertTrue((temporary / 'hepta-integrated-worktree.log').is_file())

    def test_existing_gates_and_always_upload_remain_in_place(self):
        source = WORKFLOW.read_text()
        gate = step_lines(source, STEP)
        self.assertIn('        if: ${{ !cancelled() }}', gate)
        self.assertNotIn('continue-on-error', '\n'.join(gate))
        for earlier in ['Run all current native and experiment qualification gates',
                        'Qualify the standalone HIA interpreter and direct native paths',
                        'Qualify proof-gated NDU and finite background/native mechanisms']:
            self.assertIn("env.HEPTA_QUALIFICATION_PROFILE == 'full'", '\n'.join(step_lines(source, earlier)))
            self.assertLess(source.index('      - name: ' + earlier), source.index('      - name: ' + STEP))
        upload = step_lines(source, 'Preserve failures and all raw evidence')
        self.assertIn("        if: ${{ always() && env.HEPTA_QUALIFICATION_PROFILE != 'integrated' }}", upload)
        for suffix in ['hepta-stream-ndu-build/', 'hepta-integrated/',
                       'hepta-integrated.log', 'hepta-integrated-worktree.log']:
            self.assertIn('            ${{ runner.temp }}/' + suffix, upload)
        upload = step_lines(source, 'Preserve integrated observations and source identities')
        self.assertIn("        if: ${{ always() && env.HEPTA_QUALIFICATION_PROFILE == 'integrated' }}", upload)
        for suffix in ['hepta-integrated/*.json', 'hepta-integrated/*.log',
                       'hepta-integrated.log', 'hepta-integrated-worktree.log',
                       'hepta-integrated-safety.json', 'hepta-integrated-safety.log']:
            self.assertIn('            ${{ runner.temp }}/' + suffix, upload)
        retained = [line.strip() for line in upload if line.startswith('            ')]
        self.assertFalse(any('/native/' in path or '/debug/' in path or path.endswith('/') for path in retained))
        matrix = step_lines(source, 'Execute the canonical safety matrix from the exact integrated source')
        self.assertIn("        if: ${{ !cancelled() && env.HEPTA_QUALIFICATION_PROFILE == 'integrated' }}", matrix)
        self.assertNotIn('continue-on-error', '\n'.join(matrix))
        self.assertIn('          cd "$GITHUB_WORKSPACE/../hepta-integrated-source"', matrix)

    def test_real_source_record_selects_only_explicit_profile_and_refuses_wrong_head(self):
        lines = step_lines(WORKFLOW.read_text(), 'Record and verify the tested source head')
        script = '\n'.join(line[10:] for line in lines[lines.index('        run: |') + 1:]) + '\n'
        with tempfile.TemporaryDirectory(prefix='hepta-ci-profile-') as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '--quiet')
            git('config', 'user.name', 'CI profile fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (root / 'marker.txt').write_text('committed')
            git('add', 'marker.txt')
            git('commit', '--quiet', '-m', 'profile fixture')
            head = git('rev-parse', 'HEAD')
            for branch, expected in [
                ('codex/hia-round6-convergence-20261029', 'integrated'),
                ('work/hia-six-track-execution-20261030', 'integrated'),
                ('work/hia-six-track-execution-20261030-suffix', 'full'),
                ('work/hia-eight-track-convergence-20261030', 'integrated'),
                ('work/hia-eight-track-convergence-20261030-suffix', 'full'),
                ('codex/hia-round7-opportunity-20261029', 'integrated'),
                ('codex/hia-round7-opportunity-20261029-suffix', 'full'),
                ('codex/hia-round8-integration-20261029', 'integrated'),
                ('codex/hia-round8-integration-20261029-suffix', 'full'),
                ('work/hia-p0-p7-integrated-20261030', 'integrated'),
                ('work/hia-p0-p7-integrated-20261030-suffix', 'full'),
                ('codex/hia-core-closure-20261028', 'full'),
                ('codex/hia-round6-convergence-20261029-suffix', 'full'),
                ('main', 'full'),
            ]:
                with self.subTest(branch=branch):
                    environment_file = root / 'environment'
                    environment_file.write_text('')
                    env = dict(os.environ, HEPTA_SOURCE_BRANCH=branch,
                               HEPTA_QUALIFICATION_HEAD_SHA=head, GITHUB_SHA=head,
                               GITHUB_ENV=str(environment_file))
                    run = subprocess.run(['bash', '--noprofile', '--norc', '-c', script],
                                         cwd=root, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(environment_file.read_text(), 'HEPTA_QUALIFICATION_PROFILE=' + expected + '\n')
                    receipt = json.loads((root / 'artifacts/workflow-source.json').read_text())
                    self.assertEqual(receipt['qualification_profile'], expected)
                    self.assertEqual(receipt['checkout_head_sha'], head)
                    self.assertEqual(receipt['expected_head_sha'], head)
            environment_file.write_text('')
            env['HEPTA_QUALIFICATION_HEAD_SHA'] = '0' * 40
            run = subprocess.run(['bash', '--noprofile', '--norc', '-c', script],
                                 cwd=root, env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(environment_file.read_text(), '')
            receipt = json.loads((root / 'artifacts/workflow-source.json').read_text())
            self.assertNotEqual(receipt['checkout_head_sha'], receipt['expected_head_sha'])

    def test_application_workflow_uses_clean_source_and_retains_external_identity_files(self):
        source = (ROOT / '.github/workflows/hepta-six-outcomes.yml').read_text()
        def script(name):
            lines = step_lines(source, name)
            return '\n'.join(line[10:] for line in lines[lines.index('        run: |') + 1:]) + '\n'
        with tempfile.TemporaryDirectory(prefix='hepta-ci-app-source-') as directory:
            root = Path(directory)
            workspace, temporary, evidence = root / 'source workspace', root / 'runner temp', root / 'evidence'
            workspace.mkdir()
            temporary.mkdir()
            evidence.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(workspace), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '--quiet')
            git('config', 'user.name', 'CI application fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (workspace / 'marker.txt').write_text('original application source')
            git('add', 'marker.txt')
            git('commit', '--quiet', '-m', 'application fixture')
            head = git('rev-parse', 'HEAD')
            (workspace / 'marker.txt').write_text('earlier step changed the checkout')
            (workspace / 'recursive-ndu-source').mkdir()
            (workspace / 'recursive-ndu-source/retained.txt').write_text('upstream checkout fixture')
            env = dict(os.environ, GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(temporary),
                       HEPTA_SOURCE_SHA=head, HEPTA_EVIDENCE_DIR=str(evidence))
            run = subprocess.run(['bash', '--noprofile', '--norc', '-c',
                                  script('Prepare a clean exact source for application gates')],
                                 cwd=workspace, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            clean = root / 'hepta-six-clean-source'
            self.assertEqual((clean / 'marker.txt').read_text(), 'original application source')
            self.assertEqual(subprocess.check_output(['git', '-C', str(clean), 'status', '--porcelain']).decode(), '')
            self.assertTrue((workspace / 'recursive-ndu-source/retained.txt').is_file())
            for profile in ['recursive', 'finite', 'stream']:
                build = temporary / ('hia-' + profile + '-ndu')
                build.mkdir()
                for filename in ['identity.json', 'build-commands.json']:
                    (build / filename).write_text(json.dumps({'fixture_only': True, 'profile': profile, 'file': filename}))
            run = subprocess.run(['bash', '--noprofile', '--norc', '-c',
                                  script('Retain pinned NDU identities without private source or binaries')],
                                 cwd=workspace, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertFalse((workspace / 'artifacts').exists())
            self.assertEqual(len(list(evidence.iterdir())), 6)
            for profile in ['recursive', 'finite', 'stream']:
                for filename in ['identity.json', 'build-commands.json']:
                    self.assertEqual((evidence / ('ndu-' + profile + '-' + filename)).read_bytes(),
                                     (temporary / ('hia-' + profile + '-ndu') / filename).read_bytes())
        for gate in ['Execute the checkable safety boundary',
                     'Validate selected scalar lowering for all typed inputs',
                     'Check the actual migration Core payload bound without native admission']:
            self.assertIn('        working-directory: ${{ github.workspace }}/../hepta-six-clean-source', step_lines(source, gate))


if __name__ == '__main__':
    unittest.main()
