"""Qualify v26 native Job configuration binding against independent JSON edits.

The controller receipt is a synthetic component fixture; its nineteen source
files are real admitted images. A complete ordinary Worker installation and
the original mode1/mode2 qualification remain separate, mandatory gates.
"""
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
import argparse
import fcntl
import json
import os
import shutil
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.qualify_hia_worker_config_bind import FILES, FIELDS, roots_of, vector, canonical

ROLES = (('entry', 'hia-job-entry', 2 << 20),
         ('submit', 'hia-job-submit', 4 << 20),
         ('observation', 'hia-job-observation', 2 << 20),
         ('cancel', 'hia-job-cancel', 1 << 20),
         ('launcher', 'hia-job-launch', 1 << 20))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('elf', 'runner', 'installation', 'controller', 'job-images', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--large-bytes', type=int, default=67108865)
    args = parser.parse_args()
    for name in ('elf', 'runner', 'installation', 'controller', 'job_images', 'output'):
        setattr(args, name, getattr(args, name).absolute())
    args.output.mkdir(mode=0o700, exist_ok=False)
    assert args.large_bytes > 67108864
    inputs = {}

    def read(path):
        raw = path.read_bytes()
        inputs[str(path)] = sha256(raw).hexdigest()
        return raw

    read(args.elf)
    runner = read(args.runner)
    worker_files = {name: read(args.installation / name) for name in FILES}
    roots = roots_of(args.installation)
    base_manifest = json.loads(read(args.controller / 'hia-controller.json'))
    images = {name: read(args.controller / name) for name in base_manifest['files']}
    for _, name, _ in ROLES:
        images[name] = read(args.job_images / name / name)
    assert len(images) == 19
    cases = []

    def run(name, *, mutation=None, role=None, expected=True, selected='r',
            hosts=None, prior=False, reverse=False, trace=False, extra=None,
            encoding='utf-8', padding=False):
        folder = args.output / name
        folder.mkdir(mode=0o700)
        installed = folder / 'installation'
        installed.mkdir(mode=0o700)
        for filename, raw in worker_files.items():
            path = installed / filename
            path.write_bytes(raw)
            path.chmod(0o500 if filename == 'hia-agent-worker' else 0o400)
        supplied = dict(images)
        if padding:
            for _, filename, cap in ROLES:
                supplied[filename] += bytes(cap - len(supplied[filename]))
        if mutation == 'extent-over':
            cap = next(cap for _, filename, cap in ROLES if filename == role)
            supplied[role] += bytes(cap + 1 - len(supplied[role]))
        if mutation == 'invalid-elf':
            supplied[role] = b'NOELF!!' + supplied[role][7:]
        pins = {filename: sha256(raw).hexdigest() for filename, raw in supplied.items()}
        if mutation == 'missing-role':
            del pins[role]
        if mutation == 'substituted-role':
            pins['unknown-controller-role'] = pins.pop(role)
        if mutation == 'wrong-role-pin':
            pins[role] = '0' * 64
        if mutation == 'uppercase-pin':
            pins[role] = pins[role].upper()
        manifest = {'schema': 'hepta.hia.mcp.controller.v26', 'files': pins}
        if mutation == 'legacy-schema':
            manifest['schema'] = 'hepta.hia.mcp.controller.v25'
        if mutation == 'unknown-manifest-field':
            manifest['unexpected'] = 1
        raw_manifest = (canonical(manifest) + '\n').encode()
        identity = sha256(b'synthetic-v26-controller\0' + raw_manifest).digest()
        release = installed / 'controller' / identity.hex()
        release.mkdir(mode=0o700, parents=True)
        for filename, raw in supplied.items():
            path = release / filename
            path.write_bytes(raw)
            path.chmod(0o500)
        (release / 'hia-controller.json').write_bytes(raw_manifest)
        (release / 'hia-controller.json').chmod(0o400)
        if mutation == 'missing-file':
            (release / role).unlink()
        if mutation == 'image-symlink':
            (release / role).unlink()
            (release / role).symlink_to(args.job_images / role / role)
        if mutation == 'image-hardlink':
            os.link(release / role, folder / 'second-link')
        if mutation == 'image-writable':
            (release / role).chmod(0o522)
        if mutation == 'image-not-executable':
            (release / role).chmod(0o400)
        if mutation == 'image-drift':
            (release / role).chmod(0o700)
            (release / role).write_bytes(supplied[role] + b'changed')
        if mutation == 'manifest-drift':
            (release / 'hia-controller.json').chmod(0o600)
            (release / 'hia-controller.json').write_bytes(raw_manifest + b' ')
        selected_host = {'marker': ['preserved', 17]}
        if prior:
            selected_host['native_jobs'] = {'obsolete': '\ud800'}
        config = {'hosts': {'r': selected_host, 'other': {'native_jobs': {'keep': True}}},
                  'hia_worker': {'host': selected, 'artifact_roots': roots,
                                 'worker_sha256': {'old': True}, 'native_helpers_manifest': 'old'},
                  'unrelated': {'unicode': '测验', 'quote': '"\\', 'values': [1, None, False]}}
        if hosts is not None:
            config['hosts'] = hosts
            config['hosts'][selected] = selected_host
        if extra:
            extra(config)
        if reverse:
            config = dict(reversed(tuple(config.items())))
        raw_config = json.dumps(config, ensure_ascii=True, separators=(',', ':')).encode(encoding)
        receipt = struct.pack('<8sQQ32s32sQ', b'HIACTO01', 26, 20, identity,
                              sha256(raw_manifest).digest(), 0)
        if mutation == 'receipt-schema':
            receipt = receipt[:8] + struct.pack('<Q', 25) + receipt[16:]
        if mutation == 'receipt-count':
            receipt = receipt[:16] + struct.pack('<Q', 19) + receipt[24:]
        if mutation == 'receipt-pin':
            receipt = receipt[:56] + bytes(32) + receipt[88:]
        if mutation == 'receipt-reserved':
            receipt = receipt[:-8] + struct.pack('<Q', 1)
        if mutation == 'receipt-truncated':
            receipt = receipt[:-1]
        if mutation == 'existing-output':
            (installed / 'runtime-config.json').write_bytes(b'keep-existing')
        if mutation == 'existing-temp':
            (installed / '.hia-runtime-config.tmp').write_bytes(b'keep-temp')
        with ExitStack() as stack:
            def own(fd):
                stack.callback(os.close, fd)
                return fd

            def memfd(label, raw, *, seal=True, executable=False):
                fd = own(os.memfd_create(label, 2))
                at = 0
                while at < len(raw):
                    at += os.write(fd, raw[at:at + 1048576])
                os.fchmod(fd, 0o500 if executable else 0o400)
                if seal:
                    fcntl.fcntl(fd, 1033, 15)
                os.lseek(fd, 0, 0)
                return fd

            config_fd = memfd('input-config', raw_config)
            roots_fd = memfd('input-roots', vector(roots))
            directory_fd = own(os.open(installed, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC))
            runner_fd = memfd('native-runner', runner, executable=True)
            receipt_fd = memfd('controller-receipt', receipt, seal=mutation != 'unsealed-receipt')
            passed = (config_fd, roots_fd, directory_fd, runner_fd, receipt_fd)
            deadline = time.monotonic_ns() + 120000000000
            reserved = [receipt_fd, 0, 0, 0, 0, 0, 0, 0]
            if mutation == 'aliased-receipt':
                reserved[0] = runner_fd
            if mutation == 'request-reserved':
                reserved[1] = 1
            wire = struct.pack('<8s15Q', b'HIAWCB01', 3, 0, deadline,
                               config_fd, roots_fd, directory_fd, runner_fd, *reserved)
            wire += sha256(raw_config).digest() + sha256(runner).digest()
            request_fd = memfd('request', wire)
            command = [str(args.elf)]
            if trace:
                command = ['/usr/bin/strace', '-f', '-qq', '-o', str(folder / 'trace'), *command]
            began = time.monotonic()
            result = subprocess.run(command, stdin=request_fd, pass_fds=passed,
                                    capture_output=True, env={'PATH': ''}, timeout=125)
        record = {'name': name, 'expected_success': expected, 'returncode': result.returncode,
                  'elapsed_seconds': time.monotonic() - began,
                  'stdout_bytes': len(result.stdout), 'stderr_bytes': len(result.stderr)}
        (folder / 'stdout').write_bytes(result.stdout)
        (folder / 'stderr').write_bytes(result.stderr)
        assert not result.stderr, (name, record)
        if expected:
            assert result.returncode == 0, (name, record)
            output = (installed / 'runtime-config.json').read_bytes()
            received = struct.unpack('<8sQQ32s32sQ', result.stdout)
            profile = sha256(worker_files['worker.json']).digest()
            assert received == (b'HIAWCO01', 1, len(output), sha256(output).digest(), profile, 0)
            query = subprocess.run([str(installed / 'hia-agent-worker'), '-B', '-E', '-s', '-m',
                                    'hepta.hia_agent_worker', '--installation-manifest',
                                    '--native-helpers-manifest', str(installed / 'worker.json'),
                                    '--expected-native-helpers-sha256', profile.hex()],
                                   capture_output=True, env={'PATH': ''}, check=True)
            assert not query.stderr
            expected_config = json.loads(raw_config)
            expected_config['hia_worker'].update(json.loads(query.stdout),
                python_executable=str(installed / 'hia-agent-worker'),
                native_helpers_manifest=str(installed / 'worker.json'))
            expected_config['hosts'][selected]['native_jobs'] = {
                field: {'executable': str(release / filename), 'sha256': pins[filename]}
                for field, filename, _ in ROLES}
            assert canonical(json.loads(output)) == canonical(expected_config), (name, 'semantic mismatch')
            assert (installed / 'runtime-config.json').stat().st_mode & 0o777 == 0o600
            assert not (installed / '.hia-runtime-config.tmp').exists()
            record.update(output_bytes=len(output), output_sha256=sha256(output).hexdigest(),
                          selected_host_matches=True, unrelated_values_preserved=True)
            if trace:
                rows = (folder / 'trace').read_text().splitlines()
                executions = [row for row in rows if 'execve(' in row or 'execveat(' in row]
                assert len(executions) == 3
                assert all(not any(word in row for word in ('python', '/bin/sh', '/usr/bin/cc')) for row in executions)
                record['native_exec_count'] = len(executions)
        else:
            assert result.returncode in (65, 74) and not result.stdout, (name, record)
            for filename, keep in (('runtime-config.json', 'existing-output'), ('.hia-runtime-config.tmp', 'existing-temp')):
                path = installed / filename
                if mutation == keep:
                    assert path.read_bytes() == (b'keep-existing' if keep == 'existing-output' else b'keep-temp')
                else:
                    assert not path.exists(), (name, 'partial output')
        cases.append(record)
        print(json.dumps(record), flush=True)

    run('bind-five-roles', trace=True)
    run('replace-old-native-jobs', prior=True)
    run('worker-before-hosts', reverse=True)
    run('all-existing-worker-fields', extra=lambda c: c['hia_worker'].update({k: '\ud800' for k in FIELDS}))
    run('utf16-input', encoding='utf-16')
    run('quoted-"\\-测验-path')
    for selected in (0, True, -1):
        run('array-host-' + str(selected), selected=selected, hosts=[{}, {}])
    run('exact-role-caps', padding=True)
    for mutation in ('receipt-schema', 'receipt-count', 'receipt-pin', 'receipt-reserved',
                     'receipt-truncated', 'unsealed-receipt', 'aliased-receipt', 'request-reserved',
                     'legacy-schema', 'unknown-manifest-field', 'manifest-drift',
                     'existing-output', 'existing-temp'):
        run('reject-' + mutation, mutation=mutation, expected=False)
    for _, role, _ in ROLES:
        for mutation in ('missing-role', 'substituted-role', 'wrong-role-pin', 'missing-file', 'extent-over'):
            run('reject-' + mutation + '-' + role, mutation=mutation, role=role, expected=False)
    for mutation in ('uppercase-pin', 'invalid-elf', 'image-symlink', 'image-hardlink',
                     'image-writable', 'image-not-executable', 'image-drift'):
        run('reject-' + mutation, mutation=mutation, role='hia-job-entry', expected=False)
    run('preserve-large-config', extra=lambda c: c.update(large='x' * args.large_bytes))
    for path, digest in inputs.items():
        assert sha256(Path(path).read_bytes()).hexdigest() == digest
    report = {'scope': 'NATIVE_WORKER_JOB_CONFIG_BIND_COMPONENT', 'passed': True,
              'synthetic_controller_receipt': True, 'whole_worker_installation_qualified': False,
              'input_sha256': inputs, 'large_bytes': args.large_bytes, 'count': len(cases), 'cases': cases}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases)}), flush=True)


if __name__ == '__main__':
    main()
