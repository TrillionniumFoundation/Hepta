"""Qualify HIA profile policy and defaults without opening any configured path."""
from pathlib import Path
from hashlib import sha256
import argparse
import copy
import ctypes
import json
import mmap
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_mcp_service_config import OUTPUT_BYTES, SOURCE, WORKSPACE_BYTES, render


def fixture():
    catalog = 'c' * 64
    roles = {'entry': 'hia-job-entry', 'submit': 'hia-job-submit',
             'observation': 'hia-job-observation', 'cancel': 'hia-job-cancel', 'launcher': 'hia-job-launch'}
    host = {'ssh_target': 'rog-test', 'remote_state_dir': '/srv/jobs', 'execution_mode': 'operator',
            'allow_execute': True, 'allow_write': True, 'allow_job_network': True,
            'allowed_read_path_prefixes': ['/srv/hia', '/srv/artifacts'],
            'allowed_write_path_prefixes': ['/srv/hia/state'],
            'native_jobs': {key: {'executable': '/srv/controller/' + role, 'sha256': 'e' * 64}
                            for key, role in roles.items()}}
    profile = {'host': 'rog', 'python_executable': '/srv/hia/install/hia-subprocess',
               'working_directory': '/srv/hia/install', 'state_root': '/srv/hia/state',
               'worker_sha256': 'a' * 64, 'backend_sha256': 'b' * 64, 'catalog_sha256': catalog,
               'artifact_roots': ['/srv/artifacts'],
               'native_helpers_manifest': '/srv/hia/install/native.json',
               'native_helpers_sha256': 'd' * 64}
    return {'configuration': {'hosts': {'rog': host}, 'hia_worker': profile},
            'default_state_dir': '/tmp/mcp-private', 'catalog_sha256': catalog}


def expected(value):
    config = value['configuration']
    raw = config['hia_worker']
    profile = {key: raw[key] for key in ('host', 'python_executable', 'working_directory',
               'state_root', 'worker_sha256', 'backend_sha256', 'catalog_sha256')}
    profile.update(artifact_roots=raw.get('artifact_roots', []),
                   timeout_seconds=raw.get('timeout_seconds', 120),
                   memory_max_bytes=raw.get('memory_max_bytes', 1073741824))
    for key in ('native_helpers_manifest', 'native_helpers_sha256'):
        if raw.get(key) is not None:
            profile[key] = raw[key]
    source = config['hosts'][raw['host']]
    host = {key: source[key] for key in ('ssh_target', 'remote_state_dir', 'native_jobs')}
    host.update(platform=source.get('platform', 'linux'), execution_mode=source.get('execution_mode', 'isolated'))
    host.update({key: source.get(key, False) for key in ('allow_execute', 'allow_write', 'allow_job_network',
                                                       'allow_detached_fallback', 'allow_pty')})
    host.update({key: source.get(key, []) for key in ('allowed_cwd_prefixes', 'allowed_read_path_prefixes',
                  'allowed_write_path_prefixes', 'protected_path_prefixes', 'protected_argument_substrings',
                  'denied_executables', 'allowed_dangerous_executables')})
    return {'profile': profile, 'host': host, 'state_dir': config.get('state_dir', value['default_state_dir']),
            'aliases': [[name, item['ssh_target']] for name, item in config['hosts'].items()]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flat', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    source = (root / SOURCE).read_bytes()
    assert source.decode() == render()
    flat = args.flat.read_bytes()
    image = mmap.mmap(-1, len(flat), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    image.write(flat)
    entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                             ctypes.c_size_t)(ctypes.addressof(ctypes.c_ubyte.from_buffer(image)))
    output = ctypes.create_string_buffer(OUTPUT_BYTES)
    workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
    cases = []

    def invoke(name, value, refusal=False, raw=None):
        if raw is None:
            raw = json.dumps(value, ensure_ascii=True, indent=1).encode()
        buf = ctypes.create_string_buffer(raw)
        result = entry(buf, len(raw), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        row = {'name': name, 'input_sha256': sha256(raw).hexdigest(), 'status': result}
        if refusal:
            assert result > OUTPUT_BYTES, (name, result, output.raw[:256])
        else:
            assert 0 < result <= OUTPUT_BYTES, (name, result)
            got = json.loads(output.raw[:result])
            assert got == expected(value), (name, got, expected(value))
            row['output_sha256'] = sha256(output.raw[:result]).hexdigest()
        cases.append(row)

    invoke('complete-operator-profile', fixture())
    value = fixture()
    config_wire = json.dumps(value['configuration'], separators=(',', ':')).encode()
    wrapped = (b'{"configuration":' + b' ' * ((8 << 20) - len(config_wire)) + config_wire
               + b',"default_state_dir":"/tmp/mcp-private","catalog_sha256":"' + b'c' * 64 + b'"}')
    invoke('exact-eight-mib-configuration-plus-private-fields', value, raw=wrapped)
    value = fixture()
    for key in ('artifact_roots', 'native_helpers_manifest', 'native_helpers_sha256'):
        del value['configuration']['hia_worker'][key]
    invoke('serde-profile-defaults', value)
    value = fixture()
    value['configuration']['state_dir'] = '/tmp/explicit-controller'
    value['configuration']['hia_worker'].update(timeout_seconds=3600, memory_max_bytes=17179869184)
    invoke('explicit-state-and-upper-limits', value)
    value = fixture()
    value['configuration']['state_dir'] = '/tmp/explicit-controller'
    value['default_state_dir'] = None
    invoke('explicit-state-does-not-evaluate-unused-default', value)
    value = fixture()
    value['configuration']['state_dir'] = '/tmp/controller\nstate'
    value['configuration']['hosts']['rog']['remote_state_dir'] = '/srv/remote\nstate'
    invoke('absolute-state-paths-retain-original-lexical-domain', value)
    value = fixture()
    value['configuration']['hia_worker'].update(timeout_seconds=1, memory_max_bytes=67108864)
    invoke('resource-lower-limits', value)
    value = fixture()
    value['configuration']['hosts']['rog'].update(execution_mode='isolated', allow_job_network=False,
                                                  allowed_cwd_prefixes=['/srv/hia/install'],
                                                  protected_path_prefixes=['/srv/secret'])
    invoke('isolated-administrative-profile', value)
    value = fixture()
    value['configuration']['hosts']['name@rog'] = value['configuration']['hosts'].pop('rog')
    value['configuration']['hia_worker']['host'] = 'name@rog'
    invoke('original-at-sign-host-alias', value)
    value = fixture()
    value['configuration']['hosts']['other'] = {'ssh_target': 'other-target'}
    invoke('retain-all-alias-identities', value)
    value = fixture()
    value['configuration']['hia_worker'].update(python_executable='/srv//hia/install/hia-subprocess',
                                               working_directory='/srv/hia/install/')
    value['configuration']['hosts']['rog']['allowed_read_path_prefixes'] = ['/srv/./hia//', '/srv/artifacts/']
    invoke('original-linux-path-components', value)
    value = fixture()
    value['configuration']['hia_worker'].update(native_helpers_manifest=None, native_helpers_sha256=None,
                                               unrelated_ignored_field={'number': 1.5})
    invoke('optional-null-and-ignored-profile-field', value)

    def mutate(name, path, replacement, missing=False):
        value = fixture()
        parent = value
        for key in path[:-1]:
            parent = parent[key]
        if missing:
            del parent[path[-1]]
        else:
            parent[path[-1]] = replacement
        invoke(name, value, True)

    p = ('configuration', 'hia_worker')
    h = ('configuration', 'hosts', 'rog')
    for key in ('host', 'python_executable', 'working_directory', 'state_root',
                'worker_sha256', 'backend_sha256', 'catalog_sha256'):
        mutate('missing-profile-' + key, (*p, key), None, True)
    for key, replacement in (
        ('host', 'unknown'), ('worker_sha256', 'A' * 64), ('backend_sha256', 'b' * 63),
        ('catalog_sha256', 'd' * 64), ('timeout_seconds', 0), ('timeout_seconds', 3601),
        ('timeout_seconds', 120.0), ('memory_max_bytes', 67108863),
        ('memory_max_bytes', 17179869185), ('artifact_roots', ['/srv/artifacts'] * 33),
        ('artifact_roots', None), ('python_executable', 'relative'),
        ('python_executable', '/srv/hia/install/../hia-subprocess'),
        ('working_directory', '/srv/hia/state/code'), ('state_root', '/srv/hia/install/state'),
        ('state_root', '/srv/hia/unwritable'), ('state_root', '/'),
        ('native_helpers_manifest', '/srv/hia/state/native.json'),
        ('native_helpers_manifest', None), ('native_helpers_sha256', 'X' * 64),
    ):
        mutate('profile-' + key + '-' + str(replacement)[:40], (*p, key), replacement)
    for key, replacement in (
        ('platform', 'macos'), ('allow_execute', False), ('allow_write', False),
        ('allow_job_network', False), ('allow_detached_fallback', 'false'),
        ('execution_mode', 'unknown'), ('remote_state_dir', 'relative'),
        ('ssh_target', '-oProxyCommand=bad'), ('ssh_target', '\n'), ('ssh_target', '   \t'),
        ('allowed_read_path_prefixes', []), ('allowed_write_path_prefixes', []),
        ('allowed_read_path_prefixes', ['relative']), ('allowed_cwd_prefixes', ['/srv/hia/install']),
        ('protected_path_prefixes', ['/srv/secret']), ('denied_executables', ['python']),
        ('native_jobs', {}),
    ):
        mutate('host-' + key + '-' + str(replacement)[:40], (*h, key), replacement)
    for char in ('\u0085', '\u00a0', '\u1680', '\u2000', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000'):
        mutate('unicode-empty-ssh-target-' + hex(ord(char)), (*h, 'ssh_target'), char)
    for role in ('entry', 'submit', 'observation', 'cancel', 'launcher'):
        mutate('missing-job-role-' + role, (*h, 'native_jobs', role), None, True)
        mutate('bad-job-pin-' + role, (*h, 'native_jobs', role, 'sha256'), 'A' * 64)
        mutate('bad-job-basename-' + role, (*h, 'native_jobs', role, 'executable'), '/srv/controller/wrong')
    value = fixture()
    value['configuration']['hosts']['rog']['native_jobs']['extra'] = {}
    invoke('unknown-native-job-role', value, True)
    value = fixture()
    value['configuration']['hosts']['rog']['native_jobs']['entry']['extra'] = 0
    invoke('unknown-native-job-pin-field', value, True)
    value = fixture()
    value['configuration']['hosts']['rog'].update(execution_mode='isolated',
                 allowed_cwd_prefixes=['/srv/other'], allow_job_network=False)
    invoke('isolated-cwd-exceeds-policy', value, True)
    value = fixture()
    value['configuration']['hosts']['rog'].update(execution_mode='isolated',
                 protected_path_prefixes=['/srv/hia/install'], allow_job_network=False)
    invoke('isolated-protected-installation', value, True)
    assert args.flat.read_bytes() == flat and (root / SOURCE).read_bytes() == source
    report = {'scope': 'NATIVE_MCP_HIA_ADMINISTRATIVE_CONFIG_COMPONENT', 'passed': True,
              'count': len(cases), 'flat_sha256': sha256(flat).hexdigest(),
              'source_sha256': sha256(source).hexdigest(),
              'scope_excludes_unrelated_runtime_providers': True,
              'authentication_and_file_custody_are_separate_required_gates': True,
              'whole_mcp_server_qualified': False, 'cases': cases}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases), 'flat_sha256': report['flat_sha256']}), flush=True)
    del entry
    image.close()


if __name__ == '__main__':
    main()
