"""Compare real native/Rust MCP startup for typed configuration edge cases."""
from __future__ import annotations
import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import time

from tools.qualify_hia_mcp_service_owner import Connection, INIT, READY, PING


def compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('service', 'runtime', 'config', 'manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    baseline = json.loads(args.config.read_bytes())
    host_name = baseline['hia_worker']['host']
    source_pins = {str(path): sha256(path.read_bytes()).hexdigest()
                   for path in (args.service, args.runtime, args.config, args.manifest)}
    cases = []

    def add(name, expected, mutate=None, raw=None):
        cases.append((name, expected, mutate, raw))

    def change(path, value):
        def apply(cfg):
            node = cfg
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
        return apply

    def remove(path):
        def apply(cfg):
            node = cfg
            for key in path[:-1]:
                node = node[key]
            del node[path[-1]]
        return apply

    def injected(path, value):
        def transform(cfg):
            change(path, '__TYPED_RAW_VALUE__')(cfg)
            return compact(cfg).replace(b'"__TYPED_RAW_VALUE__"', value)
        return transform

    def duplicate(path, value=None):
        def transform(cfg):
            node = cfg
            for key in path[:-1]:
                node = node[key]
            key = path[-1]
            current = compact(node[key])
            field = compact(key) + b':' + current
            duplicate = compact(key) + b':' + (current if value is None else value)
            wire = compact(cfg)
            assert wire.count(field) == 1, (path, wire.count(field))
            return wire.replace(field, field + b',' + duplicate)
        return transform

    h = ('hosts', host_name)
    p = ('hia_worker',)
    add('baseline', True)
    for location, path in [('root', ()), ('host', h)]:
        for label, value in [
            ('overflow-exponent', b'1e400'),
            ('huge-integer', b'9' * 4301),
            ('isolated-surrogate', b'"\\ud800"'),
            ('non-utf8-string', b'"\xff"'),
            ('ignored-nested-key-non-utf8', b'{"\xff":1}'),
            ('deep-array-160', b'[' * 160 + b'0' + b']' * 160),
            ('deep-object-1000', b'{"x":' * 1000 + b'0' + b'}' * 1000),
            ('deep-array-56000', b'[' * 56000 + b'0' + b']' * 56000),
        ]:
            add(location + '-ignored-' + label, True, raw=injected((*path, 'unknown_field'), value))
        for label, value in [('bad-escape', b'"\\q"'), ('short-unicode', b'"\\u00"'),
                             ('trailing-comma', b'[0,]'), ('bad-number', b'01'),
                             ('bad-exponent', b'1e+'), ('bare-control', b'"\x01"')]:
            add(location + '-invalid-ignored-' + label, False, raw=injected((*path, 'unknown_field'), value))
    for key in ('state_dir', 'hosts', 'hia_worker', 'controller_workspace_roots'):
        if key in baseline:
            add('duplicate-root-' + key, False, raw=duplicate((key,)))
    for key in ('ssh_target', 'allow_execute', 'native_jobs'):
        add('duplicate-host-' + key, False, raw=duplicate((*h, key)))
    for key in ('host', 'catalog_sha256', 'working_directory'):
        add('duplicate-profile-' + key, False, raw=duplicate((*p, key)))
    add('profile-denies-unknown-null', False, change((*p, 'unknown_field'), None))
    add('profile-denies-unknown-overflow', False, raw=injected((*p, 'unknown_field'), b'1e400'))
    add('native-entries-deny-unknown', False, change((*h, 'native_jobs', 'unknown_field'), 0))
    add('native-pin-denies-unknown', False, change((*h, 'native_jobs', 'entry', 'unknown_field'), 0))
    add('platform-unit-map-linux', True, change((*h, 'platform'), {'linux': None}))
    add('execution-unit-map-operator', True, change((*h, 'execution_mode'), {'operator': None}))
    add('enum-map-non-unit-payload', False, change((*h, 'execution_mode'), {'operator': 0}))
    add('enum-map-multiple-variants', False, change((*h, 'execution_mode'), {'operator': None, 'isolated': None}))
    for key, value in [('allow_execute', 'true'), ('allowed_read_path_prefixes', [1]),
                       ('ssh_target', 1), ('remote_state_dir', None)]:
        add('host-typed-' + key, False, change((*h, key), value))
    add('host-required-remote-state', False, remove((*h, 'remote_state_dir')))
    add('known-key-invalid-utf8', False, raw=lambda cfg: compact(cfg)[:-1] + b',"\xff":null}')
    add('known-key-isolated-surrogate', False, raw=lambda cfg: compact(cfg)[:-1] + b',"\\ud800":null}')

    def duplicate_hosts(first_edit=None, final_edit=None, escaped=False):
        def transform(cfg):
            first = copy.deepcopy(cfg['hosts'][host_name])
            final = copy.deepcopy(first)
            if first_edit is not None:
                first_edit(first)
            if final_edit is not None:
                final_edit(final)
            key = compact(host_name)
            last = key
            if escaped:
                last = b'"' + ('\\u%04x' % ord(host_name[0])).encode() + key[2:]
            hosts = b'{' + key + b':' + compact(first) + b',' + last + b':' + compact(final) + b'}'
            cfg['hosts'] = '__HOST_MAP__'
            return compact(cfg).replace(b'"__HOST_MAP__"', hosts)
        return transform

    add('host-map-last-value-wins', True,
        raw=duplicate_hosts(lambda h: h.update(ssh_target='-invalid-replaced-target')))
    add('host-map-escaped-equal-name', True,
        raw=duplicate_hosts(lambda h: h.update(ssh_target='-invalid-replaced-target'), escaped=True))
    add('host-map-last-invalid-value-refused', False,
        raw=duplicate_hosts(final_edit=lambda h: h.update(ssh_target='-invalid-final-target')))
    add('host-map-replaced-value-still-deserialized', False,
        raw=duplicate_hosts(lambda h: h.update(allow_execute='true')))
    add('host-map-replaced-missing-field-refused', False,
        raw=duplicate_hosts(lambda h: h.pop('remote_state_dir')))
    add('host-map-replaced-unknown-profile-not-applicable', True,
        raw=duplicate_hosts(lambda h: h.update(ignored_in_host={'number': 1.5})))
    add('unknown-duplicate-fields-ignored', True,
        raw=lambda cfg: compact(cfg)[:-1] + b',"unknown":1e400,"unknown":"\\ud800"}')
    add('known-profile-string-invalid-utf8', False,
        raw=injected((*p, 'host'), b'"\xff"'))

    # serde derive also implements visit_seq for structs, even with deny_unknown_fields.
    # These are the declaration orders in the frozen RuntimeConfig/HostConfig/profile.
    seq_fields = {
        'root': ('state_dir','controller_workspace_roots','hosts','weight_workers','rea_static_profiles','hia_worker'),
        'host': ('native_jobs','checkpoint_binary','checkpoint_binary_sha256','execution_mode','ssh_target','platform','remote_state_dir','allow_execute','allow_pty','allow_write','allow_job_network','allow_detached_fallback','allowed_cwd_prefixes','allowed_read_path_prefixes','allowed_write_path_prefixes','protected_path_prefixes','protected_argument_substrings','denied_executables','allowed_dangerous_executables','privileged_actions'),
        'profile': ('host','python_executable','working_directory','state_root','artifact_roots','worker_sha256','backend_sha256','catalog_sha256','native_helpers_manifest','native_helpers_sha256','timeout_seconds','memory_max_bytes'),
        'action': ('executable','fixed_args','allow_extra_args','extra_arg_patterns','timeout_seconds'),
        'entries': ('entry','submit','observation','cancel','launcher'),
        'pin': ('executable','sha256'),
    }
    defaults = dict(controller_workspace_roots=[], weight_workers={}, rea_static_profiles={},
        native_jobs=None, checkpoint_binary=None, checkpoint_binary_sha256=None,
        execution_mode='isolated', platform='linux', allow_execute=False, allow_pty=False,
        allow_write=False, allow_job_network=False, allow_detached_fallback=False,
        allowed_cwd_prefixes=[], allowed_read_path_prefixes=[], allowed_write_path_prefixes=[],
        protected_path_prefixes=[], protected_argument_substrings=[], denied_executables=[],
        allowed_dangerous_executables=[], privileged_actions={}, artifact_roots=[],
        native_helpers_manifest=None, native_helpers_sha256=None, timeout_seconds=120,
        memory_max_bytes=1073741824, fixed_args=[], allow_extra_args=False, extra_arg_patterns=[])
    def sequence(node, kind):
        values = []
        for field in seq_fields[kind]:
            if field in node: value = node[field]
            elif kind == 'action' and field == 'timeout_seconds': value = 30
            else: value = defaults[field]
            values.append(copy.deepcopy(value))
        return values
    def array_at(path, kind, length=None, extra=False, corrupt=None):
        def transform(cfg):
            node = cfg
            for key in path: node = node[key]
            value = sequence(node, kind)
            if length is not None: value = value[:length]
            if extra: value.append(None)
            if corrupt is not None: value[corrupt[0]] = corrupt[1]
            if path: change(path, value)(cfg); return compact(cfg)
            return compact(value)
        return transform
    add('sequence-runtime-all-fields', True, raw=array_at((), 'root'))
    add('sequence-runtime-extra-field', False, raw=array_at((), 'root', extra=True))
    for label, path, kind in [
        ('host', h, 'host'), ('profile', p, 'profile'),
        ('entries', (*h,'native_jobs'), 'entries'),
        ('pin', (*h,'native_jobs','entry'), 'pin')]:
        for length in range(len(seq_fields[kind]) + 1):
            add('sequence-' + label + '-prefix-' + str(length), None,
                raw=array_at(path, kind, length=length))
        add('sequence-' + label + '-extra-field', False, raw=array_at(path, kind, extra=True))
    def action_sequence(length=5, extra=False):
        def transform(cfg):
            action = sequence({'executable':'/usr/bin/true'}, 'action')[:length]
            if extra: action.append(None)
            change((*h,'privileged_actions'), {'sequence_probe':action})(cfg)
            return compact(cfg)
        return transform
    for length in range(6):
        add('sequence-action-prefix-' + str(length), length >= 1, raw=action_sequence(length))
    add('sequence-action-extra-field', False, raw=action_sequence(extra=True))
    def all_sequences(cfg):
        host = cfg['hosts'][host_name]
        for key in seq_fields['entries']:
            host['native_jobs'][key] = sequence(host['native_jobs'][key], 'pin')
        host['native_jobs'] = sequence(host['native_jobs'], 'entries')
        host['privileged_actions'] = {'sequence_probe':sequence({'executable':'/usr/bin/true'},'action')}
        cfg['hosts'][host_name] = sequence(host, 'host')
        cfg['hia_worker'] = sequence(cfg['hia_worker'], 'profile')
        return compact(sequence(cfg,'root'))
    add('sequence-all-six-structs-nested', True, raw=all_sequences)
    add('sequence-profile-required-string-null', False, raw=array_at(p,'profile',corrupt=(0,None)))
    add('sequence-profile-optional-array-null', False, raw=array_at(p,'profile',corrupt=(4,None)))
    add('sequence-profile-timeout-float', False, raw=array_at(p,'profile',corrupt=(10,120.0)))
    add('sequence-host-required-string-number', False, raw=array_at(h,'host',corrupt=(4,3)))
    add('sequence-host-default-bool-null', False, raw=array_at(h,'host',corrupt=(7,None)))
    add('sequence-host-native-entries-null', None, raw=array_at(h,'host',corrupt=(0,None)))
    add('hosts-map-remains-object', False, change(('hosts',), []))
    add('actions-map-remains-object', False, change((*h,'privileged_actions'), []))
    add('sequence-profile-trailing-comma', False,
        raw=lambda cfg: compact(cfg).replace(compact(cfg['hia_worker']),compact(sequence(cfg['hia_worker'],'profile'))[:-1]+b',]'))

    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('HEPTA_EFFECT_OWNER_', 'HEPTA_HIA_', 'HIA_LOCAL_MCP_', 'HIA_TRANSPORT_'))}
    env['PATH'] = '/usr/bin'
    env['RUST_LOG'] = 'warn'

    def check(case):
        index, (name, expected, mutate, transform) = case
        folder = args.output / f'{index:03d}-{name}'
        folder.mkdir(mode=0o700)
        cfg = copy.deepcopy(baseline)
        cfg['state_dir'] = str(folder / 'state')
        if mutate:
            mutate(cfg)
        raw = transform(cfg) if transform else compact(cfg)
        path = folder / 'runtime-config.json'
        path.write_bytes(raw)
        path.chmod(0o600)
        report = {'name': name, 'expected': expected, 'config_sha256': sha256(raw).hexdigest()}
        manifest_pin = source_pins[str(args.manifest)]
        commands = {
            'rust': [str(args.runtime), 'mcp', '--path', str(folder), '--runtime-config', str(path),
                     '--hia-controller-manifest', str(args.manifest), '--hia-controller-sha256', manifest_pin],
            'native': [str(args.service), str(path), report['config_sha256'], str(args.manifest), manifest_pin],
        }
        for owner, command in commands.items():
            started = time.monotonic()
            conn = Connection(command, {**env, 'PATH': '' if owner == 'native' else '/usr/bin'})
            accepted = False
            replies = []
            try:
                conn.send(INIT)
                replies.append(conn.read(timeout=30))
                assert replies[-1]['id'] == 'init' and 'result' in replies[-1], replies
                conn.send(READY)
                conn.send(PING)
                replies.append(conn.read(timeout=30))
                accepted = replies[-1].get('id') == 'ping' and 'result' in replies[-1]
            except (AssertionError, BrokenPipeError):
                pass
            finally:
                if conn.process.poll() is None:
                    try:
                        conn.process.stdin.close()
                    except BrokenPipeError:
                        pass
                try:
                    rc = conn.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    conn.process.kill()
                    rc = conn.process.wait(timeout=5)
                err = conn.process.stderr.read()
                (folder / (owner + '.stderr')).write_bytes(err)
                (folder / (owner + '.responses.json')).write_text(json.dumps(replies, indent=2) + '\n')
            report[owner] = {'accepted': accepted, 'rc': rc, 'seconds': time.monotonic() - started,
                             'stderr_sha256': sha256(err).hexdigest()}
        report['passed'] = report['native']['accepted'] == report['rust']['accepted'] and (expected is None or report['rust']['accepted'] == expected)
        (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)
        return report

    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(check, enumerate(cases)))
    assert all(sha256(Path(name).read_bytes()).hexdigest() == pin for name, pin in source_pins.items())
    report = {'scope': 'ACTUAL_NATIVE_AND_FROZEN_RUST_MCP_TYPED_CONFIG_STARTUP',
              'passed': all(row['passed'] for row in records), 'count': len(records),
              'pins': source_pins, 'cases': records}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['passed'], [row['name'] for row in records if not row['passed']]


if __name__ == '__main__':
    main()
