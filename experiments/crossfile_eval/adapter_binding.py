"""Freeze public adapter provenance without collecting environment values."""
from __future__ import annotations

from pathlib import Path
import re
import shutil

from .tasks import ROOT, canonical, digest

FIELDS = {'bundle_sha256', 'command', 'executable_sha256',
          'passed_environment_names', 'network_requested'}


def validate_config(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('E_ADAPTER_CONFIG: exact bundle/argv/executable/environment/network fields required')
    for name in ('bundle_sha256', 'executable_sha256'):
        if not isinstance(value[name], str) or not re.fullmatch('[0-9a-f]{64}', value[name]):
            raise ValueError('E_ADAPTER_CONFIG: invalid ' + name)
    command = value['command']
    if (not isinstance(command, list) or not command or len(command) > 64
            or any(not isinstance(arg, str) or not arg or '\0' in arg or len(arg) > 4096 for arg in command)):
        raise ValueError('E_ADAPTER_CONFIG: bounded nonempty argv required')
    names = value['passed_environment_names']
    if (not isinstance(names, list)
            or any(not isinstance(n, str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', n) for n in names)
            or len(names) != len(set(names))):
        raise ValueError('E_ADAPTER_CONFIG: unique environment names required; never supply secret values')
    if type(value['network_requested']) is not bool:
        raise ValueError('E_ADAPTER_CONFIG: explicit boolean network choice required')
    return value


def bundle_digest(directory):
    directory = Path(directory).resolve()
    if (not directory.is_dir() or directory == ROOT or ROOT in directory.parents or directory in ROOT.parents
            or (ROOT.parent / 'agent_eval') == directory or (ROOT.parent / 'agent_eval') in directory.parents):
        raise ValueError('E_ADAPTER_BUNDLE: provide a standalone bundle outside evaluator directories')
    entries = list(directory.rglob('*'))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in entries):
        raise ValueError('E_ADAPTER_BUNDLE: symlinks and special files are unsupported')
    files = sorted(p for p in entries if p.is_file())
    if sum(p.stat().st_size for p in files) > 5 * 1024 * 1024:
        raise ValueError('E_ADAPTER_BUNDLE: bundle exceeds 5 MiB')
    return digest(canonical([(p.relative_to(directory).as_posix(), digest(p.read_bytes())) for p in files]))


def actual_config(directory, command, pass_env=(), network=False):
    if not isinstance(command, list) or not command or not isinstance(command[0], str):
        raise ValueError('E_ADAPTER_COMMAND: nonempty argv list required')
    executable = shutil.which(command[0])
    if not executable:
        raise ValueError('E_ADAPTER_COMMAND: use an installed executable and {adapter}/script argument')
    executable = str(Path(executable).resolve())
    value = {'bundle_sha256': bundle_digest(directory), 'command': list(command),
             'executable_sha256': digest(Path(executable).read_bytes()),
             'passed_environment_names': list(pass_env), 'network_requested': network}
    return validate_config(value), executable


def frozen_config(plan, model):
    values = [v for v in plan['adapter_configs'] if v['model'] == model]
    if len(values) != 1:
        raise ValueError('E_ADAPTER_CONFIG: plan has no frozen adapter for this model; create a new configured plan')
    return {k: values[0][k] for k in FIELDS}
