"""Pure argv admission plus a pinned, create-only v2 CLI exec adapter.

The generated executable contains this source and its explicit configuration.
Importing this module never invokes a CLI, reads credentials or changes config.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

LEGACY_DISABLED_FEATURES = (
    'apps','apps_early_resource_discovery','plugins','plugin_sharing','remote_plugin',
    'plugin_discovery_prefetch','hooks','shell_tool','shell_snapshot','shell_snapshot_v2',
    'unified_exec','unified_exec_tty','incremental_exec_tools','deferred_executor',
    'browser_use','browser_use_external','browser_use_full_cdp_access','browser_annotation_api',
    'computer_use','in_app_browser','in_app_local_automation','image_generation','view_image',
    'multi_agent','multi_agent_v2','multi_agent_v2_dynamic_tools','agent_message_board',
    'agent_message_board_mcp','runtime_agent_instances','memories','external_agent_memory_import',
    'goals','chronicle','skill_mcp_dependency_install','skill_search','tool_suggest',
    'workspace_dependencies','enable_mcp_apps','code_mode','code_mode_only','code_mode_host',
    'code_mode_host_grpc','code_mode_tool_search','artifact','request_permissions_tool',
    'executor_capability_discovery','executor_capability_discovery_v2','standalone_web_search')

# This stable host is a dependency of the selected CLI/model path. Disabling it
# produced an actual pre-turn failure. Keeping it available is not a claim that
# all tools/capabilities are absent; original tool items still fail the parser.
DISABLED_FEATURES = tuple(name for name in LEGACY_DISABLED_FEATURES if name != 'code_mode_host')
ENABLED_DEPENDENCIES = ('code_mode_host',)
EXACT_SKIP_SKILL_WARNING = (
    'Under-development features enabled: skip_host_skill_discovery. Under-development features '
    'are incomplete and may behave unpredictably. To suppress this warning, set '
    '`suppress_unstable_features_warning = true` in /root/.codex/config.toml.')


def restrictions(config):
    legacy = config.get('schema') == 'hepta.hia.explicit-codex-launch-config.v2'
    if not legacy and config.get('schema') != 'hepta.hia.explicit-codex-launch-config.v3':
        raise ValueError('explicit launch policy version required')
    expected = LEGACY_DISABLED_FEATURES if legacy else DISABLED_FEATURES
    if config['disabled_features'] != list(expected):
        raise ValueError('registered feature restriction set differs')
    if not legacy and (config.get('enabled_dependencies') != list(ENABLED_DEPENDENCIES)
            or config.get('registered_startup_warnings') != [EXACT_SKIP_SKILL_WARNING]):
        raise ValueError('registered host dependency or exact startup warning differs')
    argv = ['--ignore-user-config','--color','never']
    settings = ['approval_policy="never"','mcp_servers={}','plugins={}',
        'web_search="disabled"','project_doc_max_bytes=0','features.skip_host_skill_discovery=true']
    settings += ['features.' + name + '=false' for name in expected]
    if not legacy:
        settings += ['features.' + name + '=true' for name in ENABLED_DEPENDENCIES]
    for setting in settings:
        argv += ['-c',setting]
    return argv


def adapt(arguments, cwd, config):
    prefix = ['exec','--json','--ephemeral','--sandbox','read-only','--skip-git-repo-check','--output-schema']
    if (len(arguments) != 17 or arguments[:7] != prefix or arguments[8] != '-c'
            or arguments[10] != '-c' or arguments[12:14] != ['-c','model_reasoning_effort="low"']
            or arguments[14:] != ['-m',config['model'],'-']):
        raise ValueError('only the exact registered v2 provider argv is admitted')
    cwd = Path(cwd)
    root = cwd.parent
    relative = root.relative_to(Path(config['campaign_root']))
    allowed = {'provider-' + task + '-' + arm + '-' + str(index)
        for task in config['task_ids'] for arm in ('fixed','greedy','ordinary','ndu') for index in (1,2,3)}
    if len(relative.parts) != 1 or relative.name not in allowed or cwd.name != 'cwd':
        raise ValueError('provider path is outside the one registered matrix')
    if arguments[7] != str(root / 'response-schema.json'):
        raise ValueError('response schema path differs')
    if arguments[9] != 'sqlite_home=' + json.dumps(str(root / 'state')):
        raise ValueError('provider state path differs')
    if arguments[11] != 'log_dir=' + json.dumps(str(root / 'logs')):
        raise ValueError('provider log path differs')
    return [config['real_cli']['path']] + arguments[:-1] + restrictions(config) + ['-'], root


def checked_bytes(path, expected_sha256, *, maximum):
    descriptor = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('registered input is not a bounded regular file')
        digest = hashlib.sha256()
        length = 0
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            length += len(chunk)
            if length > maximum:
                raise ValueError('registered input grew beyond bound')
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    state = lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if state(before) != state(after) or digest.hexdigest() != expected_sha256:
        raise ValueError('registered input identity drift')
    return before.st_size


def execute(config):
    if config.get('schema') != 'hepta.hia.explicit-codex-launch-config.v3':
        raise ValueError('legacy v2 restriction policy is retained only for original-byte verification')
    start = time.monotonic_ns()
    cwd = Path.cwd().resolve()
    actual,root = adapt(sys.argv[1:],cwd,config)
    if os.getpgrp() != os.getpid():
        raise ValueError('adapter must remain in the original owned new process group')
    cli = config['real_cli']
    size = checked_bytes(cli['path'],cli['sha256'],maximum=512*1024*1024)
    if size != cli['bytes']:
        raise ValueError('underlying CLI byte length changed')
    host = config['host_dependency_identity']
    if checked_bytes(host['path'],host['sha256'],maximum=512*1024*1024) != host['bytes']:
        raise ValueError('registered Code Mode host dependency changed')
    checked_bytes(root/'response-schema.json',config['response_schema_sha256'],maximum=65536)
    receipt = {'schema':'hepta.hia.explicit-codex-exec-adapter.v2',
        'role':'launch adapter, not underlying CLI binary','incoming_argv':sys.argv,
        'actual_exec_argv':actual,'actual_cli':cli,'cwd':str(cwd),
        'adapter_path':str(Path(__file__).resolve()),
        'adapter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'adapter_module_sha256':config['adapter_module_sha256'],
        'host_dependency_observation':host,
        'host_dependency_scope':'exact existing binary checked before exec; this hash does not attest the CLI resolver or absence of host capabilities',
        'pid_before_exec':os.getpid(),'pgid_before_exec':os.getpgrp(),
        'capability_restrictions':restrictions(config),
        'registered_feature_list_sha256':config['feature_list_sha256'],
        'pre_exec_wall_ns':time.monotonic_ns()-start,
        'network_permissions_or_auth_files_modified':False,
        'new_process_group_created_by_adapter':False,
        'complete_capability_isolation_attested':False,
        'effective_config_scope':'registered names and exact requested per-invocation flags; provider actual tool inventory/config requires independent observation',
        'model_identity_scope':'requested selector; no response identity or weights attestation'}
    descriptor = os.open(root/'LAUNCH-ADAPTER.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:
        json.dump(receipt,stream,sort_keys=True,indent=2)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.execv(cli['path'],actual)
