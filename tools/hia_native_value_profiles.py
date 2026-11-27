"""Exact Value image layouts admitted by native release authoring.

These are source/recipe declarations. Runtime construction consumes the
corresponding HIA packer and does not import this development module.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ValueProfile:
    protocol: str
    roles: tuple[str, ...]
    labels: tuple[str, ...]
    packer: str
    bridge: str


_ROLES = (
    'result_value_owner', 'result_value_core', 'result_value_import',
    'result_value_export', 'background_optimizer_json_capture',
    'agent_binary64_format', 'result_value_binary64',
    'result_value_dict_iterator', 'result_value_classes', 'native_class_mro',
    'result_value_records', 'result_value_resources', 'result_value_protocols',
    'result_value_callables', 'result_value_invocations', 'result_value_platform',
)
_LABELS = (
    'owner', 'core', 'import', 'export', 'capture', 'format', 'number',
    'dict_iterator', 'classes', 'class_mro', 'records', 'resources',
    'protocols', 'callables', 'invocations', 'platform',
)
_PROFILES = {
    protocol: ValueProfile(protocol, _ROLES[:count], _LABELS[:count],
                           f'result_value_{name}_packer',
                           f'tools/hia_result_value_{name}_bridge.S')
    for protocol, count, name in (
        ('HIABVP04', 11, 'records'),
        ('HIABVP05', 12, 'resources'),
        ('HIABVP09', 16, 'platform'),
    )
}


def value_profile(protocol):
    try:
        return _PROFILES[protocol]
    except (KeyError, TypeError) as error:
        raise ValueError('unregistered native Value release profile') from error


def qualified_value_profile(receipt):
    """Preserve older admissions and bind newer profiles to every exact role."""
    profile = value_profile(receipt.get('value_protocol', 'HIABVP04'))
    if profile.protocol != 'HIABVP04':
        if receipt.get('original_six_campaigns_qualified') is not True:
            raise ValueError('original Value campaigns are not qualified')
        if receipt.get('value_roles') != list(profile.labels):
            raise ValueError('Value qualification role layout differs')
        if receipt.get('value_packer') != 'examples/hia_bootstrap/' + profile.packer + '.hepta':
            raise ValueError('Value qualification packer differs')
    return profile


def qualified_value_sources(receipt):
    """Read each registered receipt schema without a missing-field fallback."""
    profile = qualified_value_profile(receipt)
    if profile.protocol != 'HIABVP09':
        return receipt['source_files']
    if receipt.get('schema') != 'hia.native-value-deferred-info.component.v1':
        raise ValueError('unregistered platform Value qualification schema')
    construction = receipt['construction']
    if (construction.get('schema') != 'hia.native-value-callables.build.v1'
            or construction.get('component_qualified') is not True
            or construction.get('source_frozen') is not True
            or construction.get('value_protocol') != profile.protocol
            or construction.get('value_roles') != list(profile.labels)):
        raise ValueError('platform Value construction is not source-bound')
    sources = construction['source_files']
    audit = receipt['source_audit']
    if (audit.get('frozen_before_and_after') is not True
            or audit.get('native_inputs') != sources):
        raise ValueError('platform Value construction and source audit differ')
    if receipt.get('value_bridge_source') != profile.bridge:
        raise ValueError('platform Value bridge differs')
    if receipt.get('value_packer_module') != 'tools.generate_hia_' + profile.packer:
        raise ValueError('platform Value reference packer differs')
    return sources
