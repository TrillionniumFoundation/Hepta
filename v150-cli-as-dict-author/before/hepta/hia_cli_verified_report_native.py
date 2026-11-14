"""Optional discovery CLI bundle with its real verify report handled by HIA.

All original parsing, foreign operations, exception handling and retirement
still use the original control image and adapter. Only its claimed report
effect chooses the explicitly held report owner.
"""
from __future__ import annotations

from functools import lru_cache
from weakref import ref
from .hia_cli_discovery_routing_native import NativeDiscoveryCli
from .hia_cli_native import CliSession

BUNDLE_SCHEMA = 'hepta.hia.cli-verified-report-bundle.v2'
RESOURCE_SCHEMA = 'hepta.hia.optional-profile-binding.v1'
RESOURCE_PROFILE = BUNDLE_SCHEMA
HOST_SOURCE_FILES = (
    'hepta/hia_optional_profiles.py', 'hepta/hia_program.py',
    'hepta/hia_schema.py', 'hepta/hia_opcodes.py',
    'hepta/hia_front_runtime.py', 'hepta/hia_front_continuation.py',
    'hepta/hia_exception_delivery.py', 'hepta/hia_json_preflight_native.py',
    'hepta/hia_machine_transport.py', 'hepta/hia_verified_report_native.py',
    'hepta/hia_verified_report_ports.py', 'hepta/hia_cli_verified_report_native.py',
)


def host_compatibility_sources():
    """Bind installed report owners and ports, independently of image claims."""
    from hashlib import sha256
    from pathlib import Path
    from .hia_optional_profiles import _read_bound_file
    package = Path(__file__).absolute().parent
    result = {}
    for name in HOST_SOURCE_FILES:
        raw = _read_bound_file(package, name.removeprefix('hepta/'), limit=1 << 20)
        result[name] = sha256(raw).hexdigest()
    return result


def _resource_binding(component, value):
    from pathlib import Path
    from .hia_cli_native import _relative_path
    from .hia_optional_profiles import fresh_profile_capture, VERIFIED_REPORT_HOST_PINS
    actual_hosts = host_compatibility_sources()
    fixed_hosts = set(HOST_SOURCE_FILES) - {'hepta/hia_optional_profiles.py'}
    if (type(VERIFIED_REPORT_HOST_PINS) is not dict or set(VERIFIED_REPORT_HOST_PINS) != fixed_hosts
            or any(actual_hosts[name] != digest for name, digest in VERIFIED_REPORT_HOST_PINS.items())):
        raise ValueError('installed report owners differ from the fixed HIA source compatibility anchor')
    if (type(value) is not dict or set(value) != {'schema', 'profile', 'source_root',
            'source_relative', 'source_sha256', 'identity', 'host_sources'}
            or value['schema'] != RESOURCE_SCHEMA or value['profile'] != RESOURCE_PROFILE
            or not _relative_path(value['source_root'])
            or value['source_relative'] != 'examples/hia_bootstrap/verified_report.hepta'
            or type(value['host_sources']) is not dict
            or value['host_sources'] != actual_hosts):
        raise ValueError('invalid or incompatible captured report resources')
    component = Path(component).absolute()
    root = component / value['source_root']
    # Capture through the actual component pathname. No resolve/reopen gap and
    # no second source read are permitted after the profile reader returns.
    identity, captures = fresh_profile_capture(RESOURCE_PROFILE, resource_root=root)
    if (type(value['identity']) is not dict or value['identity'] != identity
            or value['source_sha256'] != identity['files'][value['source_relative']]['sha256']):
        raise ValueError('captured report source differs from its fixed profile')
    return root, identity, captures[value['source_relative']]

_SESSION_CLASS = CliSession
_ORIGINAL_EFFECT = CliSession._effect
_ORIGINAL_EFFECT_CODE = _ORIGINAL_EFFECT.__code__


class NativeReportCli(NativeDiscoveryCli):
    def __init__(self, base, discovery, routing, parser_context, verified_report):
        super().__init__(base, discovery, routing, parser_context)
        self.verified_report = verified_report

    def prepare(self, argv, cli):
        session = super().prepare(argv, cli)
        # A replacement session/effect keeps its own actual behavior. No CLI
        # provider is evaluated early to decide whether this route is usable.
        if (type(session) is _SESSION_CLASS
                and _SESSION_CLASS.__dict__.get('_effect') is _ORIGINAL_EFFECT
                and _ORIGINAL_EFFECT.__code__ is _ORIGINAL_EFFECT_CODE
                and '_effect' not in session.__dict__):
            report_owner = self.verified_report
            held_session = ref(session)
            def report_effect(operation, a, b, c, d):
                current = held_session()
                if current is None:
                    raise RuntimeError('verified-report CLI session is no longer live')
                if operation != 9 or current.discovery_permission is not None:
                    return _ORIGINAL_EFFECT(current, operation, a, b, c, d)
                result = report_owner.invoke_bound_report(current.value(a).report)
                return current.register(result), 0, 0
            # A bound-method field would introduce a session -> method ->
            # session cycle and change the original retirement lifetime.
            session._effect = report_effect
        return session


@lru_cache(maxsize=3)
def _load_report_manifest(path, raw, source_sha):
    """Separate report mappings cannot evict the three original CLI images."""
    import json
    from pathlib import Path
    from .hia_cli_native import _relative_path
    from .hia_json_preflight_native import _unique_manifest_pairs
    from .hia_verified_report_native import NativeVerifiedReport, SCHEMA
    from .hia_optional_profiles import _read_bound_file
    value = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    keys = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256', 'profile_resources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))
            or value['source_sha256'] != source_sha or not _relative_path(value['image_path'])):
        raise ValueError('invalid or stale verified-report manifest')
    parent = Path(path).parent
    image = _read_bound_file(parent, value['image_path'], limit=1 << 20,
                            expected_sha256=value['image_sha256'])
    return NativeVerifiedReport(image, value['image_sha256'])


def installed_bundle(path, raw, bundle, *, strict=False):
    """Select an explicit six-image bundle with fresh manifests and sources.

    The original five companion fields keep their exact paths. Their loader
    still owns every old parser, formatter and discovery admission. The warm
    report route retains its immutable mapping; strict selection additionally
    rebinds the actual report image bytes on every call.
    """
    from hashlib import sha256
    import json
    from pathlib import Path
    from .hia_cli_native import _relative_path
    from .hia_cli_discovery_routing_native import CONTEXT_BUNDLE_SCHEMA, installed_bundle as installed_discovery
    from .hia_json_preflight_native import _unique_manifest_pairs
    from .hia_verified_report_native import NativeVerifiedReport, SOURCE, SCHEMA
    from .hia_optional_profiles import _read_bound_file

    original_components = ('control', 'format', 'discovery', 'routing', 'parser_context')
    expected_keys = {'schema', 'verified_report_manifest', 'verified_report_manifest_sha256',
                     *[name + suffix for name in original_components
                       for suffix in ('_manifest', '_manifest_sha256')]}
    if type(bundle) is not dict or set(bundle) != expected_keys or bundle['schema'] != BUNDLE_SCHEMA:
        raise ValueError('invalid optional verified-report CLI bundle')
    path = Path(path).absolute()
    children = {}
    metadata = {}
    for name in ('control', 'verified_report'):
        relative, digest = bundle[name + '_manifest'], bundle[name + '_manifest_sha256']
        if (not _relative_path(relative) or type(digest) is not str or len(digest) != 64
                or any(char not in '0123456789abcdef' for char in digest)):
            raise ValueError('invalid verified-report companion identity')
        target = path.parent / relative
        child_raw = _read_bound_file(path.parent, relative, limit=16384,
                                     expected_sha256=digest)
        if len(child_raw) > 16384 or sha256(child_raw).hexdigest() != digest:
            raise ValueError('verified-report companion manifest identity differs')
        children[name] = (target, child_raw)
        metadata[name] = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(child_raw.decode('utf-8'))
    control_metadata, report_metadata = metadata['control'], metadata['verified_report']
    report_keys = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256', 'profile_resources'}
    if (type(report_metadata) is not dict or set(report_metadata) != report_keys
            or report_metadata['schema'] != SCHEMA
            or not _relative_path(report_metadata['image_path'])):
        raise ValueError('invalid verified-report image manifest')
    for key in ('source_sha256', 'image_sha256', 'compiler_sha256'):
        digest = report_metadata[key]
        if type(digest) is not str or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest):
            raise ValueError('invalid verified-report image digest')
    # The original loader still validates all five real companion manifests.
    if type(control_metadata) is not dict or control_metadata.get('compiler_sha256') != report_metadata['compiler_sha256']:
        raise ValueError('verified-report and CLI companion compilers differ')
    resource_root, resource_identity, source_raw = _resource_binding(
        children['verified_report'][0].parent, report_metadata['profile_resources'])
    if sha256(source_raw).hexdigest() != report_metadata['source_sha256']:
        raise ValueError('verified-report source identity differs')
    image_path = image_raw = None
    if strict:
        image_path = children['verified_report'][0].parent / report_metadata['image_path']
        image_raw = _read_bound_file(image_path.parent, image_path.name, limit=1 << 20,
                                    expected_sha256=report_metadata['image_sha256'])
        if not 0 < len(image_raw) <= 1 << 20 or sha256(image_raw).hexdigest() != report_metadata['image_sha256']:
            raise ValueError('verified-report image identity differs')
    projection = {key: value for key, value in bundle.items()
                  if key not in ('verified_report_manifest', 'verified_report_manifest_sha256')}
    projection['schema'] = CONTEXT_BUNDLE_SCHEMA
    # The original loader binds the actual full six-image manifest bytes at
    # path before/after mapping, while owning its exact five-field projection.
    base = installed_discovery(path, raw, projection, strict=strict)
    if type(base) is not NativeDiscoveryCli or base.parser_context is None:
        raise ValueError('verified-report requires the original complete discovery CLI owner')
    report_owner = _load_report_manifest(str(children['verified_report'][0]), children['verified_report'][1],
                                         sha256(source_raw).hexdigest())
    if (_read_bound_file(path.parent, path.name, limit=16384) != raw
            or any(_read_bound_file(target.parent, target.name, limit=16384) != child_raw
                   for target, child_raw in children.values())
            or (strict and _read_bound_file(image_path.parent, image_path.name, limit=1 << 20) != image_raw)):
        raise ValueError('verified-report CLI changed while loading')
    final_root, final_identity, final_source = _resource_binding(
        children['verified_report'][0].parent, report_metadata['profile_resources'])
    if final_root != resource_root or final_identity != resource_identity or final_source != source_raw:
        raise ValueError('verified-report optional resource origin changed while loading')
    return NativeReportCli(base, base.discovery, base.routing, base.parser_context, report_owner)
