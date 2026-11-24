"""Admit the source-owned HIA scalar NDU executable and its build custody.

The compatibility response retains the upstream wire identities; this separate
image identity explicitly records that the executable implementation is HIA.
Executable sealing, time budgets and process ownership stay with the existing
prepared/one-shot transport.  There is no interpreter or foreign evaluator here.
"""
from hashlib import sha256
import json
from pathlib import Path

SCHEMA = 'hepta.hia.ndu-scalar-build.v1'
UPSTREAM = 'd3c2d760eca5065fc966820379c35c6e8d56e855'
PROFILE = 'hia-total-cost-ms-v1'
BINARY_RESOURCE = '_hia_ndu_scalar.elf'
RECEIPT_RESOURCE = '_hia_ndu_scalar_build.json'
RECEIPT_FIELDS = frozenset((
    'schema', 'implementation', 'profile', 'scope', 'compatibility_upstream_commit',
    'executable_path', 'executable_sha256', 'source_sha256', 'compiler_sha256',
    'cold_report_sha256', 'transport_adapter_sha256', 'transport_assembled_during_build',
    'build_inputs_unchanged', 'executable', 'native_compile_receipt',
    'native_packer_receipt', 'native_pack_receipt',
))
SOURCES = (
    'examples/hia_bootstrap/ndu_scalar.hepta',
    'examples/hia_bootstrap/ndu_scalar_packer.hepta',
    'tools/generate_hia_ndu_scalar.py',
    'tools/generate_hia_ndu_scalar_packer.py',
    'tools/hia_ndu_scalar_syscalls.S',
    'tools/build_hia_ndu_scalar.py',
    'tools/generate_hia_sha256.py',
    'tools/generate_hia_native_filter.py',
    'tools/build_hia_default_release.py',
    'tools/hia_wheel_backend.py',
    'hepta/hia_ndu_native.py',
    'hepta/hia_ndu_optimizer.py',
    'hepta/hia_agent_macro_policy.py',
    'hepta/hia_ndu_prepared_ranker.py',
    'hepta/hia_ndu_persistent_ranker.py',
    'tests/test_hia_ndu_scalar_native.py',
)


def default_ndu_bridge():
    """Select only the package-owned HIA image; absent source builds stay absent."""
    from .hia_ndu_optimizer import _reject

    directory = Path(__file__).resolve().parent
    binary, receipt = directory / BINARY_RESOURCE, directory / RECEIPT_RESOURCE
    present = binary.exists(), receipt.exists()
    if present == (False, False):
        # Editable imports retain the source anchor while distribution-owned
        # resources live beside that interpreter's installed metadata. Source
        # custody below must still match every active component input exactly.
        from importlib.metadata import PackageNotFoundError, distribution
        try:
            installed = distribution('hia-core')
        except PackageNotFoundError:
            return None
        binary = Path(installed.locate_file('hepta/' + BINARY_RESOURCE))
        receipt = Path(installed.locate_file('hepta/' + RECEIPT_RESOURCE))
        present = binary.exists(), receipt.exists()
        if present == (False, False):
            return None
    if present != (True, True):
        _reject('installed HIA NDU image and receipt must both be present')
    return {'binary': str(binary), 'build_receipt': str(receipt)}


def admit_ndu_bridge(binary, receipt_raw, receipt):
    """Recompute component/binary pins from actual bytes before native sealing."""
    from .hia_json_preflight_native import _source_resource_path
    from .hia_ndu_optimizer import _VerifiedBridgeImage, _read_file, _reject

    if (type(receipt) is not dict or set(receipt) != RECEIPT_FIELDS
            or receipt.get('schema') != SCHEMA
            or receipt.get('scope') != 'MATCHING_SOURCE_COLD_COMPONENT'
            or receipt.get('implementation') != 'HIA'
            or receipt.get('executable_path') != 'hia-ndu-scalar'
            or receipt.get('compatibility_upstream_commit') != UPSTREAM
            or receipt.get('profile') != PROFILE
            or receipt.get('build_inputs_unchanged') is not True
            or receipt.get('transport_assembled_during_build') is not False):
        _reject('HIA NDU requires its matching-source cold native build receipt')
    expected = {name: sha256(_read_file(_source_resource_path(name), 8 << 20)).hexdigest()
                for name in SOURCES}
    if receipt.get('source_sha256') != expected:
        _reject('HIA NDU source differs from its build custody')
    for field in ('compiler_sha256', 'cold_report_sha256', 'executable_sha256'):
        value = receipt.get(field)
        if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            _reject('HIA NDU build identity has an invalid digest')
    data = _read_file(binary, 8 << 20)
    if (not data.startswith(b'\x7fELF\x02\x01\x01')
            or sha256(data).hexdigest() != receipt['executable_sha256']):
        _reject('HIA NDU executable differs from its exact build identity')
    return _VerifiedBridgeImage(binary, data), {
        'upstream_commit': UPSTREAM,
        'binary_sha256': receipt['executable_sha256'],
        'build_receipt_sha256': sha256(receipt_raw).hexdigest(),
        'build_inputs_sha256': sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'source_attestation': 'trusted_local_matching_source_cold_hia_build',
        'implementation': 'HIA',
        'profile': PROFILE,
    }
