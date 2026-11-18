"""Bind the operator-selected native file capture to the ordinary Agent tool."""
from hashlib import sha256
import os
from pathlib import Path
import struct

from .artifact_publication import PublicationRejected
from .artifact_publication_native import _binding_sources, _run_sealed_native
from .hia_agent_store import AgentRejected, _agent_resource_path
from .hia_native_helpers import _decode, _read


SELECTOR = 'HEPTA_HIA_AGENT_ARTIFACT_CAPTURE_MANIFEST'
SCHEMA = 'hepta.hia.agent-artifact-capture-build.v1'
SOURCE_NAME = 'examples/hia_bootstrap/agent_artifact_capture.hepta'
SOURCE = _agent_resource_path(SOURCE_NAME)
EXECUTABLE = 'hia-agent-artifact-capture'

ERRORS = {
    65: ('E_HIA_PATH', 'artifact paths must be absolute'),
    69: ('E_HIA_PATH', 'artifact traversal is not permitted'),
    70: ('E_HIA_PATH', 'artifact path contains an unavailable or unsafe component'),
    67: ('E_HIA_ARTIFACT_FILE', 'artifact is not a bounded ordinary file'),
    68: ('E_HIA_ARTIFACT_CHANGED', 'artifact changed while it was read'),
    71: ('E_HIA_ARTIFACT_FILE', 'cannot read authorized ordinary artifact'),
}


def _custody_error():
    return AgentRejected('E_HIA_ARTIFACT_NATIVE_CUSTODY',
                         'selected native artifact capture is unavailable or invalid')


def _admit(manifest):
    try:
        if not manifest:
            raise ValueError('explicit capture manifest is empty')
        path = Path(manifest)
        snapshot = _read(path, 1 << 20)
        record = _decode(snapshot.raw)
        _, sources = _binding_sources()
        if (type(record) is not dict or record.get('schema') != SCHEMA
                or record.get('status') != 'NATIVE_AGENT_ARTIFACT_CAPTURE_BUILT'
                or record.get('source_manifest') != sources
                or type(record.get('source_sha256')) is not dict
                or record['source_sha256'].get(SOURCE_NAME) != sha256(SOURCE.read_bytes()).hexdigest()
                or type(record.get('executable_manifest')) is not dict
                or set(record['executable_manifest']) != {'agent-artifact-capture'}):
            raise ValueError('selected native capture source or product differs')
        code = _read(path.parent / EXECUTABLE, 1 << 20).raw
        expected = {'name': EXECUTABLE, 'bytes': len(code), 'sha256': sha256(code).hexdigest()}
        if (record['executable_manifest']['agent-artifact-capture'] != expected
                or len(code) < 176 or code[:7] != b'\x7fELF\x02\x01\x01'
                or struct.unpack_from('<HH', code, 16) != (2, 62)
                or _read(path, 1 << 20) != snapshot):
            raise ValueError('selected native capture executable identity differs')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise _custody_error() from exc
    return code


def capture(manifest, path, roots, limit):
    # The public tool bounds this path to 4096 characters. NUL cannot be passed
    # through argv; preserve the original handling of that one transport case.
    if type(path) is not str or not os.path.isabs(path):
        raise AgentRejected(*ERRORS[65])
    if '\x00' in path:
        raise AgentRejected(*ERRORS[69])
    code = _admit(manifest)
    for root in roots or ('',):
        try:
            result = _run_sealed_native(code, (os.fspath(root), path, str(limit)), b'')
        except PublicationRejected as exc:
            raise _custody_error() from exc
        if result.stderr or (result.returncode and result.stdout):
            raise _custody_error()
        if result.returncode == 0 and len(result.stdout) <= limit:
            return result.stdout
        if result.returncode == 66:
            continue
        if result.returncode in ERRORS:
            raise AgentRejected(*ERRORS[result.returncode])
        raise _custody_error()
    raise AgentRejected('E_HIA_PATH_AUTHORITY', 'artifact path is outside configured roots')
