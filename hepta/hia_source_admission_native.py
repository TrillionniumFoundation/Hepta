"""Explicit HIA owner for one fresh checkout source-digest map.

HIA owns union/order/deduplication, read claims, SHA-256 and complete-map
decisions. The fixed transport performs Path enumeration/read/close and exact
object/byte transport. It never hashes the admitted file contents in Python.
This component has no default-selector hook and imports no authoring tools.
A pinned image may create independent fresh invocations; each invocation is
single-use. The retained state is cooperative-host custody, not a process sandbox.
"""
from __future__ import annotations
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import struct
import threading

from .hia_json_preflight_native import (
    MAX_IMAGE_BYTES, NativeHiaJsonImage, _source_resource_path,
)

SOURCE_NAME = 'examples/hia_bootstrap/source_admission.hepta'
SOURCE = _source_resource_path(SOURCE_NAME)
SCHEMA = 'hepta.hia.source-admission-native.v1'
MAX_MANIFEST_BYTES = 16384
WORD = struct.Struct('<Q')
RECEIPT = struct.Struct('<6Q')


class SourceAdmissionUnknown(RuntimeError):
    pass


class SourceAdmissionRefused(RuntimeError):
    pass


def packet(operation, nonce, sequence=0, payload=None):
    """Fixed transport encoding, without source-policy decisions."""
    if payload is None:
        return struct.pack('<3Q', operation, nonce, sequence)
    return struct.pack('<4Q', operation, nonce, sequence, len(payload)) + payload


class NativeSourceAdmissionImage(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256, source_path, source_sha256):
        # Custody hashes bind executable/source bytes, never user file contents.
        raw = Path(source_path).read_bytes()
        if sha256(raw).hexdigest() != source_sha256:
            raise ValueError('native checkout source owner source identity mismatch')
        super().__init__(image, expected_sha256)
        self.source_sha256 = source_sha256
        self.source_path = str(source_path)

    def create(self, *, nonce=None):
        return NativeFileDigests(self, nonce=nonce)


class NativeFileDigests:
    """One explicit invocation, retained HIA state and at-most-once transport.

    A failed/unknown invocation is never resumed or converted to a partial map.
    New independent invocations perform their own fresh filesystem observations.
    In particular, no observed header reconstructs authority after lost ACK.
    """
    def __init__(self, image, *, nonce=None):
        self.image = image
        self.nonce = (secrets.randbits(64) or 1) if nonce is None else nonce
        if type(self.nonce) is not int or not 0 < self.nonce < (1 << 64):
            raise ValueError('nonce must be a nonzero u64')
        self.pid = os.getpid()
        self.lock = threading.RLock()
        self.state = ctypes.create_string_buffer(1536)
        self.output = ctypes.create_string_buffer(48)
        self.started = False
        self.pending = None
        self.last = None
        self.failure = None
        self.failure_receipt = None
        self.complete = False
        self.handles = []
        self.calls = 0
        self.reads = 0
        self.bytes_read = 0

    def _invoke(self, wire):
        if os.getpid() != self.pid:
            raise SourceAdmissionRefused('native source owner belongs to another process')
        if self.pending is not None:
            raise SourceAdmissionUnknown('native source owner has an unacknowledged transition')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        # Claim is published before entry.  If return/receipt publication is
        # interrupted, the retained claim cannot grant a second native call.
        self.pending = (wire, source, self.output, self.state)
        self.calls += 1
        result = self.image._entry(source, len(wire), self.output, len(self.output),
                                   self.state, len(self.state))
        reply = RECEIPT.unpack_from(self.output)
        if result != reply[0] or result not in (0, 1, 4, 16):
            raise SourceAdmissionUnknown('invalid native source owner receipt')
        if result in (0, 1, 4) and reply[2] != self.nonce:
            raise SourceAdmissionUnknown('native source owner receipt nonce mismatch')
        self.last = reply
        self.pending = None
        return reply

    def _initialize(self, declared, dynamic):
        self.handles = list(declared)
        self.handles.extend(dynamic)
        wire = bytearray(struct.pack('<4Q', 0, self.nonce, len(declared), len(dynamic)))
        for i, name in enumerate(self.handles):
            # SOURCE_FILES and Path.as_posix produce exact str in this explicit
            # checkout profile.  Do not coerce arbitrary user objects to str.
            if type(name) is not str:
                raise TypeError('native checkout path transport requires exact str')
            raw = name.encode('utf-8', 'surrogatepass')
            wire += struct.pack('<2Q', i, len(raw))
            wire += raw
        wire = bytes(wire)
        reply = self._invoke(wire)
        if reply[0:2] == (1, 5):
            required = reply[5]
            if required <= len(self.state) or any(self.state.raw):
                raise SourceAdmissionUnknown('invalid no-effect state growth receipt')
            self.state = ctypes.create_string_buffer(required)
            reply = self._invoke(wire)
        if reply[0:2] != (0, 0) or reply[3] != 0:
            raise SourceAdmissionRefused('native checkout path admission refused')
        if reply[4] > len(self.handles) or reply[5] > len(self.state):
            raise SourceAdmissionUnknown('invalid initialized native source extent')
        return reply

    def _foreign_failure(self, error, sequence):
        # This note is diagnostic only.  Failure to record it cannot authorize
        # a repeated read or replace the original filesystem exception.
        self.failure = error
        try:
            wire = struct.pack('<4Q', 3, self.nonce, sequence, 1)
            self.failure_receipt = self._invoke(wire)
        except BaseException:
            pass

    def run(self, root, declared):
        with self.lock:
            if self.started:
                raise SourceAdmissionRefused('native source invocation is single-use')
            self.started = True
            try:
                root = Path(root)
                # No set()/sorted()/hash here.  Enumeration has the original
                # Path boundary, and completes before any source file is read.
                declared = tuple(declared)
                dynamic = [p.relative_to(root).as_posix()
                           for p in (root / 'hepta').rglob('*.py')]
                reply = self._initialize(declared, dynamic)
                sequence = reply[3]
                admitted_count = reply[4]
                while True:
                    wire = packet(1, self.nonce, sequence)
                    reply = self._invoke(wire)
                    if reply[0:2] == (1, 6):
                        if reply[5] <= len(self.output):
                            raise SourceAdmissionUnknown('invalid no-effect output growth receipt')
                        self.output = ctypes.create_string_buffer(reply[5])
                        reply = self._invoke(wire)
                    if reply[0] != 0:
                        raise SourceAdmissionRefused('native source owner refused next transition')
                    if reply[1] == 2:
                        count = reply[4]
                        if (reply[3] != sequence or count != sequence or count != admitted_count
                                or count > len(self.handles)
                                or reply[5] != 48 + count * 72 or reply[5] > len(self.output)):
                            raise SourceAdmissionUnknown('invalid completed native map extent')
                        # Map order/keys/digests are solely the completed native
                        # result.  The bridge only resolves retained handles.
                        result = {}
                        for i in range(count):
                            offset = 48 + i * 72
                            handle = WORD.unpack_from(self.output, offset)[0]
                            if handle >= len(self.handles):
                                raise SourceAdmissionUnknown('native map handle outside retained transport')
                            name = self.handles[handle]
                            digest = self.output.raw[offset+8:offset+72].decode('ascii')
                            if name in result or any(c not in '0123456789abcdef' for c in digest):
                                raise SourceAdmissionUnknown('malformed native digest map record')
                            result[name] = digest
                        self.complete = True
                        return result
                    if reply[1] != 1:
                        raise SourceAdmissionUnknown('unexpected native source owner action')
                    if (reply[3] != sequence + 1 or reply[3] > admitted_count
                            or reply[4] >= len(self.handles)
                            or reply[5] != len(self.handles[reply[4]].encode('utf-8', 'surrogatepass'))):
                        raise SourceAdmissionUnknown('native read claim does not match retained transport')
                    sequence = reply[3]
                    name = self.handles[reply[4]]
                    try:
                        self.reads += 1
                        contents = (root / name).read_bytes()
                    except BaseException as error:
                        self._foreign_failure(error, sequence)
                        raise
                    self.bytes_read += len(contents)
                    reply = self._invoke(packet(2, self.nonce, sequence, contents))
                    del contents
                    if reply[0:2] != (0, 0) or reply[3] != sequence:
                        raise SourceAdmissionRefused('native source digest outcome refused')
            except BaseException as error:
                self.failure = error
                raise

    def snapshot(self):
        """Read-only local custody; never manufactures continuation authority."""
        with self.lock:
            return {'started': self.started, 'complete': self.complete,
                    'pending': self.pending is not None, 'last': self.last,
                    'failure_type': None if self.failure is None else type(self.failure).__name__,
                    'failure_receipt': self.failure_receipt, 'calls': self.calls,
                    'reads': self.reads, 'bytes_read': self.bytes_read,
                    'state_bytes': len(self.state), 'state': self.state.raw}



def native_file_digests(root, image, *, source_files):
    """Explicit operation; the caller supplies its exact declared source tuple.

    There is deliberately no import of file_digests/current_sources here. That
    avoids both an installed tools dependency and recursive cold admission.
    """
    return image.create().run(root, source_files)


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate native source-admission manifest field')
        value[key] = item
    return value


def _read_limit(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('native source-admission input exceeds its fixed code/manifest profile')
    return raw


@lru_cache(maxsize=3)
def _mapped(image, image_sha256, source_path, source_sha256):
    return NativeSourceAdmissionImage(image, image_sha256, source_path, source_sha256)


def installed_source_admission(manifest_path):
    """Freshly admit one explicit operator-selected immutable image.

    Manifest, package-owned HIA and image bytes are freshly read on every call,
    including warm mapping hits. No checkout/cwd fallback is permitted after
    installation. Existing returned objects keep their immutable mapping; a
    later selection cannot replace those bytes or resume a failed invocation.
    This local executable selection is not a cold/full qualification receipt.
    """
    path = Path(manifest_path).resolve(strict=True)
    raw = _read_limit(path, MAX_MANIFEST_BYTES)
    manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    keys = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
    if (type(manifest) is not dict or set(manifest) != keys
            or manifest['schema'] != SCHEMA
            or any(type(manifest[k]) is not str or len(manifest[k]) != 64
                   or any(c not in '0123456789abcdef' for c in manifest[k])
                   for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native source-admission manifest')
    filename = manifest['image_path']
    if (type(filename) is not str or not filename or filename in {'.', '..'}
            or '\x00' in filename or Path(filename).name != filename):
        raise ValueError('native source-admission image must be a sibling basename')
    source_bytes = SOURCE.read_bytes()
    if sha256(source_bytes).hexdigest() != manifest['source_sha256']:
        raise ValueError('native source-admission source identity mismatch')
    image_path = path.parent / filename
    image = _read_limit(image_path, MAX_IMAGE_BYTES)
    if not image or sha256(image).hexdigest() != manifest['image_sha256']:
        raise ValueError('native source-admission executable identity mismatch')
    selected = _mapped(image, manifest['image_sha256'], str(SOURCE),
                       manifest['source_sha256'])
    if (path.read_bytes() != raw or SOURCE.read_bytes() != source_bytes
            or image_path.read_bytes() != image):
        raise ValueError('native source-admission selection changed during admission')
    return selected
