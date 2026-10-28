"""Bounded exact-request reuse of advisory, identity-bound native NDU results.

Reuse applies only to the identical canonical request, including its snapshot,
generation, budget and support. It never caches a proof, native program or
publication permission. The current compiler consumer must still perform its
fresh resource, equivalence, artifact and deployment checks.
"""
from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import threading
import time

from .hia_ndu import MAX_REQUEST_BYTES, NduBridge, NduBridgeError, _read_json

SCHEMA = "hepta.hia.ndu.exact-request-reuse.v1"
_MAX_IDENTITY_BYTES = 4 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * MAX_REQUEST_BYTES
_RESPONSE_KEYS = frozenset({"schema", "status", "request_digest", "objective_digest", "snapshot_digest",
    "generation", "identity", "authority", "safety_certificate", "optimality_scope", "disposition",
    "advisory_candidate_id", "evaluated_candidate_ids", "pareto_candidate_ids", "rejected",
    "evaluation_digest", "evaluation_policy_digest", "utility_profile_digest", "paths"})
_PATH_KEYS = frozenset({"id", "verification_digest", "support_digest", "values_q32",
    "recursive_evidence_digest", "resource_cost_q32", "risk_q32", "projection_count"})


def _wire(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError, UnicodeError) as error:
        raise NduBridgeError("decision reuse: invalid JSON: " + str(error)) from error


def _identity_bytes(path):
    """Reject replaced, nonregular, oversized or concurrently changed receipts."""
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")):
        raise NduBridgeError("decision reuse requires no-follow regular-file descriptor support")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_IDENTITY_BYTES:
                raise NduBridgeError("decision reuse: invalid identity receipt")
            data = stream.read(_MAX_IDENTITY_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = Path(path).lstat()
    except OSError as error:
        raise NduBridgeError("decision reuse: identity receipt unavailable: " + str(error)) from error
    fields = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                           item.st_mtime_ns, item.st_ctime_ns)
    if len(data) != before.st_size or fields(before) != fields(after) or fields(after) != fields(current):
        raise NduBridgeError("decision reuse: identity receipt changed during read")
    return data


def _validate_response(response, request, payload, manifest):
    if (type(response) is not dict or set(response) != _RESPONSE_KEYS
            or response.get("schema") != "hepta.hia.ndu.response.v1"
            or response.get("status") != "advisory"
            or response.get("authority") != "DENY_ALL"
            or response.get("safety_certificate") is not False
            or response.get("optimality_scope") != "bounded-supplied-candidate-paths-only"
            or type(response.get("generation")) is not int
            or type(response.get("disposition")) is not str):
        raise NduBridgeError("decision reuse: response schema or authority changed")
    expected = {"objective_digest": request.get("objective_digest"),
                "snapshot_digest": request.get("snapshot_digest"),
                "generation": request.get("generation"),
                "request_digest": sha256(payload).hexdigest(), "identity": manifest["identity"]}
    if any(response.get(name) != value for name, value in expected.items()):
        raise NduBridgeError("decision reuse: stale or foreign response bindings")
    try:
        inputs = {row["id"]: row for row in request["candidates"]}
        candidates = set(inputs)
        chosen = response["advisory_candidate_id"]
        if chosen not in candidates | {None}:
            raise NduBridgeError("decision reuse: response names an unknown candidate")
        for name in ("evaluation_digest", "evaluation_policy_digest", "utility_profile_digest"):
            value = response[name]
            if type(value) is not str or not re.fullmatch("[0-9a-f]{64}", value) or value == "0" * 64:
                raise NduBridgeError("decision reuse: malformed evaluation digest")
        sets = {}
        for name in ("evaluated_candidate_ids", "pareto_candidate_ids"):
            values = response[name]
            if (type(values) is not list or any(type(x) is not str for x in values)
                    or len(values) != len(set(values)) or not set(values) <= candidates):
                raise NduBridgeError("decision reuse: malformed candidate frontier")
            sets[name] = set(values)
        if not sets["pareto_candidate_ids"] <= sets["evaluated_candidate_ids"]:
            raise NduBridgeError("decision reuse: foreign Pareto candidate")
        if chosen is not None and chosen not in sets["pareto_candidate_ids"]:
            raise NduBridgeError("decision reuse: selected candidate outside admitted frontier")
        evaluated, frontier = sets["evaluated_candidate_ids"], sets["pareto_candidate_ids"]
        disposition = response["disposition"]
        consistent = {
            "InfeasibleExplicitAbstain": evaluated == frontier == {"abstain"} and chosen == "abstain",
            "UniqueParetoRecommendation": (len(frontier) == 1 and chosen in frontier
                                            and evaluated != {"abstain"}),
            "ParetoSetRequiresSlowPath": len(frontier) > 1 and chosen is None,
        }
        if not consistent.get(disposition, False):
            raise NduBridgeError("decision reuse: disposition disagrees with selected frontier")
        rejected = response["rejected"]
        if type(rejected) is not list:
            raise NduBridgeError("decision reuse: malformed rejection list")
        denied = set()
        for row in rejected:
            if (type(row) is not dict or set(row) != {"id", "reasons"}
                    or row["id"] not in candidates or row["id"] in denied
                    or type(row["reasons"]) is not list or not row["reasons"]
                    or any(type(x) is not str for x in row["reasons"])):
                raise NduBridgeError("decision reuse: malformed rejection entry")
            denied.add(row["id"])
        if denied & sets["evaluated_candidate_ids"] or denied | sets["evaluated_candidate_ids"] != candidates:
            raise NduBridgeError("decision reuse: incomplete evaluation partition")
        paths = response["paths"]
        if type(paths) is not list or len(paths) != len(candidates):
            raise NduBridgeError("decision reuse: malformed path inventory")
        seen = set()
        for row in paths:
            if (type(row) is not dict or set(row) != _PATH_KEYS or row["id"] not in candidates
                    or row["id"] in seen):
                raise NduBridgeError("decision reuse: malformed path entry")
            seen.add(row["id"])
            original = inputs[row["id"]]
            if (type(row["resource_cost_q32"]) is not int or not 0 <= row["resource_cost_q32"] < (1 << 63)
                    or type(row["risk_q32"]) is not int or not 0 <= row["risk_q32"] <= (1 << 32)):
                raise NduBridgeError("decision reuse: path costs and risk must be exact bounded integers")
            if any(row[name] != original[name] for name in ("verification_digest", "support_digest",
                                                            "resource_cost_q32", "risk_q32")):
                raise NduBridgeError("decision reuse: stale path bindings")
            values, proof = row["values_q32"], row["recursive_evidence_digest"]
            if (type(values) is not list or len(values) != len(original["events"]) + 1
                    or any(type(v) is not int or not -(1 << 63) <= v < (1 << 63) for v in values)
                    or type(row["projection_count"]) is not int or row["projection_count"] != 0
                    or type(proof) is not str or not re.fullmatch("[0-9a-f]{64}", proof)
                    or proof == "0" * 64):
                raise NduBridgeError("decision reuse: malformed recursive path")
    except (KeyError, TypeError) as error:
        raise NduBridgeError("decision reuse: malformed request or response") from error


class NduDecisionCache:
    """One bounded in-memory owner for exact native advisory responses.

    Concurrent identical calls are serialized, so one native invocation can
    serve later identical requests. Entries are immutable serialized bytes.
    Every access rechecks the admitted build receipt, bridge object, executable
    bytes, implementation bytes and response bindings. This is local drift
    detection under the existing trusted-host boundary, not remote attestation.
    """
    def __init__(self, bridge, *, max_entries=16, max_bytes=8 * 1024 * 1024):
        if not isinstance(bridge, NduBridge):
            raise NduBridgeError("decision reuse requires an admitted native NduBridge")
        if type(max_entries) is not int or not 1 <= max_entries <= 128:
            raise NduBridgeError("decision reuse entries must be an integer in 1..128")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 * 1024:
            raise NduBridgeError("decision reuse bytes must be an integer in 1..67108864")
        self._bridge = bridge
        self._max_entries, self._max_bytes = max_entries, max_bytes
        self._identity_path = Path(bridge.identity_manifest)
        self._executable_path = Path(bridge.executable)
        self._identity_raw = _identity_bytes(self._identity_path)
        self._manifest_raw = _wire(bridge.manifest)
        if _wire(_read_json(self._identity_raw)) != self._manifest_raw:
            raise NduBridgeError("decision reuse: bridge and file identities differ")
        self._implementation = self._implementation_digest()
        self._binding = sha256(_wire({"schema": SCHEMA,
            "manifest_sha256": sha256(self._manifest_raw).hexdigest(),
            "implementation_sha256": self._implementation})).hexdigest()
        self._entries = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()
        self._closed = False
        self._counts = {"hits": 0, "misses": 0, "native_evaluation_attempts": 0,
                        "evictions": 0, "oversize_not_retained": 0, "failures": 0}
        self._verify_identity()

    @staticmethod
    def _implementation_digest():
        from . import hia_ndu
        paths = [Path(__file__), Path(hia_ndu.__file__)]
        return sha256(_wire({path.name: sha256(path.read_bytes()).hexdigest()
                             for path in paths})).hexdigest()

    def _verify_identity(self):
        if self._closed:
            raise NduBridgeError("decision reuse owner is closed")
        if (Path(self._bridge.identity_manifest) != self._identity_path
                or Path(self._bridge.executable) != self._executable_path
                or _wire(self._bridge.manifest) != self._manifest_raw
                or _identity_bytes(self._identity_path) != self._identity_raw
                or self._implementation_digest() != self._implementation):
            raise NduBridgeError("decision reuse: admitted identity or implementation drift")
        self._bridge._verify_binary()

    def evaluate_with_receipt(self, request):
        started = time.monotonic_ns()
        payload = _wire(request)
        if len(payload) > MAX_REQUEST_BYTES:
            raise NduBridgeError("decision reuse request exceeds 1 MiB")
        frozen = _read_json(payload)
        key = sha256(self._binding.encode() + b"\0" + payload).hexdigest()
        with self._lock:
            try:
                self._verify_identity()
                row = self._entries.get(key)
                reused = row is not None
                if reused:
                    original_payload, response_raw, response_sha, charged_bytes = row
                    if original_payload != payload or sha256(response_raw).hexdigest() != response_sha:
                        self._bytes -= charged_bytes
                        del self._entries[key]
                        raise NduBridgeError("decision reuse: corrupted entry")
                    response = _read_json(response_raw)
                    _validate_response(response, frozen, payload, self._bridge.manifest)
                    self._entries.move_to_end(key)
                    self._counts["hits"] += 1
                else:
                    self._counts["misses"] += 1
                    self._counts["native_evaluation_attempts"] += 1
                    response = self._bridge.evaluate(frozen)
                    _validate_response(response, frozen, payload, self._bridge.manifest)
                    response_raw = _wire(response)
                    if len(response_raw) > _MAX_RESPONSE_BYTES:
                        raise NduBridgeError("decision reuse native response exceeds 4 MiB")
                    # Do not retain a result if the executable, receipt or
                    # implementation changed during the native invocation.
                    self._verify_identity()
                    cost = len(payload) + len(response_raw)
                    if cost > self._max_bytes:
                        self._counts["oversize_not_retained"] += 1
                    else:
                        while self._entries and (len(self._entries) >= self._max_entries
                                                  or self._bytes + cost > self._max_bytes):
                            _, old = self._entries.popitem(last=False)
                            self._bytes -= old[3]
                            self._counts["evictions"] += 1
                        self._entries[key] = (payload, response_raw, sha256(response_raw).hexdigest(), cost)
                        self._bytes += cost
                # Parsing yields a fresh object even for the first caller;
                # neither caller-owned requests nor results enter retained state.
                answer = _read_json(response_raw)
                # Hits also recheck after parsing/validating the cached bytes;
                # identity drift during that work cannot return old advice.
                self._verify_identity()
                receipt = {"schema": SCHEMA, "request_sha256": sha256(payload).hexdigest(),
                    "binding_sha256": self._binding, "response_sha256": sha256(response_raw).hexdigest(),
                    "reused_exact_response": reused, "native_invoked": not reused,
                    "wall_ns": time.monotonic_ns() - started,
                    "authority": "DENY_ALL", "safety_certificate": False,
                    "fresh_native_evaluation_claim": not reused,
                    "compiler_publication_authorized": False}
                return answer, receipt
            except Exception:
                self._counts["failures"] += 1
                raise

    def evaluate(self, request):
        return self.evaluate_with_receipt(request)[0]

    def is_bound_to(self, bridge):
        return self._bridge is bridge

    @property
    def timeout(self):
        return self._bridge.timeout

    @timeout.setter
    def timeout(self, value):
        if type(value) not in {int, float} or not 0 < value <= 120:
            raise NduBridgeError("decision reuse timeout must be in (0,120]")
        self._bridge.timeout = value

    def statistics(self):
        with self._lock:
            return {"schema": SCHEMA, **self._counts, "entries": len(self._entries),
                    "retained_payload_bytes": self._bytes, "max_entries": self._max_entries,
                    "max_payload_bytes": self._max_bytes, "closed": self._closed,
                    "binding_sha256": self._binding, "authority": "DENY_ALL",
                    "safety_certificate": False, "resource_scope": "request and response byte payloads; Python object overhead excluded"}

    def close(self):
        with self._lock:
            self._entries.clear()
            self._bytes = 0
            self._closed = True
            return self.statistics()

    def __copy__(self):
        raise NduBridgeError("decision reuse has one synchronization owner")

    def __deepcopy__(self, memo):
        return self.__copy__()
