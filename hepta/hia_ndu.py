"""Call the original Rust NDU algorithms; all returned decisions are advisory.

The compiler's independent verifier must establish candidate legality. Neither a
``verified`` input nor a digest authenticates that fact, and this module never
issues safety or deployment credentials. Costs and continuation values are
supplied measurements/estimates with a declared scope, not performance proofs.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any

Q32 = 1 << 32
REQUEST_SCHEMA = "hepta.hia.ndu.request.v1"
MAX_REQUEST_BYTES = 1_048_576
RECURSIVE_BRIDGE_ENV = "HEPTA_RECURSIVE_NDU_BRIDGE"
RECURSIVE_IDENTITY_ENV = "HEPTA_RECURSIVE_NDU_IDENTITY"


class NduBridgeError(ValueError):
    """Invalid input, mismatched executable identity or rejected native request."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NduBridgeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(raw: bytes) -> dict[str, Any]:
    try:
        result = json.loads(raw, object_pairs_hook=_unique_object,
                            parse_constant=lambda value: (_ for _ in ()).throw(
                                NduBridgeError(f"non-finite JSON value: {value}")))
    except (ValueError, UnicodeError) as error:
        raise NduBridgeError(str(error)) from error
    if not isinstance(result, dict):
        raise NduBridgeError("expected a JSON object")
    return result


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def event(*, identity: str, instant_q32: int, discount_q32: int = Q32,
          preference_digest: str) -> dict[str, Any]:
    """Describe one actual/modeled continuation step, including refused work.

    Use a distinct identity for each physical step. A refusal still has its real
    negative cost; a stop step has no invented future improvement. The native
    implementation checks sequence, duplicate identities and discount bounds.
    """
    return {"event_digest": hashlib.sha256(identity.encode()).hexdigest(),
            "preference_digest": preference_digest, "instant_q32": instant_q32,
            "discount_q32": discount_q32}


def candidate(*, candidate_id: str, verified: bool, verification_digest: str,
              support_digest: str, events: list[dict[str, Any]], terminal_q32: int,
              resource_cost_q32: int = 0, risk_q32: int = 0,
              uncertainty_q32: int = 0) -> dict[str, Any]:
    """Bind an upstream decision to a value path without minting any authority."""
    return {"id": candidate_id, "verified": verified,
            "verification_digest": verification_digest, "support_digest": support_digest,
            "events": events, "terminal_q32": terminal_q32,
            "resource_cost_q32": resource_cost_q32, "risk_q32": risk_q32,
            "uncertainty_q32": uncertainty_q32}


class NduBridge:
    """Identity-checked subprocess transport for the bounded original NDU CLI.

    The identity manifest is a locally trusted build input. Hash checks detect
    drift; they do not provide remote attestation or defend a hostile build host.
    """

    @classmethod
    def from_environment(cls, *, timeout: float = 10.0):
        """Load only the explicitly configured recursive protocol and identity.

        The candidate-ranking bridge has a different protocol and build receipt.
        Its HEPTA_NDU_* variables are deliberately not fallback configuration.
        """
        executable = os.environ.get(RECURSIVE_BRIDGE_ENV)
        manifest = os.environ.get(RECURSIVE_IDENTITY_ENV)
        if not executable or not manifest:
            raise NduBridgeError(
                f"{RECURSIVE_BRIDGE_ENV} and {RECURSIVE_IDENTITY_ENV} are required")
        return cls(executable, manifest, timeout=timeout)

    def __init__(self, executable: str | os.PathLike[str],
                 identity_manifest: str | os.PathLike[str], *, timeout: float = 10.0):
        self.executable = Path(executable).resolve(strict=True)
        self.identity_manifest = Path(identity_manifest).resolve(strict=True)
        self.timeout = timeout
        self.manifest = _read_json(self.identity_manifest.read_bytes())
        if self.manifest.get("schema") != "hepta.hia.ndu.build.v1":
            raise NduBridgeError("unsupported build identity schema")
        if not 0 < timeout <= 120:
            raise NduBridgeError("timeout must be in (0, 120] seconds")
        self._verify_binary()
        observed = self._invoke(["--identity"], b"")
        if observed != self.manifest.get("identity"):
            raise NduBridgeError("native source identity does not match build manifest")

    def _verify_binary(self) -> None:
        if _sha256_file(self.executable) != self.manifest.get("binary_sha256"):
            raise NduBridgeError("native executable digest mismatch")

    def _invoke(self, arguments: list[str], payload: bytes) -> dict[str, Any]:
        try:
            completed = subprocess.run([str(self.executable), *arguments], input=payload,
                                       capture_output=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise NduBridgeError(f"native NDU execution failed: {error}") from error
        if len(completed.stdout) > 4 * MAX_REQUEST_BYTES:
            raise NduBridgeError("native response exceeds bound")
        result = _read_json(completed.stdout)
        if completed.returncode != 0 or result.get("status") == "error":
            raise NduBridgeError(str(result.get("error", "native NDU failed")))
        if result.get("authority") != "DENY_ALL" or result.get("safety_certificate") is not False:
            raise NduBridgeError("native transport attempted to confer authority")
        return result

    def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return original native recursion and feasibility/Pareto receipts.

        Missing/invalid/unknown inputs fail closed in the Rust typed protocol.
        A caller must independently reverify the chosen code before deployment.
        """
        try:
            payload = json.dumps(request, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False).encode()
        except (ValueError, TypeError) as error:
            raise NduBridgeError(str(error)) from error
        if len(payload) > MAX_REQUEST_BYTES:
            raise NduBridgeError("request exceeds 1 MiB")
        self._verify_binary()
        response = self._invoke([], payload)
        if response.get("schema") != "hepta.hia.ndu.response.v1" or response.get("status") != "advisory":
            raise NduBridgeError("unsupported native response")
        expected = {"objective_digest": request.get("objective_digest"),
                    "snapshot_digest": request.get("snapshot_digest"),
                    "generation": request.get("generation"),
                    "request_digest": hashlib.sha256(payload).hexdigest(),
                    "identity": self.manifest["identity"]}
        if any(response.get(key) != value for key, value in expected.items()):
            raise NduBridgeError("native response has stale or foreign bindings")
        candidates = {row["id"] for row in request.get("candidates", [])}
        if response.get("advisory_candidate_id") not in candidates | {None}:
            raise NduBridgeError("native response names an unknown candidate")
        return response
