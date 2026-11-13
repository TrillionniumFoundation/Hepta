"""Private in-memory evidence for switching among already proved native images.

This module has no receipt import or deserialization API. The trusted runtime
constructs records only from its own successful proof/build/load operation.
Equivalence is transitive through the immutable baseline; a selection does not
need to solve the same pure, total scalar theorem again. It still checks state,
Core, implementation, artifact, actual mappings and safe-point generation.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .hia_program import verify_program


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class _PreparedProof:
    scope: str
    root_core: str
    core: str
    state: str
    artifact: str
    implementation: str
    policy: str
    build_receipt: str
    proof: str
    depth: int


def _issue(image, *, parent, implementation, policy, scope):
    """Called after the runtime itself proved, built and sealed this image."""
    checked = verify_program(image.program)
    receipt = image.receipt
    proof, native = receipt.get("verification", {}), receipt.get("native", {})
    expected_base = parent.core if parent else checked.sha256
    if (receipt.get("schema") != "hepta.hia.optimized-native.v1"
            or receipt.get("status") != "verified_core_native_bound"
            or proof.get("status") != "verified"
            or proof.get("base_sha256") != expected_base
            or proof.get("candidate_sha256") != checked.sha256
            or proof.get("policy_sha256") != _digest(policy)
            or native.get("core_sha256") != checked.sha256
            or native.get("artifact_sha256") != image.artifact_sha256
            or native.get("target") != image.state["target"]
            or type(proof.get("verification_sha256")) is not str):
        raise ValueError("E_PREPARED_PROOF: internal proof/build bindings are incomplete")
    if parent and (parent.scope != scope or parent.implementation != implementation or parent.policy != _digest(policy)
                   or parent.state != _digest(image.state)):
        raise ValueError("E_PREPARED_PROOF: parent proof uses another implementation, policy or state")
    return _PreparedProof(scope=scope, root_core=parent.root_core if parent else checked.sha256,
                          core=checked.sha256, state=_digest(image.state),
                          artifact=image.artifact_sha256, implementation=implementation,
                          policy=_digest(policy), build_receipt=_digest(receipt),
                          proof=proof["verification_sha256"], depth=parent.depth + 1 if parent else 0)


def _matches(record, image, *, implementation, policy, scope):
    if type(record) is not _PreparedProof:
        return False
    # VerifiedProgram is public and forgeable; recheck its actual canonical
    # bytes and primitive resource/CFG rules instead of trusting its type.
    checked = verify_program(image.program)
    return (record.scope == scope and record.core == checked.sha256 and record.state == _digest(image.state)
            and record.artifact == image.artifact_sha256
            and record.implementation == implementation and record.policy == _digest(policy)
            and record.build_receipt == _digest(image.receipt))


def _reuse(base_record, base, candidate_record, candidate, *, implementation, policy, scope):
    if (not _matches(base_record, base, implementation=implementation, policy=policy, scope=scope)
            or not _matches(candidate_record, candidate, implementation=implementation, policy=policy, scope=scope)
            or base_record.root_core != candidate_record.root_core
            or base_record.state != candidate_record.state):
        raise ValueError("E_PREPARED_PROOF: no intact internal equivalence path")
    return {"schema": "hepta.hia.prepared-equivalence-use.v1", "root_core_sha256": base_record.root_core,
            "base_sha256": base_record.core, "candidate_sha256": candidate_record.core,
            "base_proof_sha256": base_record.proof, "candidate_proof_sha256": candidate_record.proof,
            "base_depth": base_record.depth, "candidate_depth": candidate_record.depth,
            "proof_source": "successful-internal-admission-only", "new_solver_call": False,
            "serialized_receipt_authority": False}
