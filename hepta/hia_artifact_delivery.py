"""Custody of one explicit artifact-provider invocation and its actual receipt.

Only the private entry's complete nonce-bound HIA acknowledgement can confirm
handoff. An ordinary public CLI exit code is never a negative acknowledgement.
No payload is re-read or hashed here, and no operation is retried.
"""
from __future__ import annotations

from contextvars import ContextVar
import os

from .hia_artifact_delivery_protocol import (
    RETURNED, REFUSED, acknowledgement, control_descriptor,
)
from .hia_native_delivery import DeliveryRecord


class ArtifactDeliveryUnknown(RuntimeError):
    """An actual artifact native handoff lacks a confirmed complete result."""


_CURRENT = ContextVar('hia_artifact_provider_delivery', default=None)
_REQUEST_REJECTIONS = (ValueError, OSError, TypeError, OverflowError, RecursionError)
_OPERATIONS = {'publish': 1, 'verify': 2, 'withdraw': 3,
               'store-put': 4, 'store-get': 5, 'store-hash': 6}


class ArtifactInvocation:
    """Transport lifetime spanning code custody, process and public receipt."""
    def __init__(self, operation):
        self.operation = operation
        self.claimed = False
        self.armed = False
        self.acknowledgement = None
        self.descriptor_error = None
        self.record = self.activation = self.token = None
        self.nonce = None
        self.payload_bytes = None

    def __enter__(self):
        self.record = DeliveryRecord(self)
        try:
            self.nonce = os.urandom(16)
            self.activation = self.record.foreign(observation=False)
            self.activation.__enter__()
        except BaseException:
            self.record.retire()
            raise
        return self

    def __exit__(self, kind, error, traceback):
        try:
            if error is not None:
                self.record.failed(error)
                self.record.propagate(error, ArtifactDeliveryUnknown, _REQUEST_REJECTIONS)
            else:
                self.record.check(ArtifactDeliveryUnknown)
                if not self.record.terminal:
                    missing = ArtifactDeliveryUnknown('artifact invocation lacks its complete public receipt')
                    self.record.failed(missing)
                    raise missing
        finally:
            try:
                if self.token is not None:
                    token, self.token = self.token, None
                    _CURRENT.reset(token)
            except BaseException as reset_error:
                self.record.failed(reset_error)
                raise
            finally:
                try:
                    self.activation.__exit__(kind, error, traceback)
                finally:
                    self.record.retire()
        return False

    def arm(self, value):
        """Last original argument, immediately before the one expected call.

The causal activation covers earlier Path/fspath/object evaluation, but those
providers cannot steal a protocol token that has not yet been armed.
        """
        self.record.check(ArtifactDeliveryUnknown)
        if self.armed or self.claimed:
            raise ArtifactDeliveryUnknown('artifact invocation token cannot be reused')
        self.armed = True
        self.token = _CURRENT.set(self)
        return value

    def code(self, admitted):
        try:
            control_descriptor(admitted, private=True)
        except ValueError as error:
            # Preserve the original memfd/seal/readback refusal order. Invalid
            # private ABI bytes can never reach a child, even if sealing works.
            # This also keeps the original seal-fault controls authoritative.
            self.descriptor_error = error
        return admitted

    def payload(self, original):
        # Only the fixed private executable consumes this prefix. The public
        # executable retains the complete old arbitrary stdin domain.
        self.payload_bytes = len(original)
        return self.nonce + original

    def handoff(self, environment):
        if self.descriptor_error is not None:
            from .artifact_publication import PublicationRejected
            raise PublicationRejected('E_PUBLISH_NATIVE_CUSTODY: selected private delivery entry unavailable') from self.descriptor_error
        self.record.check(ArtifactDeliveryUnknown)
        # Last original subprocess argument: prior callee/argv/fspath/keyword
        # evaluation has completed. This is the actual foreign call boundary.
        self.record.enter_native()
        return environment

    def returned(self, result):
        try:
            receipt = acknowledgement(result.stderr, self.nonce, result.returncode, result.stdout)
        except (ValueError, TypeError, AttributeError) as error:
            raise ArtifactDeliveryUnknown('artifact native delivery acknowledgement is missing or invalid') from error
        if (type(self.operation) is str and receipt.operation not in (0, _OPERATIONS[self.operation])
                or receipt.outcome == RETURNED and receipt.operation == 0):
            raise ArtifactDeliveryUnknown('artifact native acknowledgement names another operation')
        if (receipt.outcome == RETURNED
                and receipt.input_bytes != (0 if receipt.operation == 3 else
                    len(result.stdout) if receipt.operation == 5 else self.payload_bytes)):
            raise ArtifactDeliveryUnknown('artifact native acknowledgement byte observation differs')
        self.record.check(ArtifactDeliveryUnknown)
        self.acknowledgement = receipt
        if receipt.outcome == REFUSED:
            # HIA has acknowledged the complete original refusal/cleanup
            # disposition, including allowed directory-fsync residual files.
            self.record.confirmed(terminal=True)
        elif receipt.outcome != RETURNED:
            raise ArtifactDeliveryUnknown('artifact native effect or output delivery remains unconfirmed')
        # RETURNED remains pending until the original public JSON/raw receipt
        # validation has completed. stdout alone never confirms publication.
        return receipt

    def confirmed(self):
        self.record.check(ArtifactDeliveryUnknown)
        if self.acknowledgement is None or self.acknowledgement.outcome != RETURNED:
            raise ArtifactDeliveryUnknown('artifact public receipt has no matching native acknowledgement')
        self.record.confirmed(terminal=True)


def take_invocation(expected=None):
    if expected is None:
        return None  # The explicit original direct helper cannot steal a token.
    current = _CURRENT.get()
    if (current is expected and type(current) is ArtifactInvocation
            and current.armed and not current.claimed):
        current.record.check(ArtifactDeliveryUnknown)
        current.claimed = True
        token, current.token = current.token, None
        _CURRENT.reset(token)
        return current
    raise ArtifactDeliveryUnknown('canonical artifact invocation lacks its one-shot private token')


def handoff(invocation, environment):
    return environment if invocation is None else invocation.handoff(environment)


def payload(invocation, original):
    return original if invocation is None else invocation.payload(original)
