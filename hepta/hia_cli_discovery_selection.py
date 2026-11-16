"""Explicit source-bound HIA JSON selection for ordinary discovery actions.

The selected image owns metadata filtering, sorting, JSON and catalog hashing.
This bridge only selects an operator manifest, converts the parser's schema to
bytes and carries the completed bytes to the existing stdout text stream.
The public dictionary-returning Python APIs retain their original contracts.
"""
from __future__ import annotations

from dataclasses import dataclass
import os

SELECTOR = 'HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST'


@dataclass(frozen=True, slots=True)
class DiscoveryJsonBytes:
    """Internal completed JSON bytes; never passed as a public mapping."""
    payload: bytes

    def __post_init__(self):
        if type(self.payload) is not bytes or not self.payload.endswith(b'\n'):
            raise ValueError('native discovery must return newline-terminated UTF-8 JSON bytes')


def selected_json(operation, schema=None):
    """Absent means retained API; every present selection is fail closed.

    The explicit profile uses the immutable metadata in the selected source.
    Mutable replacement Python providers are not consulted in that profile.
    Parser admission, errors and stdout encoding remain with the current CLI.
    """
    if SELECTOR not in os.environ:
        return None
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('selected CLI discovery JSON manifest must not be empty')
    if schema is not None and type(schema) is not str:
        raise TypeError('CLI discovery schema must be an exact parser string')
    from .hia_cli_discovery_json_native import installed_cli_discovery_json, request
    owner = installed_cli_discovery_json(selected)
    wire = request(operation, None if schema is None else schema.encode('ascii'))
    return DiscoveryJsonBytes(owner.render(wire))
