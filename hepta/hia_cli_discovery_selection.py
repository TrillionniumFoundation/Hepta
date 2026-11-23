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


def selected_json(operation, schema=None, *, package_owner=None, package_default=False):
    """Prefer explicit admission, then a package owner, then the retained API.

    The explicit profile uses the immutable metadata in the selected source.
    Mutable replacement Python providers are not consulted in that profile.
    Parser admission, errors and stdout encoding remain with the current CLI.
    """
    selected = os.environ.get(SELECTOR)
    if selected is None and package_owner is None:
        if package_default:
            from .hia_default_native import default_cli_discovery
            package_owner = default_cli_discovery()
        if package_owner is None:
            return None
    if selected == '':
        raise ValueError('selected CLI discovery JSON manifest must not be empty')
    if schema is not None and type(schema) is not str:
        raise TypeError('CLI discovery schema must be an exact parser string')
    from .hia_cli_discovery_json_native import installed_cli_discovery_json, request
    owner = package_owner if selected is None else installed_cli_discovery_json(selected)
    wire = request(operation, None if schema is None else schema.encode('ascii'))
    return DiscoveryJsonBytes(owner.render(wire))
