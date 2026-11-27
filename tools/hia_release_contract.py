"""Validate the retained release contract in its actual source domain.

This development reader does not build a native contract or qualify a release.
Native publication still requires the native inventory/contract producer and a
fresh cold replay. Hosted authoring keeps its separate complete seed contract.
"""
from pathlib import Path
import json

from tools.hia_native_worker_source_authority import _object, load_native_source_authority
from tools.hia_selfhost_contract import CONTRACT_PATH, ROOT, support_contract

NATIVE_AUTHORITY = 'docs/HIA_NATIVE_SOURCE_AUTHORITY.json'
HOSTED_SEED = 'tools/qualify_hia_selfhost.py:build_seed'


def read_contract(root=ROOT):
    contract = json.loads((Path(root) / CONTRACT_PATH).read_bytes(), object_pairs_hook=_object)
    if type(contract) is not dict:
        raise ValueError('release source contract must be an object')
    return contract


def source_domain(contract):
    identity = contract.get('source_identity')
    roles = identity.get('roles') if type(identity) is dict else None
    if type(roles) is not dict:
        raise ValueError('release source contract must declare its source roles')
    if roles.get('authoring_authority') == NATIVE_AUTHORITY:
        return 'native'
    if 'authoring_authority' not in roles and roles.get('seed_entry') == HOSTED_SEED:
        return 'hosted'
    raise ValueError('unrecognized release source contract domain')


def validate_release_contract(root=ROOT):
    root = Path(root).resolve(strict=True)
    declared = read_contract(root)
    if source_domain(declared) == 'native':
        from tools.generate_hia_source_release_cold_admit import native_authority_contract
        authority = root / NATIVE_AUTHORITY
        if NATIVE_AUTHORITY not in load_native_source_authority(authority):
            raise ValueError('native release source contract must capture its authority')
        expected = native_authority_contract(root, authority)
    else:
        expected = support_contract(root)
    if declared != expected:
        raise ValueError('release source contract differs from the current source closure')
    return declared
