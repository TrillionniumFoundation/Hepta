"""Explicit construction-time selection; no image admission on the default path."""
from __future__ import annotations

import os
from weakref import ref

SELECTOR = 'HEPTA_HIA_STORE_LIFECYCLE_MANIFEST'
_BOUND_STORES = {}


def capture_store_lifecycle():
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    from .hia_store_lifecycle_native import installed_store_lifecycle, NativeStoreLifecycleOwner
    custody = installed_store_lifecycle(selected, capture_identity=True)
    return NativeStoreLifecycleOwner(custody)


def bind_store_lifecycle(store, owner):
    """Bind by object identity without observing business attribute/hash hooks.

    Values hold the actual admitted owner. Keys are exact integers, and the weak
    reference callback does not capture the Store. A reference identity check
    prevents a delayed cleanup from removing a later object with a reused id.
    """
    if owner is None and not _BOUND_STORES:
        return
    key = id(store)
    if owner is None:
        previous = _BOUND_STORES.get(key)
        if previous is not None and previous[0]() is store:
            del _BOUND_STORES[key]
        return
    from .hia_store_lifecycle_native import NativeStoreLifecycleOwner
    if type(owner) is not NativeStoreLifecycleOwner:
        raise ValueError('store lifecycle requires its captured owner, not serialized metadata')
    owner.checker_owner()

    def retired(reference, key=key, bindings=_BOUND_STORES):
        previous = bindings.get(key)
        if previous is not None and previous[0] is reference:
            del bindings[key]

    reference = ref(store, retired)
    _BOUND_STORES[key] = (reference, owner)


def store_lifecycle_owner(store):
    # Absence never consults an ambient selector or any Store attribute.
    if not _BOUND_STORES:
        return None
    binding = _BOUND_STORES.get(id(store))
    if binding is None or binding[0]() is not store:
        return None
    owner = binding[1]
    from .hia_store_lifecycle_native import NativeStoreLifecycleOwner
    if type(owner) is not NativeStoreLifecycleOwner:
        raise ValueError('store lifecycle requires its captured owner, not serialized metadata')
    return owner
