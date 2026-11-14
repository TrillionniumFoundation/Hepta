"""Bind lifecycle selection once without touching Store attributes or hashes."""
from __future__ import annotations

import os
import weakref

SELECTOR = 'HEPTA_HIA_STORE_LIFECYCLE_MANIFEST'
_BOUND_STORES = {}


def capture_store_lifecycle():
    if SELECTOR not in os.environ:
        return None
    from .hia_store_lifecycle_native import installed_store_lifecycle, NativeStoreLifecycleOwner
    return NativeStoreLifecycleOwner(installed_store_lifecycle(os.environ[SELECTOR]))


def bind_store_lifecycle(store, owner):
    previous = _BOUND_STORES.get(id(store))
    if previous is not None and previous[0]() is store:
        previous[1].check_store(store)
    if owner is None:
        if previous is not None and previous[0]() is store:
            del _BOUND_STORES[id(store)]
        return
    from .hia_store_lifecycle_native import NativeStoreLifecycleOwner
    if type(owner) is not NativeStoreLifecycleOwner:
        raise TypeError('store lifecycle requires an admitted owner')
    key = id(store)
    def released(reference):
        current = _BOUND_STORES.get(key)
        if current is not None and current[0] is reference:
            del _BOUND_STORES[key]
    _BOUND_STORES[key] = (weakref.ref(store, released), owner)


def store_lifecycle_owner(store):
    selected = _BOUND_STORES.get(id(store))
    if selected is None or selected[0]() is not store:
        return None
    from .hia_store_lifecycle_native import NativeStoreLifecycleOwner
    if type(selected[1]) is not NativeStoreLifecycleOwner:
        raise TypeError('Store lifecycle binding lost its admitted owner')
    return selected[1]
