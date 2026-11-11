"""Native selected-call exception/unwind decisions for the complete call owner.

NEW UNEXECUTED DEVELOPMENT LIBRARY. It is not a Worker entry or namespace service.
The full HIA call controller embeds these functions; no hosted interpreter may
choose their decisions. Error/value handles are private issued peer leases.
"""
CONSTANTS={
 'UW_NATIVE_FAILED':2048,'UW_TX':2056,'UW_SCOPE':2064,
 'UW_CLASS':2072,'UW_ERROR':2080,'UW_ATOMIC_EXIT':2088,
 'UW_INSTALL_ERROR':2096,'UW_PENDING':2104,
 'UW_DOMAIN_HANDLER':1,'UW_ROLLBACK':2,'UW_THROW':3,
 'UW_INSTALL_WRAP':4,'UW_INSTALL_RECORD':5,
 'UW_SCOPE_INITIAL':0,'UW_SCOPE_INSTALL':1,'UW_SCOPE_MAIN':2,
 'UW_SCOPE_NATIVE':3,'UW_SCOPE_ACK':4,'UW_SCOPE_ERROR_RECORD':5,
 'UW_SCOPE_FINALLY':6,'UW_SCOPE_INSTALL_RECORD':7,
}
BODY=r'''
def call_domain(kind:u64) -> u64:
    return choose(kind == 1 or kind == 2 or kind == 3 or kind == 4 or kind == 5 or kind == 7 or kind == 8 or kind == 9, 1, 0)

def call_install_catches(kind:u64) -> u64:
    return choose(kind == 1 or kind == 3 or kind == 7 or kind == 8, 1, 0)

def call_scope(w:mutbuf, scope:u64) -> u64:
    put(w, UW_SCOPE, scope)
    return scope

def call_begin_transaction(w:mutbuf, atomic:u64) -> u64:
    put(w, UW_TX, choose(atomic != 0, 2, 1))
    return 0

def call_before_commit(w:mutbuf) -> u64:
    put(w, UW_ATOMIC_EXIT, choose(get(w, UW_TX) == 2, 1, 0))
    put(w, UW_TX, 0)
    return 0

def call_after_commit(w:mutbuf) -> u64:
    put(w, UW_ATOMIC_EXIT, 0)
    return 0

def call_failure(w:mutbuf, kind:u64, error:u64) -> u32:
    put(w, UW_CLASS, kind)
    put(w, UW_ERROR, error)
    scope = get(w, UW_SCOPE)
    if scope == UW_SCOPE_INITIAL:
        return UW_THROW
    if scope == UW_SCOPE_INSTALL:
        if call_install_catches(kind) != 0:
            put(w, UW_INSTALL_ERROR, 1)
            return UW_INSTALL_WRAP
        return UW_THROW
    if scope == UW_SCOPE_INSTALL_RECORD:
        return UW_THROW
    if scope == UW_SCOPE_ERROR_RECORD:
        put(w, UW_NATIVE_FAILED, 1)
        return UW_THROW
    if scope == UW_SCOPE_FINALLY:
        return UW_THROW
    if scope == UW_SCOPE_ACK or (scope == UW_SCOPE_NATIVE and call_domain(kind) == 0):
        put(w, UW_NATIVE_FAILED, 1)
    transaction = get(w, UW_TX)
    if transaction != 0:
        put(w, UW_ATOMIC_EXIT, choose(transaction == 2, 1, 0))
        put(w, UW_PENDING, 1)
        return UW_ROLLBACK
    return call_after_unwind(w)

def call_rollback_observation(w:mutbuf, failed:u64, kind:u64, error:u64) -> u32:
    put(w, UW_TX, 0)
    put(w, UW_PENDING, 0)
    if failed != 0:
        put(w, UW_CLASS, kind)
        put(w, UW_ERROR, error)
    return call_after_unwind(w)

def call_after_unwind(w:mutbuf) -> u32:
    kind = get(w, UW_CLASS)
    if get(w, UW_ATOMIC_EXIT) != 0 and call_domain(kind) == 0:
        put(w, UW_NATIVE_FAILED, 1)
    put(w, UW_ATOMIC_EXIT, 0)
    if call_domain(kind) != 0:
        return UW_DOMAIN_HANDLER
    put(w, UW_NATIVE_FAILED, 1)
    return UW_THROW

def call_install_wrapped(w:mutbuf, error:u64) -> u32:
    put(w, UW_ERROR, error)
    put(w, UW_CLASS, 1)
    put(w, UW_SCOPE, UW_SCOPE_INSTALL_RECORD)
    return UW_INSTALL_RECORD

def call_finally_required(w:mutbuf) -> u64:
    return choose(get(w, UW_NATIVE_FAILED) == 0, 1, 0)
'''
