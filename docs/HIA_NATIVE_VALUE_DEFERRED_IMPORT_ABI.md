# Private deferred Value JSON import

HIABVQ10 accepts only the original operation 1 JSON import. It uses the same
128-byte request header, original JSON tail, parser, arena allocation and
ordinary HIABVR01 result capability at 24. All reserved fields and unused
capabilities retain their original refusal rules.

Only this entry defers resource finalizers and invocation retirement.
It does not modify a shared context flag, replace the original parser or
expand any previous request domain. The existing arena mutex and the
original atomic publication and rollback paths remain in use.

The new component tests 17 original scalar and container imports against
ordinary Q01/1, including arbitrary-width integers, negative zero, Unicode
and nested objects. Eight malformed JSON inputs preserve their original
error statuses and deliver no result capabilities. Real code-munmap EIO
creates a pending native retirement queue; private imports and actual
getrandom EIO leave that queue intact, and a later ordinary operation
performs real retirement. A failed import does not publish its partially
constructed tree. The exact private request domain and output canaries
are checked without changing the existing assertions.

The code-body dispatcher refuses this private domain. A final public owner
must also refuse HIABVQ10. That enclosing integration remains separately
tracked and is not claimed by this component receipt.
