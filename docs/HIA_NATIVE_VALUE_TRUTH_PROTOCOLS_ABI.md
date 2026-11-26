# Native Value truth prerequisites

This checkpoint retains the fifteen-role HIABVP08 layout, original compiler,
4 MiB role bound and 16 MiB enclosing text bound. Its complete construction,
source pins and unchanged regression evidence are recorded in
HIA_NATIVE_VALUE_TRUTH_PROTOCOLS_COMPONENT.json. The canonical current Value
product is HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json.

## Last external reference and descendant cycles

Dropping the last external reference to an ordinary instance or container
can expose a cycle among its class, MRO, namespace and native method. The
instance itself need not have an incoming graph edge. While native callable
custody exists, collection now examines this descendant graph before
concluding that the drop cannot retire native code. Existing context tokens
remain live throughout the gate. Native finalizer acknowledgement still
controls actual resource retirement.

## Private classified invocation: Q05 operation 97

The request uses the same 128-byte header and actual callable, argument
tuple and optional keyword dictionary as operation 70. Validation, argument
snapshot, code execution and capability custody use the same native path.

Operation 97 additionally returns the actual classification at offset 56:
0 for a returned value, 1 for an Exception subclass raised value, and 2 for a
BaseException raised value outside Exception. Classification uses the actual
class MRO while the Value mutex is held, before the primary reference is
delivered. Operation 70 continues to leave offset 56 zero.

The primary strong capability at 24/32/40, disposition at 64, pending at 80,
known at 88, delivered at 96 and cleanup status at 104 remain independent.
A later native munmap failure preserves the delivered original exception and
its classification. Private operation 97 is not admitted as a code-body
request or an ordinary public owner operation.

## Canonical error classes: Q05 operation 98

The standard 128-byte request has argument zero at 104 and all capability,
tail and reserved fields zero.

| ID | Actual canonical class | Direct base |
|---|---|---|
| 43 | UnicodeError | ValueError |
| 44 | UnicodeEncodeError | UnicodeError |
| 45 | HIAProgramLLVMRejected | ValueError |

Operation 98 accepts only these three IDs and returns a normal strong class
capability. Repeated lookup returns the same class identity. Operation 87
continues to accept exactly IDs 38 through 42 and reject ID 43. Existing
operation 75 captures actual exception args and namespace with these classes.
This gate does not claim automatic specialized exception attributes,
tracebacks or Python exception formatting.

## Private fixed container operations: HIABVQ07

The old HIABVQ06 domain remains unchanged. Its accepted operations are
2, 4, 7, 8, 9, 10, 17, 19, 21, 26, 32, 36, 37, 38, 39 and 49. Its original
rejection of operations 3 and 12 remains covered by the unchanged original
managed-edge gate.

The new private magic HIABVQ07 accepts exactly five original operations:

| Operation | Fixed native operation |
|---|---|
| 3 | Create a list |
| 12 | Fetch a list or tuple index |
| 16 | Append to a list |
| 18 | Export the supported native JSON value |
| 24 | Exact integer addition or subtraction |

All ordinary argument validation, mutex protection, result capability
publication and error semantics are unchanged. Only automatic native
resource-finalizer draining is deferred for that single entry. No global
defer flag or request-selected entry address exists. The code-body whitelist
rejects the entire Q07 domain. A new enclosing public owner must reject Q07
explicitly, just as it rejects Q06; its derived public-profile gate is tracked
separately from this component.

The kernel-failure gate first creates actual pending native code retirement
by refusing munmap. Each of the five Q07 operations leaves that custody
pending. One subsequent ordinary native operation 47 performs real retry and
acknowledgement outside the caller's internal lock.

## Evidence and limits

The final image passed all six original component gates and all six original
campaigns with their original 300/660-second campaign budgets. It also passed
31 record, 17 resource, 17 VerifiedProgram, 18 exception, 10 hash/equality,
seven managed-edge, five packer, 15 invocation and eight invocation-custody
groups. The packer gate includes 55 malformed frames and the original bounds.

Nineteen additional groups exercise four descendant-cycle shapes, the three
canonical classes, six actual return/raise classifications, private-domain
refusals, four actual Value/code munmap failures, and pending retirement
across all five Q07 operations. CPython 3.14.4 remains the oracle.

The Future truth role, public owner profile, callback/worker fusion,
arbitrary iterable dataclass construction and complete public runtime
remain separately qualified. This component checkpoint does not convert
their pending work into a whole-system pass.
