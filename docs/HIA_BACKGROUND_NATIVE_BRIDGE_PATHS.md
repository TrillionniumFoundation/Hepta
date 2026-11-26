# Native background bridge paths

## Status and exact scope

The policy implements the live dictionary iteration and filesystem part of the
original `BackgroundOptimizer.__init__` bridge expression. Each `next` obtains
the current key and value from the actual dictionary owner, calls the captured
path coercion component, resolves that path with the unchanged qualified HIA
POSIX resolver, and inserts the resolved result before advancing the iterator.
It does not precompute a vector of path values. A method that changes another
dictionary value therefore affects the subsequent iteration, and actual size
and key changes have the native iterator's original error behavior.

**The present result is a private intermediate dictionary of exact strings.**
The original public expression contains actual `PosixPath` instances. The final
fixed native Path class factory must create those instances before this result
can become the public `_bridge`. The actual PurePath input fastpath and initial
runtime class gate are also separate required integrations. A class-name string
or caller flag cannot establish any of those facts.

The original source-author verifier passes, the readable x86 bridge agrees with
its packer bytes, and an external development harness has executed the actual
mechanical capsules and actual Linux filesystem syscalls. Its 76 checks cover
the original bridge expression, live dictionary mutations by captured methods,
method bypass for native string/bytes subclasses, exception identity,
resource failures, partial writes, interruption before a write, and cleanup
consumption controls. In that harness HIA policies and the value graph are
executed from their exact development authors in Python. This is explicitly
**not native HIA qualification**. The companion record keeps native build,
native qualification, public Path factory and whole runtime flags false.

## Fixed interface

The closed export is `hia_background_bridge_paths`, with the existing six-word
input/output/work pointer-and-length convention. Input is 128 bytes. Output and
work are each at least 262144 bytes. Their actual views must be disjoint,
nonwrapping and live. The enclosing native factory must strongly retain the
actual value context and all captured executable closures throughout the call
and any retained cleanup. Every concurrent invocation has its own exclusive
work frame; this interface does not grant simultaneous access to the same frame.

### Request: HIABBPQ1

| Offset | Field |
| --- | --- |
| 0 | `HIABBPQ1` |
| 8 | 0: begin conversion; 1: resume the retained invocation |
| 16, 24, 32 | Actual input dictionary capability for operation 0 |
| 40 through 127 | Zero |

Operation 1 requires all input capability words to be zero. The original option
component has already checked the original public dictionary shape. The private
leaf does not re-evaluate that public option check after a callback mutates it.

### Captured work prefix: HIABBPC1

| Offset | Field |
| --- | --- |
| 0 | `HIABBPC1` |
| 8, 16, 24 | Actual value entry, context address and extent |
| 32 | Actual closed `native_path_value` entry |
| 40 | Actual closed `native_path_resolve` entry |
| 48 | Actual fixed NDU original-error formatter entry |
| 56 | Captured process ID |
| 64 | Retained state: 0 empty, 1 known continuation, 2 quarantine |
| 72 | Actual pure path window codec entry |
| 80 through 127 | Zero |

Work 128..1919 retains the actual owner continuation; 2048..2079 is codec
scratch; 4096..8191 is the child's persistent path-conversion owner; 8192..8575
retains bounded dependency diagnostics, including the actual capability row.
The resolver owns 16384..217087, and the formatter owns 225280..258047.
Offsets describe internal ownership, not public caller-supplied authority.

### Reply: HIABBPR1

| Offset | Field |
| --- | --- |
| 0 | `HIABBPR1` |
| 8 | Status |
| 16, 24, 32 | Owned result dictionary, only for completed status 0 |
| 40, 48, 56 | Owned exact typed-error JSON bytes, only for status 1 |
| 64, 72, 80 | Owned actual raised exception, only for status 2 |
| 88 | Retained-state classification |
| 96 | Private dependency/detail value |
| 104 | Completed flag, only for a completed successful conversion |
| 112 through 127 | Zero |

Statuses are 0 success, 1 original builtin error record, 2 actual captured
exception, 5 allocation failure, 6 lifecycle refusal, 7 dependency failure,
8 transport failure and 9 retained work. Private frame rejection returns
`0xfffffffd`. No owned result capability is published while status is 9.
An empty operation-1 call succeeds with completed zero.

## Filesystem transport and strings

The fixed `native_path_resolve` capsule closes the unchanged resolver's original
syscall/continue protocol. It installs the actual workspace base, performs
system calls and feeds their raw results back. It does not interpret paths or
make path policy decisions. Its dedicated HIA packer takes one actual policy
image under `HIAPTRP1`. The policy remains the existing `dfb3ef61` resolver;
the additional capsule does not change symlink, relative-path or long-cwd rules.

The parent reads the captured exact string or native string-base value in
8192-byte windows. The pure codec quotes its WTF-8 bytes into one JSON string
body. A private memfd contains the complete original resolver input and is
sealed with all four required seals before a read-only mapping is passed to the
resolver. The parent validates the resolver's actual returned descriptor and
seals, maps its full filesystem-byte result, and decodes UTF-8 with the original
surrogateescape behavior into a second sealed scalar request. That actual
request creates the exact native string value.

Transfer windows and three-byte UTF-8 lookahead are not an aggregate path-size
limit. Full lengths remain checked u64/actual platform file extents. The loop
checks arithmetic before constructing extents. Actual allocation or filesystem
failure remains a failure; it is not replaced with truncation.

## Ownership and resumption

The owner retains each actual iterator row before invoking a path method. It
owns its iterator, output dictionary, current key/value, coercion result,
native-object metadata references, resolved value and any original error or
exception capability. It also records all three actual private descriptors and
their mappings. Known cleanup failure preserves this real state in the same
exclusive frame. It never retries a descriptor after an actual close outcome
that may have consumed it.

Child path conversion cleanup resumes with its operation 2 and never calls the
captured method again. After that cleanup completes, operation 1 may continue
the already captured parent invocation, including filesystem work that had not
yet begun. It is therefore a resume operation, not a promise that no new
continuation step will occur. Previously executed callbacks, completed
resolution and dictionary insertion are not replayed.

Value references use V02 operation 29 and validate the entire `HIABVR02` header,
reserved fields, status domain and flag correlations before changing a slot.
Known consumption immediately clears only that reference. An actual remaining
mapping is tracked separately and uses operation 31; only confirmed successful
31 clears the recorded pending state. Known-unconsumed plus pending preserves
both facts and enters classification 2, since neither retry order proves that
the original capability was consumed. Unknown protocol, contradictory success,
unknown close completion, and consumed-without-recorded-cleanup failure also
retain quarantine. Keeping a class or context alive is not a substitute for
interpreting explicit consumption correctly.

## Remaining gates

The final source DAG must capture the new iterator and value owner, actual path
converter, unchanged POSIX resolver, original error formatter, codec and both
closed capsules. Every runtime HIA source must compile twice under the unchanged
494833 compiler limits. Actual HIA packing and linking must reproduce identical
bytes, and the native pack/private-pointer/actual fault gates must pass on the
pinned execution host. The original oracle there is CPython 3.14.4. Development
checks on 3.12 use the exact original bridge AST and absolute Unicode-error paths
where those versions have different relative-path error positions.

Public Path class integration, full constructor order, final controller,
fresh importer/self rebuild, cold qualification, MCP activation and repository
cleanup are not established by this component.
