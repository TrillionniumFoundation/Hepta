# Shared native path conversion contract

Status: implementation contract for the shared native owner. It is not a native
qualification or a claim that the public MV/BG path boundary is complete.

## Actual inputs and fixed context

The entry is a fixed six-word native function `(source, source_n, output,
output_n, workspace, workspace_n) -> u32`. Both MV and BG use this same path
coercion owner. MV subsequently performs the original absolute-path operation;
BG subsequently invokes the independently qualified physical resolver.

The exact 128-byte input is `HIANPV01`, followed by fifteen little-endian words:

| Offset | Field |
| --- | --- |
| 8 | Operation: 0 `os.fspath`, 1 single-argument `Path` coercion, 2 cleanup |
| 16, 24, 32 | Actual input value capability for operation 0/1; all zero for 2 |
| 40 through 127 | Zero |

There is no caller-supplied converted path, asserted type, verified flag,
deadline extension or exception-family classification in this request.

The workspace is at least 4096 bytes. Its first 128 bytes are fixed configuration:

| Offset | Field |
| --- | --- |
| 0 | `HIANPVC1` |
| 8 | Captured actual mutable-value owner entry |
| 16 | Actual value-context address |
| 24 | Actual value-context byte length |
| 32 | Captured PID |
| 40 through 127 | Zero |

The native owner preserves that configuration. Bytes 128 through 4095 belong to
its persistent continuation and actual owned-reference inventory and are zero
when a fresh frame is created. The parent strongly owns the value context and
the whole frame until all cleanup completes. Different frames may run
concurrently; overlapping calls on the same frame are refused using the actual
frame guard. A new 0/1 operation is accepted only while that frame is idle.

The output is at least 32768 bytes. Private continuation scratch is not an owned
resource store: every reference that can outlive a call is recorded in the
persistent workspace before an effect can suspend or fail.

## Complete reply and actual custody

A complete entry returns zero with a 128-byte `HIANPVR1` reply:

| Offset | Field |
| --- | --- |
| 8 | Status: 0 success, 1 new built-in TypeError, 2 actual callback exception, 3 owner allocation failure, 4 dependency/lifecycle failure |
| 16, 24, 32 | Independently owned successful path value capability |
| 40, 48, 56 | Independently owned actual raised-exception capability; preserves identity |
| 64, 72, 80 | Independently owned bytes capability containing the full TypeError JSON |
| 88 | Semantic detail |
| 96 | `cleanup_required`, Boolean |
| 104 | `quarantined`, Boolean |
| 112 | Actual dependency detail |
| 120 | Zero |

Only the capability appropriate to a completed status is populated. A status-1
message uses exact `{"type":"TypeError","message":...}` JSON with complete
original text. Its bytes are held by the ordinary value owner; no 8 MiB path or
message limit is added. Status 2 preserves the actual callback exception rather
than rebuilding it from a class-name string. A callback's actual MemoryError
also takes this identity-preserving route; status 3 denotes an allocation
failure in the conversion owner itself.

When cleanup is pending or quarantined, no result or exception capability is
published. The workspace retains the actual original outcome and its owned
references. Operation 2 resumes only cleanup of these captured resources; it
does not call the filesystem method again and does not repeat path coercion.
After cleanup succeeds, it publishes the original outcome exactly once and
returns the frame to idle. A subsequent operation 2 on an idle frame is a
lifecycle refusal, not a second publication.

Cleanup first validates the entire `HIABVR02` reply, its reserved words and
Boolean fields, and the operation's success invariants. In particular, 29/30
success requires known=1, consumed=1, pending=0; 31 success requires known=1,
consumed=0, pending=0. The exact allowed cleanup status sets and associated
flags in `HIA_RESULT_VALUE_NATIVE_CLEANUP_ABI.md` are checked before trusting
consumption; an arbitrary status such as 999 is not accepted. Contradictory success is quarantined before changing the
owned slot. For a valid known-consumed completion the slot is cleared even
when status is nonzero. Actual pending mapping cleanup is retried only with 31.
An unknown consumption result, or a nonzero post-consumption result without a
recorded retryable mapping, is kept in persistent quarantine. The parent cannot
discard the workspace because a reply only claims that cleanup is pending.

Malformed private frames return `0xfffffffd` without a structured completion.
An undersized output/workspace uses the same private refusal, and does not start
the conversion. Neither a partial header nor a nonzero entry return is a
successful or authoritative exception result.

## Actual native method callback

The converter strongly retains the receiver and obtains operation 26's actual
environment, base and class-name references. It invokes the captured method
entry outside the mutable-value registry lock. The executable closure containing
that method remains strongly owned by the native class factory throughout the
object/context lifetime. A nonzero function address alone is not custody.

The callback is the same six-word ABI. Its exact 128-byte input is `HIAPFSP1`:

| Offset | Field |
| --- | --- |
| 8 | Zero |
| 16, 24, 32 | Actual receiver capability, borrowed strongly for this call |
| 40, 48, 56 | Actual environment capability, borrowed strongly for this call |
| 64 through 127 | Zero |

It receives a distinct, fresh workspace of at least 4096 bytes. Prefix 0..127 is
`HIANPFC1`, then the same value entry, context, context length and PID at 8..32,
with 40..127 zero. That prefix is read-only. Bytes 128..4095 are callback-local
scratch, initially zero. The callback never receives the converter's persistent
continuation frame. Output is at least 32768 bytes.

The callback returns zero with an exact 128-byte `HIAPFSR1` header. Offset 8 is
0 for an ordinary return, 1 for an actually raised TypeError-family exception,
or 2 for another actually raised Exception/BaseException. Offsets 16/24/32 hold
one independently owned actual value/exception capability. All remaining header
words are zero. The family decision comes from the captured native method and
its actual exception construction/class path, not public caller metadata or a
string comparison. Bad framing, bad ownership or unknown completion is a
dependency failure and retains the converter's real captured resources.

## Original coercion semantics

Exact str/bytes and actual native str/bytes subclasses bypass `__fspath__` for
operation 0. Other native objects call their captured method. A missing method
and a non-str/bytes returned value use the original, distinct TypeError wording.
The `os.fspath` type-name formatting keeps the original 200-byte UTF-8 precision
and replacement behavior after `_PyType_Name` selects the suffix after the last
dot; it is not a 200-code-point truncation. The Path argument message uses the
complete actual `__name__`, including dots.

Operation 1 follows the original Path constructor: it catches actual TypeError
from `os.fspath`, restores the original argument for its own type check and
produces the Path argument TypeError. Other actual exceptions propagate with
identity. A successful bytes result names that returned bytes type in the Path
error, while a successful str or str-subclass result is accepted. The complete
Path error uses the original Python class-name representation, without snapshot
display truncation.

Support for real native class objects, scalar subclasses and their executable
closure is part of the public factory work. These private request contracts do
not by themselves claim arbitrary foreign-interpreter objects or all PurePath
fast-path instances have been integrated.
