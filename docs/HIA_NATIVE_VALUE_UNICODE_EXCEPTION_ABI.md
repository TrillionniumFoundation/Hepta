# Native Unicode exception capture and fields

The sixteen-role HIABVP09 format and its sole Value entry are unchanged.
This profile adds HIABVQ05 operations 108 and 109. It leaves operation 75,
the previous class-catalog bounds and all deferred request domains unchanged.

## Wire and ownership

Requests are 128 bytes without a tail. A, B and C are capability triples
at offsets 24, 48 and 72. Fields 16, 96, 112 and 120 are zero. C is zero.

| Operation | A | B | Selector at 104 | Result |
|---|---|---|---|---|
| 108 | Actual five-item tuple | Optional actual Unicode class | 0 | Actual exception |
| 109 | Actual captured Unicode exception | Zero | 0 encoding, 1 object, 2 start, 3 end, 4 reason | Strong field capability |

A for 108 contains encoding, object, start, end and reason. B zero selects
canonical UnicodeDecodeError (70). An explicit B must be a real class or
subclass of UnicodeDecodeError (70) or UnicodeEncodeError (44), with actual
MRO identity. A same-named unrelated class is rejected.

Both operations use HIABVR01: status at 8, kind at 16, primary capability
at 24–40, size at 48, disposition at 64, pending at 80, known at 88, primary
delivered at 96 and cleanup status at 104; 112 and 120 are zero. Inputs are
borrowed. Field 96 never consumes an input in these operations. Disposition
1 is a normal returned object. A delivered primary capability remains owned
by the caller even when subsequent real native cleanup fails. An
undelivered response has a zero primary triple.

## Actual fields and graph

Encoding and reason must be real str or str subclasses. The object must
be bytes or a bytes subclass for Decode and str or a str subclass for Encode.
Their field aliases retain the actual input objects. Start and end accept
real int/bool or int subclasses within signed native ssize range. Their
stored descriptors are exact int values, while exception args preserve the
original tuple entries, including bool and subclass identity. Negative and
out-of-object-range positions are preserved like the original constructors.

These are captured, already materialized decoder or encoder facts. A
custom index protocol returns explicit status 27 for an enclosing caller
to handle outside the Value mutex; this component does not execute user
code under that mutex. Non-index types return status 2, wrong field count
returns 7 and out-of-ssize integer range returns 4. These wire refusals are
not presented as complete public Python constructor argument binding.

The five fields live in a real private tuple traced by the existing fifth
managed edge. They are not exception dictionary tags. Cause, context and
suppression occupy their existing slots in the same tuple. Operations 106
and 107 preserve the Unicode fields during actual atomic chain updates.
The original native collector reclaims self and mutual chain cycles.
Caller input drops cannot release fields retained by the exception.

## Validation and remaining scope

The frozen image passed the original six component groups and six campaigns,
all previous platform/call/GC/custody/record/deferred-domain gates, and nine
Unicode groups. The new comparisons use actual CPython 3.14.4 decoder and
encoder failures, signed ssize boundaries, true class/subclass and alias
identity, original args, chain replacement, native cycle collection,
getrandom EIO before publication and actual code-munmap EIO after both
operations publish their primary capability. The complete Value remains
below 4 MiB and all HIA functions retain the original compile budgets.

The three superseded test runs are preserved. Their new test-only scalar
projection used a legacy oracle that only decodes its own str subclass.
The final oracle decodes the real native base descriptor and separately
checks actual class and alias identity, without changing production
sources or weakening the original assertions.

Public constructor default/binding behavior, arbitrary custom index calls,
mutable Unicode descriptor setters, full string formatting and the whole
public LLVM layer remain separate unfinished scopes.
