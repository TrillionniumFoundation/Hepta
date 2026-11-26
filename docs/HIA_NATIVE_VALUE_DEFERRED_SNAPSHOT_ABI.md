# Private deferred atomic Value snapshot

The separate HIABVQ09 request domain accepts only operation 23. It preserves
the original HIABVQ01 operation 23 request and response fields and executes
the same arena-mutex-protected native snapshot. The single entry defers
resource finalizers and invocation retirement. It does not change a shared
context flag or relax the original operation or existing Q06, Q07 and Q08
request domains.

A is the actual list, tuple or dictionary capability. Argument 104 is the
starting logical index; argument 112 is the maximum number of entries.
The ordinary HIABVR01 success response has the current container size at
48, returned count at 64 and required output extent at 72. Rows start at
8192 and occupy 64 bytes: logical index at 0, value kind at 8, key capability
at 16 and value capability at 40. List and tuple key capabilities are zero.
Dictionary rows retain both actual key and value objects.

The implementation reserves capacity and creates all children as unpublished
capabilities. Any prepublication failure rolls back every temporary token.
Only after the complete snapshot exists does the native operation publish
all children. A nonzero status returns no published children and count zero.
The caller must not inspect nonzero tail bytes as capabilities on failure:
they can contain unpublished or already-rolled-back temporary values.

The component gate exercises complete and partial snapshots, original Q01/23
compatibility, dictionary keys and all child identities, and actual child
lifetime after the parent and caller's original references are dropped.
It also creates a real code-munmap EIO retirement queue, snapshots under the
private deferred profile, drops the original references using the native
deferred drop protocol, and proves that only a later ordinary operation
performs retirement. Actual getrandom EIO, short output and wrong-type
failures retain no published children. All input/refusal and output-canary
checks remain active.

The fixed code-body dispatcher refuses this domain. Final public enclosing
owners must refuse the entire private domain; that separate enclosing
integration is not claimed by this Value component qualification.
