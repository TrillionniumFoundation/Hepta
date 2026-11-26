# Native deferred resource capture

The new private request magic is HIABVQ08. It accepts only operation 48.
The existing HIABVQ05 operation 48, HIABVQ06 and HIABVQ07 domains keep their
original contracts. The fifteen-role HIABVP08 pack layout is unchanged.

## Request and ownership

The request is the original 128-byte resource-capture header followed by the
actual 24-byte native carrier capability. The tail length at 96 is 24 and
the resource kind at 104 is validated by the existing fixed native binding.
Environment, base and name capabilities have the same meaning as ordinary
capture. No request-supplied function pointer or context address is accepted.

Capture executes under the ordinary Value arena mutex with all original
type, binding, allocator and capability checks. Only the automatic finalizer
drain for this single entry is deferred. No global context flag is changed.

The caller transfers the input native carrier only when the actual receipt
reports known=1 and consumed=1. Any delivered Value capability must be kept
or explicitly released independently of the status and cleanup facts.
Known=1 and consumed=0 leaves the input carrier with the caller.

## Reply

The reply keeps HIABVR01 and the original result capability. This private
profile adds separate pending domains so an enclosing queue lock does not
wait for its own parent finalizer.

| Offset | Meaning |
|---|---|
| 8 | Original operation status |
| 24, 32, 40 | Delivered strong Value capability |
| 80 | Union of actual pending cleanup |
| 88 | Capture disposition is known |
| 96 | Actual input native carrier was consumed |
| 104 | Arena mapping retirement is pending |
| 112 | Native resource or continuation retirement is pending |
| 120 | One: this entry deferred automatic finalizers |

A successful capture can report pending at 112 while remaining successful
and delivering its capability. Pending does not reverse an already completed
ownership transfer. A getrandom failure before capture reports known=1,
consumed=0 and no delivered capability while preserving unrelated pending
native retirement. The caller may then drop its still-owned native carrier.

## Verified behavior

The four new groups use the actual native Runtime carrier, actual native
code ownership and real kernel getrandom or munmap errors. They cover normal
capture, capture while retirement is queued, failure before transfer, and
32 exact-domain refusal controls. No mock carrier or host cleanup loop is
used. One ordinary native operation 47 performs the later retry outside the
enclosing lock, and capabilities, native registries, artifacts and file
descriptors return to their original state.

The frozen image was then rerun through all six original component gates and
six original campaigns with the original 300/660-second campaign limits.
The existing records, hash/equality, resources, VerifiedProgram, exceptions,
packer, managed-edge, invocation, invocation-custody and truth-prerequisite
groups also passed against this exact image.

The code-body whitelist rejects Q08. The new public enclosing owner must
also reject the entire Q08 domain. That derived public-profile gate remains
separate from this Value component. Final Future/BG composition and the
whole public runtime are not claimed by this receipt.
