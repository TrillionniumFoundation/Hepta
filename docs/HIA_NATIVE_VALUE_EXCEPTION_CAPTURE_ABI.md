# Native exception capture

This component captures already materialized exception state into the unique Value arena. It is not qualification for Python exception constructors, OSError errno specialization, formatting, tracebacks, or generic callable execution.

## Q05 operation 75

The 128-byte HIABVQ05 request uses A at 24 for an actual BaseException subclass class capability, B at 48 for an exact tuple of args, and optional C at 72 for an exact namespace dictionary. All other fields except magic and operation are zero. An absent C creates a distinct empty dictionary.

The response is the established HIABVR01 capability response. Success publishes a real kind-8 object whose actual class, args tuple, namespace dictionary, and class name participate in the same collector. Q03 type/isinstance and Q02 descriptor operations observe those actual objects. Validation uses class identity and MRO, never a class-name tag. Failure before publication returns no capability.

## Q05 operation 87

The exact 128-byte class request uses arg0 at 104. Canonical IDs are 38 ArithmeticError, 39 OverflowError, 40 StopIteration, 41 MultiversionRejected, and 42 HIAProgramRejected. The catalog is extended lazily so preexisting resource construction keeps its original allocation order.

## Evidence

The unchanged original 494833 compiler built every one of the 15 modules twice, and the native HIABVP07 packer matched the independent byte oracle. The new exception capture gate passed 18 groups against CPython 3.14.4, including actual kernel getrandom EIO and arena mremap ENOMEM, real subclasses and impostors, strong args/namespace retention, and exception/container cycles. Existing 31 record, 17 resource, and 10 hash/equality groups passed against the same image. The original six large campaigns have not been rerun for this component checkpoint.

The frozen image is 3,097,603 bytes, SHA256 f15f08b0301c73d0d63fc552d555dc00617130288680c808a812a05d25c8ce63. The previous fully qualified 14-role checkpoint remains separately pinned; no previous pass has been retagged.
