# Native path coercion component

This checkpoint contains the persistent HIA coercion owner, a complete TypeError
renderer, and the readable mechanical capsule with an HIA-only production
packer. It is a source and development-qualification checkpoint. Native HIA
execution and the complete public class/factory boundary remain unqualified.

## Composition and custody

`native_path_value.hepta` holds the real input, descriptor, callback result and
temporary message references in its persistent 4096-byte workspace. The fixed
value owner supplies types and method metadata. The callback is invoked outside
the value registry lock. Only after exact cleanup completion does the owner
publish one independently owned result, exception, or complete TypeError bytes.
Quarantine never retries the filesystem method. Unknown reply bytes remain in
the persistent workspace or retained callback allocation for diagnosis.

The shared request and callback contracts are in HIA_NATIVE_PATH_VALUE_ABI.md.
The constructor of that workspace must retain the actual value context and its
captured code. The current private kind8 representation does not by itself
prove the executable lifetime of arbitrary public class objects.

`HIANPP01` has a 40-byte header: magic, count=2, policy length, error-role length,
mode. Mode0 produces the closed general ET_REL export `hia_native_path_value`;
mode1 produces its complete six-word flat image. The two actual HIA images
follow the header. Each image retains the existing 4MiB bound; the emitted text
retains the existing 16MiB bound. Output and workspace refusals are atomic. The
production packer does not invoke an assembler or external linker. The readable
S file is retained as mechanical provenance.

The mechanical capsule validates disjoint source/output/workspace spans and
unsigned endpoint overflow before the policy. It only executes the policy's
fixed syscall, actual captured function, fixed error-renderer, copy and atomic
operations. Its two relative call holes are 245 and 448; the capsule is 669 bytes.
The HIA owner checks the captured PID and a per-frame atomic guard. Prefix 0..127
is immutable, callback work is separate, and temporary maps are retained until
real unmap completion.

## Original behavior covered so far

The independent development matrix calls the running interpreter's os.fspath
and Path constructor. Success compares the constructor's actual single raw
argument, before subsequent path normalization. It covers missing methods,
str/bytes subclass bypass, invalid method returns, three iterator types, actual
callback exception identity and Path's TypeError replacement rule. The formatter
preserves the 200-byte UTF8 precision of `_PyType_Name` after its last-dot rule;
Path's full class name uses original repr and is not diagnostic-truncated.

The local interpreter is CPython 3.12.14. The explicit stable-Unicode development
matrix does not stand in for the original 3.14.4 all-Unicode/native run. PurePath's
actual MRO fast path, arbitrary native class code ownership, and the public MV
and BG factory integration remain open. No class name or caller-verified bit is
used as a replacement for those obligations.

## Reproduction

The same repository supplies the shared result-value author and root's iterator
from 30bf8211d4b21a50ff43a92dcb5d80afa573d3c4. Kind 9 metadata now exposes its actual
mode only at op7/O56; old kinds 0..8 and all other operations retain their old
header fields. Regenerate all dependent HIA roles from this common source.

Run `python tools/qualify_hia_native_path_value.py --output NEW_DIRECTORY` for
the mechanical bridge plus development authors. Supplying both `--image` and
`--value-image` selects actual native components; that mode has not run in this
checkpoint. `qualify_hia_native_path_value_controls.py` is explicitly an offline
author/control suite. `qualify_hia_native_path_value_errors.py` supports native
`--image` or explicit `--author-stable-unicode` for local development. None of
these development results changes the final release or whole-runtime flags.
