# Native Core bytes JSON front door

This is an explicit new bytes-only API. It does not activate or replace
`hia_program._decode`, the existing public verifier, or the retained host stack.

`NativeCoreJSONBytes.decode(raw, nominal_image)` uses two pinned native HIA
images. The first image validates the entire UTF-8 input, performs the existing
ordered syntax/duplicate-key preflight at Core's 262144-node and root-depth-64
limits, checks the selected decimal integer digit policy, and emits sorted,
compact, non-ASCII-escaped UTF-8 canonical bytes. The second image emits the
nominal packet from those canonical bytes. Consequently packet object order
matches the detached value returned by the original `_decode` path, including
nested keys and normalization of negative zero.

Python owns fixed image admission, private buffers, scalar request/reply fields,
hashes and the established public exception rendering. It does not parse a
payload, construct a payload value graph, sort keys, canonicalize JSON, or walk
the resulting packet. The optional constructor wrapper is produced by the
nominal image and is not charged against the submitted Core JSON node budget.

The accepted bytes domain retains the original 8 MiB limit and integer/string/
bool/null subset. The complete UTF-8 check precedes syntax and structural
preflight; the complete preflight precedes decimal integer conversion policy.
An overlong byte input reports `E_HIA_LIMIT: program exceeds byte budget`.
A structural excess reports `E_HIA_LIMIT: program exceeds structural budget
before JSON allocation`. Invalid syntax, Unicode, duplicate keys and decimal
policy violations report `E_HIA_FORMAT: invalid/deep UTF-8 JSON`.

Integer policy defaults to the caller's `sys.get_int_max_str_digits()` scalar,
captured once for both native image calls; an explicit policy is also recorded.
Zero disables the decimal digit limit. No arbitrary-precision Python integer
is constructed from the payload. The Core limits remain fixed even though the
generic nominal codec independently supports depth 128.

The front image deliberately reuses the existing HIA arena decoder and HIA
canonicalizer rather than adding a second grammar. Native admission builds an
arena, checks integer lexemes, then canonicalizes the admitted immutable wire.
The second image owns all canonical-wire-to-packet conversion. Both images'
identities, the integer policy, the raw and canonical input hashes, the source
node count and packet identity are carried in the returned immutable records.

The builder requires a matching complete cold source contract containing the
new source. Development tests instead report their real seed/B1/B2 compilation
scope explicitly. A local component test, successful compilation or packet
equality case is not whole-stack qualification or an all-input refinement proof.
