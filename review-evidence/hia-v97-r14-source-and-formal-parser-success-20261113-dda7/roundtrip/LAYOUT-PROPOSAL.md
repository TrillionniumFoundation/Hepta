# Resident layout: measured constraints and next candidate

The fixed v95 render-v2 actual build contains a 49925-byte controller,
260056-byte frontend and 598469-byte semantic checker. Its packet is 908498
bytes; the aligned ELF is 913408 bytes. The original 1 MiB aggregate leaves
135168 bytes. These observations come from its actual `public-builder-r2/built`
images; they are not estimates of the newer checker revision.

This independent build produces a 281588-byte existing canonical image and a
193766-byte new reparser. Even the reparser alone exceeds the v2 free space.
Appending both original binaries is therefore not a valid integration plan.
The existing packer also has exactly two fixed resident slots, not a general
indirect-function capability.

The next candidate should replace the current representation resident with a
single explicitly selected representation component containing render,
reparse and canonical modes. Shared HIA JSON/preflight/escaping/sort helpers
must be captured once, with exact source and call-edge projection. The final
byte comparison belongs to the HIA controller and may consume only two
successful canonical results bound to the retained original input and the
independent reparse output. Its private buffers must retain the original bytes
until that comparison completes. The semantic resident's original required
passes must all remain.

The existing frontend already contains the decoder and canonical subtree
serializer. These are real reusable code, but no combined image size or fit
has yet been measured. The reparser's relocated attribute scanner has a
different buffer layout and cannot be blindly deduplicated by name. Sharing
it requires an explicit common scratch/offset interface or a separately
qualified whole-document validation step that preserves each attribute's
2048-node/depth-16 limit and duplicate-key refusal. Removing that check, or
borrowing a previously qualified serializer's result without executing it on
the new reparse output, is not an acceptable space reduction.

The v2 checker already removes statically unreachable helpers. Merely proposing
that same dead-function pruning again supplies no evidence of a further size
gain. Any later phase specialization, shared code relocation or changed
resident layout needs an actual new compile, exact input custody and full
positive/negative controls under the unchanged 1 MiB, 20-second and VM limits.
The frozen v2/v3 and this independent component remain separate scopes.
