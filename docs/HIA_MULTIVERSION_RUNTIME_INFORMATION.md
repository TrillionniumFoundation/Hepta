# Native multiversion information capture

This checkpoint closes complete GenerationInfo capture and detached publication
results in the actual HIA runtime. It does not claim the complete public runtime:
full cleanup/history snapshots, final background provider and public typed
exception mapping remain separate integration work.

## Actual ownership and identities

The existing fixed HIA runtime performs normalization, per-export proof, native
build, sealed load, mapping checks and original VM/native probes. The new capture
continuation reads that same generation holder while its original lifetime and
locks remain in force. It reads the actual descriptor, fstat, seals, loaded
symbol offsets, admitted ABI and proof/probe bookkeeping. The actual embedded
mapping checker is hashed before and after preparation. A caller cannot submit
successful mapping, proof or resource observations.

The full GenerationInfo JSON is allocated once and owned by the generation.
GEN offsets 168 and 176 store its allocation and extent, including its 32-byte
HIAMVIR2 envelope. Generation destruction frees it exactly once before freeing
the generation. Each info/publication result receives a separate allocation
before the original writer or lease unlock. That returned value survives later
publication, runtime close, lease close and final generation retirement.
The receiver owns the returned allocation and must release it.

The capture frame has an exact checked dynamic allocation. Public generation
and epoch digits are never narrowed to a machine integer or a fixed scratch
span. This does not waive original filesystem limits: the original artifact
name is generation-{decimal}.so, so a very long decimal can fail actual native
construction. Such failure still consumes the reserved immutable generation.

## Private effect request

HIAMVEX3 keeps the original 256-byte HIAMVEX1 fields and opcodes. Construction
marks this runtime for complete information capture. Existing HIAMVEX1/2
contexts and their qualified behavior remain unchanged. Subsequent internal
calls on an EX3 context retain the capture setting.

Operations 1 (publish), 6 (lease info) and 7 (rollback) return detached
GenerationInfo. Operation 2 (publish-if-current) returns the complete original
publication dictionary: generation, selection_epoch, prepare_ns,
max_prepare_ns and measurement_admission when supplied. Expected generation
and epoch remain full canonical decimal tails at lengths 224 and 232, with
actual comparison under the original selection lock. The original token
commit marker and budget checks are unchanged.

The existing HIAMVER1 result stores the owned allocation pointer/extent at
144/152. Its allocation begins with HIAMVIR2: magic, kind (0 information or
1 publication), status zero and JSON extent. There are no trailing bytes.

## Pure information facet

The fixed six borrowed-view role returns u32 status, never a truncated result
length. Success is zero. Bad private input returns 0xfffffffd; insufficient
output returns 0xfffffffe without output writes. Workspace is 8192 bytes and
its first word reports the complete required extent. The resulting HIAMVIR2
length is u64. Input, workspace and output are separate owned spans.

HIAMVGI1 has a 512-byte header followed by generation digits, optional epoch
digits, admitted HIAMVAB1 ABI and optional measurement JSON. The header carries
actual hashes, artifact size, proof/probe counts, original baseline/profile
flags, descriptor identity and loaded mapping offsets. HIAMVPI1 mode 2 has a
128-byte header and already captured GenerationInfo JSON, full epoch digits
and optional decision JSON. These fragments are from fixed native owners;
this private facet is not a public JSON admission or proof interface.

HIAMVPI1 fields are mode 2 at 8, GenInfo JSON extent at 16, epoch extent at 24,
measurement extent at 32, prepare_ns at 40, max_prepare_ns at 48 and zero
reserved words through 120. The preparation budget stays below 2^63.

## Failure order and cleanup

An allocation failure before publication follows the original preparation
cleanup. An allocation failure after the actual commit reports that failure
and preserves the committed marker, selected generation and token. It never
reruns publication. The pending physical unlock must complete before ordinary
coordinator unwind: the coordinator removes that unlock from its held mask
when it issues the operation, before the effect finishes it.

The first real failure-injection campaign exposed an omitted physical unlock
on this post-commit path. Its failed evidence is preserved. The corrected
same-image campaign covers all eleven actual capture/output allocation
sites and controls, including finalizer resource and allocation accounting.

## Native construction and qualification

The complete actual component is assembled by the qualified HIA compiler,
closed HIA packers and closed HIA shared linker. The readable assembly change
is limited to fixed role dispatch, actual code-span observation and unchanged
mechanical effects. Final production reconstruction does not run the Python
development authors or assembler.

The companion JSON record contains all source/artifact pins, complete
qualification records and the explicitly retained failed campaign
explanations. Qualification includes the original dataclass, eleven scalar
ABIs, actual loaded mappings, proved-total profile, 200-digit actual generation,
16,385-digit epoch carry, 1,048,577-digit pure information formatting,
concurrent publication/info, last-reference finalization, retained results,
private frame/short-output guards and original runtime/carrier regressions.
The component records preserve whole_native_runtime=false.
