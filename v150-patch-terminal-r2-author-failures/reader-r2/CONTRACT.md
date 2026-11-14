# Terminal reader R2: streaming publication only

The first Root readback exited with code 137. Its only output is the complete
160,481-byte STAGES.json. No FRAMES.json or terminal RESULT was produced. This
is a failed independent readback, not a failed qualification rerun: the earlier
20-owner product result remains its original actual result. The available
environment observations do not establish the cause of the termination.

R1 is retained without edits. The explicit R2 changes one function, `publish`,
and the independent author/output path constants. All source, runtime, control,
test, owner, frame, Native12 snapshot, VM selection, comparison, and final guard
functions remain byte for byte. READS, SEEN, OBSERVED_READS and all prior input
structures are unchanged. There is no sampling, caching, missing-file fallback,
input reduction, product execution, or budget change.

R1 publication materialized the complete json.dumps string and its encoded
bytes while the verified frame metadata was still resident. R2 first streams
the same JSONEncoder settings to determine exact length and SHA256. It then
streams the same encoding to an exclusive new file, calculating SHA256 and Git
blob SHA1 incrementally. Each pass uses the same sorted keys, indentation,
default encoder options and final newline as R1. A separate held-file read
verifies every output byte through both hashes and exact length, while checking
the held/named seven-field identity before and after. Publication does not
materialize the entire serialized document as an additional string or bytes
object. Individual encoder chunks remain subject to the same value strings
already present in memory; this change does not claim a bound on all R1 live
metadata.

R2 is a narrow response to the observed publication point. It does not prove
that serialization caused exit 137, or claim that any remaining memory growth
cannot fail. A second failed readback must remain a new preserved failure.
The R2 reader is not executed by its author. Root reviews the exact inverse and
launches its single independent readback. The original product and R1 output
directories remain read-only, and original qualification status, unknown-frame
custody boundaries, current-cold exclusions and all_frames_retired=false remain
unchanged.
