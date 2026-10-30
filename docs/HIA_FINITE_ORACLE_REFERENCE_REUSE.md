# Bounded deterministic reference reuse for finite contexts

`build_bank(..., reuse_oracle=True)` explicitly opts one finite native bank into
reusing trusted deterministic oracle results. The default remains `False`.
The original `protocol_v1.json`, its 120-second limit and incomplete studies
remain unchanged. No native result, qualification, proof or consumed plan is
cached.

Every candidate is still freshly proved all-input equivalent to the bank's
baseline, checked against its selected LLVM, compiled and bound to sealed native
bytes. Before each preparation and execution the existing implementation and
held-descriptor checks still run. The reference namespace binds the actual bank,
baseline Core digest, checker implementation digest and reference profile. Its
exact canonical key contains mode, seed, fixed parameter and the complete value
sequence. IDs and equivalent candidate slots are omitted only from this pure
reference key; they remain bound in the independently consumed trace and native
event verification. A different bank cannot import entries or reports.

The oracle was already trusted host code, finitely crosschecked against the VM.
The opt-in additionally requires deterministic results for the exact input over
the bank lifetime. It does not prove Python purity, source-C refinement, final
machine-code correctness or whole-language safety. Changing the trust assumption
must not be concealed behind this cache. The cache is bank-local, nonpersistent,
unserialized and unshared with another owner.

Two independent caps apply: 256 entries and 1 MiB of retained canonical input
plus outcome bytes. At either cap a miss computes the ordinary oracle without
storing a new entry. This changes cost, never expected semantics or budgets.
The stored values preserve the first trap and its position, or the returned
state and rolling checksum. They are immutable tuples. There is no eviction,
automatic execution replay or replenishment of trace nonces.

`oracle_reference_statistics()` returns a diagnostic copy with hits, misses,
failed computations, capacity bypasses, actual creation/lookup/computation/store
and clearing wall times, peak counts and bytes, and retained canonical-byte
nanoseconds. The byte metric includes both exact key and result encodings. It
does not represent Python RSS, physical energy, money or a memory-safety proof;
Python container overhead remains bounded indirectly by the independent item
cap. Complete preparation time must still be charged, because the component
timers are diagnostics and are not an exhaustive physical cost decomposition.
Close clears the cache after attempting native resource release, including when
native cleanup debt remains. Pure reference storage is not authority to close
an uncertain descriptor or restart an uncertain child.

## Separate frozen-before-run experiment

`experiments/hia_crc_context/protocol_v2.json` and
`tools/qualify_hia_crc_context_reuse.py` define a new 60-observation matrix:
two fixed synthetic input phases, two repeats, three polynomial workloads and
five original policies. A trace contains sixteen 256-byte requests. Every arm
uses the same cache policy, and all 240 child contexts actually execute.

Before timing any arm, four baseline plans populate the independent reference
set and are cancelled without native execution. This work, the complete
source/kernel proofs, all winning and losing candidate builds, input generation
and final bank cleanup are charged to cold setup. Each measured arm must incur
no new oracle miss. Every arm still pays its actual lookup, trace construction,
full native lifecycle and output validation. Raw attempted contexts are retained;
failures are not rerun or removed. The new study has a 300-second checked-between-
operations limit, while each child keeps the unchanged 5-second wall and
3-second CPU limits. This is not a hard real-time bound on the parent process.

The primary finite-job gate compares complete **host** arm costs against the
strongest of all three static controls, subtracts complete cold setup and release
cost, and requires distinct exported code. Native-only timing is a separate
diagnostic. Envelopes over two repeated synthetic inputs are not confidence
intervals. There is no cache-disabled end-to-end arm, so this matrix cannot
establish a net cache speedup; its mechanism tests establish avoided repeated
reference computation. It also contains no NDU policy and cannot demonstrate
NDU value, general dynamic adaptation, production demand or global optimality.

Source and protocol are committed before local execution. The evidence records
`local-frozen-before-run` and explicitly makes no public preregistration claim.
Both positive and negative outcomes retain this cost and claim boundary.
