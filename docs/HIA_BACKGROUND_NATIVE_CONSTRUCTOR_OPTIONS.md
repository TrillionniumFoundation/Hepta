# Native background constructor options

## Current scope

This HIA policy preserves the original constructor's scalar options and exact
bridge key set. Actual construction on ROG compiled the policy and packer twice
with the pinned 494833 native HIA compiler, constructed the object with the
native HIA packer, and checked the full mechanical prefix and relocations.
The original unmodified qualifier then executed the native policy with the
matching complete eleven-role Value image under CPython 3.14.4: all 5397
original boundary comparisons and the empty-cleanup case passed, for 5398
policy calls and 11655 actual Value calls. The 24 original native packer cases
also passed. These results are recorded in
HIA_BACKGROUND_NATIVE_COMPONENT_CONSTRUCTION.json.

This qualifies the options boundary through the first Path call. The original
runtime type fixture is used only to reach that boundary; it does not establish
the actual public Runtime class check. Actual integrated lifetime and failure
behavior, path conversion, complete construction, worker ownership, and final
production qualification remain with the enclosing BackgroundOptimizer gates.

The enclosing constructor must first perform its actual runtime type check. It then calls this policy, creates a live iterator over the original bridge dict, and interleaves each iterator next with actual path conversion and path resolution. It must then verify the baseline, validate the scalar function and actual runtime baseline/current binding, allocate the coordinator and start the worker in the original order.

The returned options do not contain resolved paths or frozen copies of path values. A first path's actual __fspath__ callback can modify the second dict value. The subsequent iterator next must see that current value. Dict size and key changes use the native live-iterator protocol; they must not be replaced by a caller-supplied list or verified flag.

## Exact option behavior

The policy preserves this order and these defaults:

| Option | Admitted exact type and range | Default |
| --- | --- | --- |
| max_pending | exact integer, 1 through 8 | 8 |
| timeout_ms | exact integer, 1 through 5000 | 2000 |
| bridge_timeout_s | exact integer or binary64, strictly positive and at most 60 | binary64 10.0 |
| bridge | exact native dict with the keys binary and build_receipt | required |

Boolean values do not count as exact integers. Integer magnitudes are inspected as native decimal values before conversion into machine words, so huge positive or negative integers follow the original range-rejection path without JSON conversion or a new digit limit. Positive finite binary64 values are compared by their exact bit pattern; positive subnormals are accepted, while either zero, negative values, infinities and NaNs are rejected. Integer versus binary64 timeout identity remains explicit.

Bridge membership is checked through actual dict lookup and its key equality rules. This allows the shared value owner's legitimate string-base subclasses to compare as string keys while bytes keys remain different. Temporary lookup keys and retained values are all released before a normal result. No path method is invoked here.

Original validation failures carry the exact BackgroundOptimizationRejected class and E_HIA_BACKGROUND messages. Capability, lifecycle, allocation and malformed-provider failures are separate private results.

## Fixed six-word interface

Export: hia_background_constructor_options. Arguments are input pointer/length, output pointer/length, and work pointer/length. Input is exactly 128 bytes, output at least 32768 bytes, and work at least 2048 bytes. Views must be disjoint, nonwrapping, and present.

### Request

HIABOPQ1 has operation at 8: 0 validates options; 1 retries only retained cleanup. Reserved words at 16 and 120 are zero.

| Offset | Operation 0 field |
| --- | --- |
| 24, 32, 40 | Actual max_pending value capability |
| 48, 56, 64 | Actual timeout_ms value capability |
| 72, 80, 88 | Actual bridge_timeout_s value capability |
| 96, 104, 112 | Actual bridge dict value capability |

An all-zero optional capability means the argument was omitted, not that its value is None. The required bridge capability cannot be wholly zero. Original missing-required-argument binding belongs to the enclosing public constructor. Operation 1 requires all four input capability fields to be zero.

### Captured context

HIABOPC1 occupies the first 128 bytes of work. It contains the actual value entry at 8, value context pointer at 16, its extent at 24, captured PID at 32 and retained-state classification at 40. Remaining prefix words are zero. Work 128 through 1919 stores the component's retained continuation only after failed cleanup.

The parent holds actual dependencies and all input capabilities throughout the invocation. It captures the new actual value owner supporting HIABVQ02 operations 29 and 31 and holds its context and executable closure strongly through cleanup. Each simultaneous invocation has its own work frame. A frame with retained state remains exclusive until cleanup completes. Classification 1 means remaining owned references or an actually recorded mapping cleanup can be resumed. Classification 2 means an unknown or inconsistent completion requires persistent quarantine; the component refuses blind retry.

### Reply

HIABOPR1 uses a 192-byte header:

| Offset | Field |
| --- | --- |
| 8 | Status |
| 16 | Validation completed, only on successful completed result |
| 24 | max_pending |
| 32 | timeout_ms |
| 40 | bridge timeout unsigned integer or exact binary64 bits |
| 48 | 1 for integer timeout, 0 for binary64 |
| 120 | Original validation code, 1 through 4 |
| 128 | Original error JSON byte count |
| 136 | Retained-state classification |
| 144 | Private dependency/detail code |

Other header fields are zero. No owned result value is transferred. Original error JSON begins at 192. Statuses are 0 success, 1 original rejection, 5 actual allocation failure, 6 lifecycle/PID refusal, 7 dependency failure and 9 retained cleanup. Invalid private frames return 0xfffffffd. The mechanical entry may zero only its output phase word at 256 before semantic frame rejection; disjoint-view and range rejection precedes that write.

A successful cleanup-only request returns the saved completed result if validation already completed. It never repeats option inspection or path effects. A cleanup request on an empty frame returns success with completed zero.

Temporary references are released using operation 29's explicit HIABVR02 reply. The consumer first validates the complete header, reserved fields, Boolean flags, producer status domain and the operation's correlated success constraints. Malformed replies retain the original owned slot and enter quarantine. A valid known-consumed result clears its slot immediately, including status 11. If a mapping remains pending, the frame records that separate fact and later calls only operation 31. A nonzero post-consumption result without a recorded mapping clears the consumed reference and enters quarantine; it does not retry that capability. Only confirmed operation-31 success clears a saved pending mapping. A nonzero reply before acquisition of the value lock cannot prove that another pending cleanup is gone.

The exact producer domains are 0/1/6/11 for operation 29 and 0/6/11 for operation 31. Status 1 is known-unconsumed with no mapping pending. Status 6 is known-unconsumed. Known-consumed results have only status 0 or 11, and successful drops require known 1, consumed 1 and pending 0. A valid known-unconsumed result with pending 1 preserves both the original capability and the pending mapping, then enters classification 2. Ordinary cleanup cannot retry either operation in an order that proves the original capability was consumed. An unknown outcome is not made retryable by an apparent flag or an unrecognized status.

## Build authority and pending gates

The runtime source pair is background_optimizer_constructor_options.hepta and background_optimizer_constructor_options_packer.hepta. The readable bridge performs syscalls, bounded copies and fixed captured six-word calls only. It makes no type, range, dictionary or ownership decision.

The native construction and original-boundary gates described above have now
passed with the pinned compiler and matching Value image. The original cases
retain the complete timeout range, float boundaries, 100001-digit integers,
exact types, dictionary key equality, and original error precedence. Actual
integrated lifetime and failure controls, the real Runtime class gate, and the
remaining public constructor phases still require their enclosing native tests.

This component does not establish complete BackgroundOptimizer, whole native runtime, activation or repository cleanup.
