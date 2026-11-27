# Original diagnostic observer limitation

The immutable first phase report is retained unchanged. Its `NativeStoreLifecycleImage` timing/count entries are nested observations, not a count of distinct machine calls.

In the fixed product, `NativeStoreLifecycleImage` inherits `NativeContinuationImage`, which inherits `NativeHiaJsonImage`. The diagnostic patched both the generic base initializer and Store initializer. The generic initializer installed a sampled wrapper, then the Store initializer captured that wrapper as its `actual` entry and installed the original Store receipt observer around it. Each invocation consequently visits `Profile.native_call` twice under the same label. Both wrappers also append image metadata for the same construction, so those two records do not prove two mappings.

The raw total of 2,422 is therefore not 2,422 distinct machine entries. Sample timings under that label include the inner observer and do not establish an exact Store C-entry CPU total or a true one-in-64 sample of distinct machine calls. The original Store qualifier receipt observer still runs once for each matching full table return and reports mode1=1,090 and mode2=120 in each case. That separate original receipt observation is preserved without changing its predicate.

The source scan, public Store call, publication effect, context timestamp and client-stage observations are not duplicated by this inheritance. All fresh maps still match the complete original 1,429-path map. Namespace, request and budget image wrappers are attached once. Timings remain instrumented observations and cannot qualify the original 35-method group.

A future diagnostic successor can avoid the nested Store wrapper by leaving generic-base Store entries unwrapped and observing them solely in the Store initializer. No original report is rewritten, and no business rerun is requested merely to improve this optional counter.
