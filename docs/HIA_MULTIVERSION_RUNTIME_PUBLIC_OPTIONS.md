# Native public runtime option admission

This component implements the original ordered constructor option checks over
actual native mutable-value capabilities. It is an internal fixed entry for the
public runtime constructor. Program admission, proof, directory creation,
generation loading and the enclosing public runtime remain separate gates.

The qualified flat is 52,136 bytes, SHA256
03c0b69999bebf047286f6008d8e5a71b1855a3bf3b61d171c8ef7be82395014.
Both policy compilations, both packer compilations and both native pack/link
runs are byte-identical. The policy has 16 functions, 142 blocks and 720
operations under the unchanged source-compiler limits.

## Request and fixed context

The six-word entry is hia_mv_runtime_public_options(source, source_extent,
output, output_extent, context, context_extent). Source, output and context
must be non-null, nonoverlapping and nonwrapping. Input is exactly 128 bytes.
Output is at least 32,768 bytes, with the first 128 bytes and any error JSON
forming the returned public record; the rest is private per-call continuation
storage. The fixed context is at least 128 bytes and is never modified.

The request magic is HIAMVOP1. Operation at byte 8 is zero. Actual value
capabilities occupy bytes 24/32/40 for validation_timeout_ms,
48/56/64 for max_live_generations and 72/80/88 for prove_total.
Every other word is zero. An all-zero capability means that keyword was
omitted. An actual native None capability is a supplied value and is rejected
by the original exact-type rule. Partial-zero, stale, foreign and context-token
capabilities are not interpreted as omitted.

The immutable HIAMVOC1 context captures the actual value entry at 8,
its strongly owned context address at 16, its extent at 24, and the actual
constructing process ID at 32. Words 40 through 127 are zero. The composition
owner retains the value context, fixed image and all nonzero input capabilities
through the call. The process is checked even when every option is omitted.
No public caller may choose these captured dependency pointers.

The parent owns all input references. This component only uses native value
operations 7 and 19, which inspect immutable scalar data under the value
owner's mutex. It creates no references, mappings or heap storage and therefore
has no retained-cleanup continuation. Multiple calls use independent output
buffers and may share this read-only context.

## Exact original semantics

The checks run in this order:

1. validation_timeout_ms must have exact integer kind and be between 1 and
   30000 inclusive; omission supplies 2000.
2. max_live_generations must have exact integer kind and be between 2 and 64
   inclusive; omission supplies 8.
3. prove_total must have exact Boolean kind; omission supplies False.

Integer values keep their actual arbitrary precision until their decimal size,
sign and range have passed. Only those admitted bounded values are converted
to private machine words. Boolean, binary64, None, text and container values
are never coerced into integers. The checks do not serialize caller integers
and do not introduce an integer-to-string digit-limit failure.

The original platform check precedes these options in the enclosing public
constructor. This component does not accept a caller-supplied host-support
flag. The final constructor must perform its actual host check before calling
this entry, then perform actual whole-program admission afterward.

## Completion

The entry returns zero with HIAMVOR1. Status is at byte 8, original option
error code at 16, admitted timeout at 24, live-generation bound at 32,
Boolean profile at 40, error JSON length at 48 and dependency detail at 56.
All other public header words are zero.

Status 0 returns the three admitted values. Status 1 is the original
MultiversionRejected class and exact E_HIA_MULTIVERSION message, encoded as
a JSON object with class and message fields at byte 128. Error codes 1,
2 and 3 identify timeout, live-generation bound and prove_total respectively.
Status 2 preserves an actual value-provider MemoryError if reported.
Status 3 is an invalid capability, lifecycle or fixed-dependency failure;
it is never reclassified as an original option-type rejection.

Malformed private frames or views return 0xfffffffd. Mechanical view rejection
does not write any view. A well-formed view with a malformed private frame may
reset only the private phase word at output byte 256; source and context remain
unchanged. No public error or partially admitted option record is published.

## Actual qualification

The final actual native image passed 30,853 comparisons against the unchanged
original ScalarMultiversionRuntime.__init__. The external oracle stops at
the actual _admit effect boundary after the option checks; it does not claim
to execute the later proof, filesystem or generation lifecycle.

These comparisons cover all 30,000 admitted timeout values, the complete
live-generation boundary under both Boolean profiles, all native value kinds,
omitted versus actual None, 600 multi-option error-priority combinations,
machine-integer overflow boundaries and a complete 100,001-digit integer.

Additional actual-native gates passed:

- 45 private request/view/context refusal controls.
- 15 stale, foreign, wrong-nonce, partial-zero and wrong-kind capability or
  destroyed-context checks using the real native value registry.
- 2,048 calls from eight threads sharing the immutable captured context.
- Actual fork-child refusal, including the all-default request.
- Successful real native inspection under an exhausted address-space limit
  after all required buffers and references had been allocated.
- 20 independently captured before/after context controls, replacing a
  tautological comparison in the earlier external observer. Product bytes
  were unchanged.
- 24 HIA packer controls and a complete readable mechanical-prefix check.

All value references were released and the actual value context destroyed.
The companion JSON records complete source/build/report identities and
external QA source text. The mechanical adapter performs fixed six-word calls,
raw syscall forwarding and bounded view/copy operations only. HIA performs
the business checks and diagnostics. External assembly is used solely to
verify the readable adapter against the HIA packer's fixed template.
