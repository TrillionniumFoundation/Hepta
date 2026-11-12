# Bounded UNPACK qualification progress, isolated revision 1

This proposal observes the existing complete Core116 only when the explicit
UNPACK qualifier invokes it. It does not modify the default Core qualifier,
its arguments, its three group order, any test body or any original ID. It does
not change the eighteen additional controls, compile budgets, or either new
180-second owner and its three-second cleanup. The independent type-cache
correction is not part of this delta.

## What the events mean

The actual loader uses a TestSuite subclass at every nested level. Its original
suite implementation is still called once. Four inherited hooks surround class
setup, class teardown, module fixture switching and module teardown. Module
fixture switching includes the original preceding module teardown; nested
events show that boundary explicitly. Each beginning or ending transition
writes at most one JSONL record. A return is labelled `normal_return`,
`fixture_error` when unittest has caught an error into its result, or
`base_exception` when the hook propagates an exception. Neither a fixture return
nor a test's start/stop callback is a method PASS.

TestLoader's complete frozen ID list and every actual inner suite are checked
before execution. No suite is flattened, reordered or reloaded. The native
return counter is only sampled at these bounded transitions; there is no
per-primitive logging. The complete original report, its independent success
predicates and real image ledgers remain mandatory.

## Failure and ownership

The log is create-only, held by an open descriptor and bounded to 524,288 bytes,
4,096 events and 1,024 bytes per event. The receipt is at most 131,072 bytes.
Each fixed path is traversed by held no-follow directory descriptors; file
identity and every parent link are rechecked. Short writes, bound failures or
changed paths cannot yield a complete receipt. The original partial log remains.

When an original hook is propagating a BaseException, a secondary logging
exception is retained without replacing it. The same priority is kept when
unittest has already caught a fixture error into its result: subsequent
diagnostic writes stop, original unittest work continues, and the progress
receipt remains HOLD. There is no diagnostic fallback to a PASS.

The new UNPACK reader independently rereads the complete JSONL and receipt,
their current identities, the exact original Core report, current helper and
actual runtime source. It checks strict event sequence, all loaded/started/
stopped IDs, matching nested fixture boundaries and the last complete operation
end. Missing, truncated, duplicate or unmatched events cannot qualify. The final
sampled native-return total is joined to the actual UNPACK ledger. The old thirty
gates do not import or invoke this helper.

## Runtime and evidence scope

Both official CPython v3.12.14 and v3.14.4 `Lib/unittest/suite.py` originals are
retained here; their complete 13,512 bytes and SHA256 are identical. The helper
checks the actual suite source and admits only those two exact interpreter
versions. Matching-cold UNPACK qualification still separately requires 3.14.4.
Any local 3.12 source-control result remains a 3.12 observation.

The nine source controls use real synthetic unittest modules, nested suites,
fixture errors, KeyboardInterrupt/MemoryError and real bounded file originals.
They forbid native constructors and product subprocesses. Heavy cold/image
admission is explicitly mocked only in the reader integration control; these
fixtures make no native or qualification claim. Source-only controls are run
only after this proposal and the exact harness are canonically frozen.

The parent must regenerate its combined contract/coverage and run the complete
source gate after integration. No existing pure candidate, frozen Actions
control, failed run, type-cache source or old thirty-gate implementation is
modified by this experimental proposal.
