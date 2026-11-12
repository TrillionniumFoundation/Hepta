# Fixed UNPACK pointer-type cache: independent correction

This candidate changes one production file relative to pure
`006accd3d73d48b9ef39c821be55a5346cd48ce0`:
`hepta/hia_core_unpack_native.py`.

It caches the fixed six-argument `ctypes.PYFUNCTYPE` **type** once. Each new
`UnpackSession` still reads the actual `image._entry` address and instantiates
its own pointer object from that address. All five buffers remain fresh. The
HIA bytes, ABI JSON, transaction/shim bytes, GIL/error flags, old-host poison,
primitive requests and releases are unchanged. There is no result cache,
session reuse, iteration shortcut, effect merger, new resource cap, test
removal or deadline adjustment.

The official CPython 3.14.4 source and the failed run's measured boundary are
already preserved in `deea5bc49e900d7b84a82f0f5fe205db50ebf7e3`, under
`experiments/hia_core_unpack_20261112/native-development-r1-timeout-analysis/`.
That source confirms one newly defined `CFunctionType` on each PYFUNCTYPE call.
The original actual 116 timeout remains a failure. Neither its attributable
cost fraction nor the speed improvement of this change has been measured.

`check_source_and_abi.py` contains six source/structure controls. They compare
the entire reversible source delta; check the original protected inputs and
shim; observe old/new factory construction counts; inspect fresh buffers and
packets at all four arities; inspect actual pointer-type ABI/GIL/error flags;
and check that each session observes its entry address and original exceptions.
The controls use inert integer addresses and never call a function-pointer
object. HIA steps, transaction primitives and the runtime leaf constructor are
poisoned. The report is a local interpreter/source fact, not CPython 3.14.4
native qualification, an actual Core caller run, or a timing benchmark.

The intended difference includes reusing the private ctypes pointer type.
Runtime monkeypatches of the ctypes factory or inspection of fresh private
type identities are not newly asserted equivalent. The CPython object runtime
and single-call C-API transaction remain explicit hosted dependencies.

This is an independent source revision. The old pure006acc, A418/B720,
original failed operation, HIA/ABI images and original 18/116 method IDs remain
unchanged. Root must integrate the new bridge digest into a new candidate,
regenerate its declaration/coverage artifacts, admit a fresh manifest with
the new bridge identity, and perform the original complete validation before
claiming the deadline closed. The standard matching-cold and full-harness
mandatory-gate draft remains separate.
