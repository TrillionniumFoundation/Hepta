# HIA bounded file reading

The current component is generated as examples/hia_bootstrap/bounded_read.hepta.
Its 14-function program is 57,752 bytes, SHA-256
ae9172bc1a794e9a377652415e66fe672d643352c5ca6d964a352f04d2fc437e.
The complete original 59,728-byte program, original author, six source methods,
finite populations and caller controls are retained in
tests/fixtures/hia_legacy_byte_components_ff636/. The current author generated
the current program; historical bytes are not substituted into current compilation.

## Entry and responsibility

The public HIA entry remains f0(readbuf, mutbuf, mutbuf) -> u32, with exactly
64 request bytes, 24 result bytes and 1,024 private state bytes. The source-owned
ABI is hepta/hia_bounded_read_abi.json. The program owns observation order,
regular-file and size decisions, the bounded read count, context-close
continuations, exception transitions and explicit local/temporary release plans.

Path conversion, OS calls, CPython buffering and context-manager mechanics,
foreign callables/operators, dynamic globals, exception objects and reference
counting remain explicit transport boundaries. The definition-time default is
8 MiB. An explicitly supplied limit retains its original foreign-object
behavior; this component adds no UID, hard-link, parent-directory or pathname
restriction to the original reader.

HEPTA_HIA_BOUNDED_READ_MANIFEST selects the source-bound native component.
An absent selector preserves the original reference entry. An explicitly
selected invalid or empty manifest fails admission. The original
HIAEditRejected, _reject and read_bounded function/class ASTs remain exact.

## Construction and custody

The matching-source builder requires the current complete release contract,
the original cold report, its physical generation location index and all three
actual B1/B2/B3 images. It checks the requested compiler against actual B3 and
captures current host inputs before creating output. It rechecks the physical
generations, current sources, captured host inputs and actual compiler output
before publishing a selectable manifest.

The separate --development entry makes no matching-cold or full-delivery claim.
Both entries retain the original compile limits and validate the original
request, complete output, stdout, stderr and native receipt: 20 seconds wall,
10 seconds CPU, and 1 MiB input/output/workspace capacities. A stale release
contract remains a refusal; adding these sources does not refresh a cold result.

## Original finite controls

The original qualification still has 55 component cases: 12 rejection,
24 lifetime/global-observation, 10 permission-protocol and 9 real-filesystem
cases. Each group keeps its original 30-second limit. The eight original public
caller methods and their seven CLI children retain the 180-second caller group,
20-second per-child limit, exact IDs and observation counts. The complete
qualification keeps its original 180-second outer limit and 3-second cleanup.

The two declared source-name migrations are represented by a pure, fixed
prior_take in tools/hia_bounded_read_source_history.py: six temporary caller
filenames change from .hia to .hepta, and one assembly staging filename changes
from .hiaasm to .hepta. Each relation validates the complete current SHA-256
and the complete original SHA-256. Actual initial/terminal source pins, child
policies and native compiler inputs continue to use physical current bytes.

The new current source checks cover the regenerated program and ABI, immutable
historical corpus, exact caller relation and four unchanged original admission
methods. Historical source counts and hashes remain historical assertions.
Source checks, reference-route caller checks, development native observations,
matching-source cold qualification and installed delivery are separate results.

Arbitrary foreign objects, GC histories, traceback/reflection behavior, async
behavior and finalizer interleavings are not proven by a finite case population.
Build or source-check success alone does not close those domains or claim a
complete native product.
