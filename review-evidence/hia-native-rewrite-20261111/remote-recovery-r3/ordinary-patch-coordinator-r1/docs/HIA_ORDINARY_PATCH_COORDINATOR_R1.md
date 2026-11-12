# Native ordinary patch coordinator: exact raw JSON path

Status at submission: new source, zero generation, zero B3 compilation and zero
runtime entries for this coordinator revision. The existing preparation and
receipt leaf results are separate evidence and are not counted here.

## Runtime ownership and order

The new HIA role 56 owns this sequence:

1. Invoke the existing actual program child on the original program byte view.
   Validate its terminal event and complete private receipt, copy its canonical
   Core and independently hash that exact copy with the actual native hash peer.
2. Invoke the existing HIA service role 58 and JSON decoder role 31 on the
   original patch bytes with the original flags and decimal-digit limit.
   Preserve the exact error. Only a successful decode reaches preparation.
3. Construct the private preparation envelope from the admitted canonical base
   and the original unchanged request bytes. Invoke HIA role 57 and preserve all
   twenty-two ordered preparation errors. Its output is still an unadmitted
   insertion-preserving candidate.
4. Invoke the exact HIA object-prefix kernel as role 63. It performs the
   caller-owned snapshot and structural checks in their original order, before
   the canonical byte budget. It then emits canonical bytes.
5. Invoke a fresh actual program child on those canonical candidate bytes with a
   distinct child lease. Require a primitive result, authenticate the complete
   private receipt and hash the actual copied Core bytes again.
6. Build the receipt input using the two actual admitted canonical values,
   retained original input identity, and actual preparation metadata. Invoke
   HIA role 59 for interface comparison, exact diagnostics and the complete
   ordered receipt. Publish only the final native outputs.

The original function is hepta/hia_program_tools.py::apply_program_patch at
0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5. Fresh candidate checking in that
function receives a dictionary. Sending an oversized prepared candidate
directly to the raw JSON checker would change error order; the object-prefix
step is mandatory.

The private object-prefix input has a justified producer domain. The original
request decoder accepts integer JSON, strings, booleans and null; it rejects
floating/exponent/non-finite syntax, duplicate keys and invalid scalar strings
before preparation. Preparation works on detached decoded values and emits an
insertion-preserving integer JSON view. This does not claim arbitrary
caller-owned object, alias, cycle or floating-value support.

## Private transport

The standalone development executable reads a 64-byte little-endian header:
HIAEJN01, lease, mode 1, digit limit, program byte count, patch byte count,
zero unused third-view count, and zero reserved field. Program bytes precede
patch bytes. This is a private mechanical transport, not a new public CLI.

The retained executor transforms the initial header into HIAEJI01 and invokes
role 56. The HIA root requires a nonzero lease no larger than UINT64_MAX minus
five, a digit limit of zero or 640 through UINT32_MAX, exact view capacities,
the one-MiB controller workspace and otherwise fresh state. The first program
child uses lease L+1 and its primitive child L+2; the second uses L+3 and L+4.

Success is the retained HIAEDR01 private result: 64-byte header, complete
canonical base, complete canonical candidate and complete ordered receipt.
The terminal 128-byte HIACDE01 event goes to stderr and the successful payload
to stdout. A semantic error exits 2, with its terminal event followed by the
complete native error bytes on stderr and no stdout. Unexpected private ABI
failures retain the executor's original failure behavior.

The coordinator does not accept a caller receipt or digest as Core authority.
It retains the original input identity from the actual first program child
while that child's workspace is recycled for the fresh admission.

## Mechanical executor and ELF packing

The original fixed executor has only two source edits:

- Permit role 57 and role 59 as actual one-shot component calls, while retaining
  the rejection of direct entry to controller roles 56 and 58 and the original
  protected program-child roles.
- Clear the role-63 second-read-only bit because the new role 63 is the actual
  object-prefix kernel and writes its output buffer.

All other original executor bytes are retained. It performs explicit memory,
descriptor, native-call and stream operations; no JSON, Core, patch or receipt
business logic is added. It still consists of a small assembly template, so this
component does not establish that every project source is now HIA.

The HIA packer emits the entire final ELF and its 63-role table. Development
binutils supply the fixed template only; the final file has one RX load segment,
a non-executable stack declaration and no interpreter or dynamic loader.
The independent build compares every byte of the actual HIA-produced ELF with
a separately constructed expected layout, including all padding and addresses.
Neither that comparison nor an image hash grants semantic qualification.

The four replacement role images and the packer are freshly compiled by the
exact original 35ee compiler. All other roles keep the full original source and
image binding. The dependency reader verifies every original artifact member
and its content hashes and modes before it issues the original role files.

## Independent validation

The submitted CI runs five fresh B3 compiles and one actual native ELF-packer
entry. Every B3 invocation retains 10 CPU seconds, 20 wall seconds, 256 MiB and
the original one-MiB source/output/workspace domain. The original limits are
128 functions, 1536 blocks, 8192 operations, 256 blocks per function, 16 block
parameters and an SSA index below 2048. There is no 128-operations-per-block gate.

Nine independent runtime groups retain 90 CPU seconds, 180 wall seconds and
one GiB. The harness also checks cumulative parent-plus-child CPU consumption.
They cover:

- 113 complete transformation and later-refusal cases across primitive v1–v8,
  v1/v2 patch policy and all four edit actions.
- 58 original preparation diagnostics and ordering cases.
- 48 reachable interface, effects, default-loan and returned-loan cases.
- Raw input syntax, duplicate keys, depth, UTF-8, non-finite syntax, decimal
  limits and base-before-request failure order.
- Exact original input identity, 64 distinct edits and an actual structured-v2
  base before an ordinary patch.
- Original 1024-function admission before a candidate exceeding that domain.
- Oversized prepared candidates whose byte and snapshot/node failures must
  retain the original object-input order.
- Two actual near-eight-MiB admitted values and their complete receipt.

Every case executes the actual fixed ELF and compares its complete success
bytes or complete error bytes with an independent call of the full original
apply_program_patch. Python reference business owners are disabled while the
native process runs. Original input packets, process stdout/stderr, complete
outputs and expected bytes are preserved as verified compressed content objects.
Source, image and executable identities and modes are checked before and after.
Native process counts are not reported as inferred internal component-entry
counts.

## Remaining closure

This development join does not install a public CLI, authorize filesystem
publication or Store transactions, provide the Python caller-owned object API,
replace the general backend, remove build-time Python, or qualify the entire
native distribution. The user-requested final cleanup remains conditional on
actual complete native replacement and matching-source end-to-end gates.
All old implementations and original failures remain available while that
work continues.
