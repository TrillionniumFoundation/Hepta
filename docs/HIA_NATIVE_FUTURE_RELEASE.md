# Source-bound native Future release

The final native release owner now executes the Future family as stage 13,
after the existing NDU runtime stage. The retained HIASTD01 recipe compiles
the complete matching family twice, constructs its native packer executables,
checks every source and image identity, and publishes five flat images plus
their frozen construction receipt.

The matching family is the inherited-Future version qualified in
HIA_BACKGROUND_NATIVE_FUTURE_INHERITED.json. Its original public owner,
kernel, cell, carrier, timeout, logger, value representation, notifications,
array observers and iterable observers are unchanged. Rebuilding the five
images from their current HIA sources produces the exact previously qualified
bytes. Historical component receipts are retained as evidence for their
original versions; they are not silently updated to describe this build.

## Products

| Product | Bytes | SHA256 |
| --- | ---: | --- |
| hia-result-value.core.bin | 990342 | 6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c |
| hia-future-notify.core.bin | 80226 | 4a06fc521a47285685a6632e0f17b876364ee5e934bb81f5eb3f4195dc263580 |
| hia-future-public.core.bin | 1991586 | 6615552f0a51de92ae2eba6294339167089572fa8db61ecd71751637aae4838f |
| hia-future-observers.core.bin | 301031 | 640bda6bf540218f7e8b02c33b5c48c37681c19b2c74363b3ae5ceb46ef642ba |
| hia-future-iterable.core.bin | 513782 | 5b4c98c6325abb9b597e70574f8cc7136af7db8758a7e2fde5910c3cd8d0fb9f |

The recipe also publishes hia-future-build.json, exactly the retained
docs/HIA_NATIVE_FUTURE_RELEASE_BUILD.json bytes. It checks that receipt's
digest before publication. Its 28 source modules, five readable mechanical
bridge sources, compiler identity, native kit and individual filter identities
are recorded in that receipt and checked by the recipe.

## HIA packing adapter

The existing notify, array and iterable packers use a status return and place
the resulting image length in workspace word zero. Native release filters
return an image length. The new background_optimizer_future_release_packer
is a HIA adapter between those interfaces. It contains the unchanged original
packer functions with their internal calls renamed, selects only those three
functions by their existing packet magic, preserves their errors, and returns
the checked output length after success. Requests never provide an executable
address or a claim that packing succeeded.

The generator verifies and renders the combined HIA program. The actual native
compiler produces a 51,377-byte flat image with SHA256
a32df6cf3f5976874b4df217a06b9b082acf95c57e424ef19919d599b8237465.
The retained HIA source itself is 75,851 bytes. All other family HIA policies
remain byte-identical to the source-pinned inherited-Future checkpoint.

## Construction and qualification

The development qualification executes the 813,129-byte hia-source-build
compiler with SHA256
494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af.
Each of the 28 modules is compiled twice with identical bytes. The compiler's
actual build and pack operations construct the three-source native filter kit;
that native kit constructs every packer executable. The kit and wrappers are
checked against their independent fixed mechanical ELF templates. The actual
HIA packers then produce all five images above, including the array image
embedded by the iterable packer and the notify/value images embedded by the
public Future packer.

Eighteen checks cover source-kit correspondence, byte identity with the
original packers, empty and unknown requests, truncated packets, output and
workspace bounds, and nonzero reserved fields. Rejected inputs do not publish
an output image. The separate release-registration qualification executes the
new source-compiled owner and DAG roles: all seven registered recipes are
captured with their actual pins, missing captures are refused, and the final
construction phase is selected only after the seventh recipe. Its 34 cases
also check publication order, actual recipe extents and source catalog closure.

Reproduce from an isolated checkout:

```sh
PYTHONPATH=. python tools/generate_hia_future_release_packer.py
PYTHONPATH=. python tools/qualify_hia_future_native_release.py --compiler /absolute/path/to/hia-source-build --output /absolute/path/to/future-qa
PYTHONPATH=. python tools/generate_hia_future_native_release.py
PYTHONPATH=. python tools/qualify_hia_native_release_closure.py --source . --compiler /absolute/path/to/hia-source-build --output /absolute/path/to/registration-qa --compiler-sha256 494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af
```

The generation command consumes the frozen receipt; a new independently
qualified image requires an explicit receipt update. The development drivers
and generators are outside the native production source authority. The
retained HIA sources, HIASTD01 recipe and ordinary source-bound receipt are
the production inputs.

## Remaining aggregate gates

This change closes matching-family source construction and its release
registration. It does not supply the remaining unified typed public dispatcher,
callable/environment ownership, external signal provenance, complete
BackgroundOptimizer or multiversion public runtime. Executing all HIASTD01
nodes under the full native release owner, cold qualification, installed
reconstruction and production activation remain distinct required gates.
No result in this receipt authorizes retirement of an active old implementation.
