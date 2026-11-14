# Default HIA owner candidate wheel

The explicit candidate builder packages the existing complete `full_cost.hepta`
owner with its image, child manifest and a fixed helper-bundle digest. Installing
this Linux x86-64 candidate makes the ordinary `assess_full_cost` call use HIA
without a native selector in the environment. The ordinary worker likewise
captures that package-owned bundle before service effects.

The checked-in pin is `None`. Source checkouts and ordinary portable wheels keep
their existing defaults and the two retained Python arithmetic bodies. This
change constructs and checks the next default artifact; it does not delete those
bodies, replace SQLite or the Python worker, or activate a production release.

## Platform and public behavior

The active Core CI jobs run on Ubuntu, and native executable profiles declare
Linux x86-64. The portable Python distribution has only a Python >=3.11
requirement. Twenty-five original full-cost/holdout/wire methods have no OS gate;
thirteen real process-observation methods require Linux. The absence of a broader
formal platform promise is not permission to narrow those portable APIs.

The candidate uses `py3-none-linux_x86_64`, `Root-Is-Purelib: false` and a build
tag distinguishing explicit development from matching-cold construction. It is
not substituted for the portable artifact. An incompatible target refuses its
native candidate; the portable source profile is still available unchanged.
All original full-cost input domains, report fields and refusal ordering remain.

## Construction and bootstrap order

```sh
python -B tools/build_hia_default_release.py \
  --compiler /qualified/current/B3.image.bin \
  --cold-report /qualified/current/cold.json \
  --output /new/private/default-native
python -B tools/qualify_hia_default_release_callers.py \
  --package-build /new/private/default-native/build.json \
  --evidence /new/private/default-native-callers
```

The strict builder validates the completed cold report against the full current
source identity before creating its output. It compiles the existing HIA owner,
checks the complete compiler output receipt, captures the ordinary package inputs,
and builds an actual ordinary wheel with the existing setup hook. Every production
Python module and packaged source is checked against captured source bytes.

Only then does it derive the data-only `hia_default_native_pin.py` declaration,
bundle, image resources and platform wheel metadata. Wheel `RECORD` is regenerated
over the exact final bytes. The build report records every derived member and the
final artifact digest. No other runtime Python source is transformed in packaging.

The source contract binds the handwritten loader, builder and portable pin
template. The derived image and pin are outputs, not cold source inputs. Adding
their own digests to the cold input would create a cycle. The installed worker
identity hashes the actual derived pin, which binds the exact helper bundle and
its child manifest/image. The pinned HIA source stays byte-identical to cold input.
The package provenance identifies the source template separately from its generated
declaration; it never claims that every installed byte equals the cold source tree.

`--development` is an explicit, mutually exclusive construction mode. Its pin,
wheel build tag, component receipt and package report remain development-scoped.
It cannot supply a matching-source cold qualification.

## Default and administrator custody

The package pin module is always installed. Missing or changed bytes cannot turn
an installed candidate back into the portable profile. Its independent installed
wheel `RECORD` binds both the declaration hash and the default bundle inventory;
even rewriting the declaration to the valid portable `None` template in a fresh
process refuses. Native selection occurs at
the original lazy full-cost admission point, after the same validated arm inputs.
The captured bundle, child manifest, HIA source, image, pin and installed inventory are checked before
and after native entries. No runtime authoring or compiler import is required.

The worker first retains its original ambient-selector and incomplete-pair
refusals. Without administrator flags it then binds the package bundle using its
fixed digest. Scope ownership, file identity, environment restoration and terminal
attestation continue through `native_helpers_scope`.

An explicit administrator bundle takes precedence as a complete executable set.
The default resolver never supplements it. If that scope lacks the full-cost
owner, calling full cost refuses instead of using package or generic-loader code.
An explicit valid alternate full-cost bundle works through its captured image.

## Acceptance before deleting retained arithmetic

The component controls build and install a real candidate outside the checkout,
forbid both original arithmetic bodies, and check actual HIA calls without
selector variables. They exercise the ordinary worker and restarted service,
explicit bundle precedence and omissions, ambient selection, independent public
threads, missing/corrupt package inputs and warm custody. A real portable wheel
control keeps the previous API available on other host observations.
Repeated ordinary calls also require each image to disappear by reference-counted
cleanup with cyclic GC disabled; the image and its captured custody do not retain
each other through the construction lookup table. Pin and inventory file reads
use an explicit 8 KiB buffer without enlarging their existing read bounds.

The caller qualifier runs all 38 unchanged methods in the six complete original
modules retained by `qualify_hia_full_cost_callers`. It records every planned,
started and stopped identity, actual native calls, installation provenance and
before/after source and package hashes. No skip, expected failure or omitted
method is accepted. `full_cost_0daf86d.py.txt` remains the independent frozen oracle.

Deleting `_reference_arm` and `_reference_decision` is a later, explicit default
transition after matching-current-cold artifact and installed-default gates pass
and the remaining platform distribution contract is settled. Their 26 lines are
still production source here; this candidate does not claim their retirement or
whole-native delivery.
