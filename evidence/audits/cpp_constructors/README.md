# Independent review of typed C++ constructors

This review found no additional blocker within the constructor core at
`f3bd3ff7d6fdb9fc09e6a88629c2f64fdfdb61b3`. It supplements the author's
qualification with independently authored native probes. It does not prove
whole-library memory safety, foreign nonretention, universal ABI compatibility,
or all allocation-failure paths on other C++ implementations.

The observed compiler source hash stayed
`e7110f318c96da79a7dd7e194c75d1e1390b4d1a3eaeda58ad12c654d6b9fd91`
before and after both replays. The host used GCC/G++ 13.3.0 and Rust 1.90.0.
The generated C++ bridge was not edited to perform fault injection.

## Allocation and lifetime observations

`allocation_lifetime.json` retains 54 fresh native process observations:
six positive baseline cases, 31 individually injected allocation failures,
three constructor-body exceptions, thirteen steps in the public-API search
for an insertion that grows the registry, and one warm reference observation.
The allocation failures use real replaceable `operator new` calls; each
injection fires once, after a specified number of successful allocations.

| Creation path | Observed allocation sites, each individually failed |
| --- | ---: |
| Serialized, cold registry | 6 |
| Serialized, warm registry | 4 |
| Creator-thread handle, cold registry and thread token | 7 |
| Creator-thread handle, warm registry and thread token | 4 |
| `noexcept` object constructor, cold wrapper | 5 |
| Serialized insertion with observed registry growth | 5 |
| **Total injected failures** | **31** |

The authored `Counted` fixture owns an allocated payload and has a separately
counted member subobject. Every injected failure and constructor exception
returned the caught-exception status and left the output handle untouched.
Every completely constructed object was destroyed exactly once; if object
construction failed, its completed member subobject was destroyed exactly
once. Each failure was followed by a successful creation, value read and
destruction. A second destruction returned the stale-handle status without
another destructor call. Existing live peers retained their original values.

The growth cases also let a destructor call a method on a live peer. Those
calls completed, checking that the registry mutex had been released before
the generated failure cleanup invoked the foreign destructor.

Warm failure paths returned the live allocation count to its prior value.
Cold paths deliberately report their retained infrastructure separately:
some failures leave the process-lifetime registry, and an affine creation can
also leave its thread token. Those observed deltas range from zero to two
allocations. They are not reported as zero total allocation retention. The
foreign objects and member subobjects were all reclaimed. The existing
process-lifetime registry and abandoned-handle policies remain unchanged.

This run does not intercept aligned allocation overloads. The fixtures and
generated types in these observed paths used ordinary allocations; the result
does not cover arbitrary over-aligned foreign types or custom allocators.

## Argument categories, exception declarations and v1 compatibility

`categories_and_v1.json` retains eight native positive constructor cases:

- Scalar value and scalar `const_ref`, with the competing overload deleted.
- POD value and POD `const_ref`, with the competing overload deleted.
- Const-span and mutable-span rvalue arguments, with the const-lvalue span
  overload deleted.
- One scalar type whose rvalue overload can throw and whose const-reference
  overload is `noexcept`, checking the selected overload's distinct result.

Seven adversarial contracts are rejected by the native compiler with
`E_CPP_NATIVE`, and no output directory is published: two scalar category
mismatches, two POD category mismatches, one span element-type mismatch, and
false `noexcept` claims on scalar and span rvalue overloads. The accepted
reports continue to say that an exact constructor parameter signature has
not been proved. Constructibility permits ordinary C++ implicit conversions.

The v1 comparison loads the immediately preceding generator from
`e8a3b4cb6f1b2f31df73a3fdd68fc9878d809697`. No other `hepta/` compiler files
changed between that baseline and the reviewed constructor commit. The
standard-library v1 fixture produces byte-identical public C headers and
Hepta extern declarations with the old and new generators. A separately
compiled C11 client is linked and run against each generated bridge; both
pass scalar, POD, span, embedded-NUL string, default vector construction,
exception-output preservation and duplicate-destruction checks. This checks
the observed host ABI, not every compiler pair or shared-library deployment.

`native_tests.log` separately records the eight existing constructor tests
run on the exact reviewed commit: all passed, with no skips, in 20.801 s.
Those tests include a deliberately retaining foreign span constructor that
demonstrates the nonretention obligation is not proved by its JSON descriptor,
and a throwing mutable-span constructor that preserves the handle output
while retaining its already-performed buffer write. Neither observation is
misrepresented as prevention or rollback.

## Replay

Use a clean checkout of the reviewed commit, the preceding generator's Git
object, a C++20 compiler, a C compiler, and Rust 1.90.0. Boost headers are
required by the separate existing constructor test module. The scripts take
explicit paths, create temporary build directories, and refuse to overwrite
an earlier output report.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 evidence/audits/cpp_constructors/scripts/allocation_lifetime.py \
  --repo /path/to/f3bd3ff-checkout --cxx g++ \
  --rustc /path/to/rustc --output /tmp/cpp-allocation-review-new.json

PYTHONDONTWRITEBYTECODE=1 python3 evidence/audits/cpp_constructors/scripts/categories_and_v1.py \
  --repo /path/to/f3bd3ff-checkout --cxx g++ --cc gcc \
  --rustc /path/to/rustc \
  --baseline e8a3b4cb6f1b2f31df73a3fdd68fc9878d809697 \
  --output /tmp/cpp-categories-review-new.json

cd /path/to/f3bd3ff-checkout
PYTHONDONTWRITEBYTECODE=1 RUSTC=/path/to/rustc \
  python3 -m unittest tests.test_cpp_constructors -v
```

The scripts' assertion failures or native nonzero exits are failures, not
successful evidence. The JSON retains the contract, source identities,
native observations, rejected diagnostics and stated limitations. `manifest.json`
binds the archived reports, replay scripts and reviewed source-file hashes.
Parent integration and the final unified qualification remain separate from
this exact-commit audit.
