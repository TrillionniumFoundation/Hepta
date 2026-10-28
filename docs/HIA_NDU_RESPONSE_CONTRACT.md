# One response contract for NDU transport and advisory reuse

The original recursive, finite-graph and persistent stream profiles share the
`hepta.hia.ndu.response.v1` wire format. They retain distinct source/compiler
admission requirements. `hepta.hia_ndu_response` is the common pure validator
for their bounded, linear Q32, zero-projection response profile. It has no
dependency on a compiler, runtime, transport or cache.

`NduBridge.evaluate` validates every ordinary response with that contract.
`NduSession.evaluate` inherits the same complete inner-response validation in
addition to its stream handshake, sequence, sealed image and actual process
identity checks. `NduDecisionCache` uses the identical validator for fresh and
retained replies, and binds the validator source in its implementation digest.
Choosing whether to cache advice therefore does not select a different response
acceptance contract. Caching remains opt-in and disabled by default.

## Checks

- Exact response and path field inventories, supported schema, profile and
  disposition, `DENY_ALL`, and a literal false safety-certificate field.
- Exact frozen request digest, objective, snapshot and integer generation;
  typed native build identity, without Python boolean/integer aliases.
- Distinct known evaluated, Pareto and rejected candidate identities; a complete
  disjoint evaluated/rejected partition; Pareto membership within the evaluated
  set; and selection/disposition/frontier agreement.
- One path receipt per supplied candidate, binding the original verification
  and support digests and exact bounded integer resource/risk fields.
- Bounded integer recursive values of the declared path length, nonzero digest
  shapes, and exactly zero projections for this profile.

Malformed replies raise `NduBridgeError`. A fresh malformed session reply is
terminal: the session closes the process and sealed descriptor, reaps the child,
and refuses later requests on that owner. Invalid cached bytes refuse without a
fresh native fallback. The cache owns its retained advice; a caller separately
owns and closes any underlying session.

## Evidence and scope

The pre-fix discrepancy was reproduced on source
`2f49151ab9d8812eeb02ac2056f224f140099d76` using the original finite NDU executable
at source `4b6391e116949af0c7e59776baead67271856bdb`: twelve classes of malformed
post-native replies passed the ordinary bridge and failed the cached route.
The retained reproduction includes the original executable/build identity,
source bytes, raw native process streams, and explicitly labelled reply
mutations. The original executable was not modified.

`tests/test_hia_ndu_response.py` exercises actual recursive and finite replies
through ordinary, cache-miss and cache-hit routes. It includes unique choices,
unresolved ties, abstention, malformed structures, typed identity and validator
source drift. `tests/test_hia_ndu_session.py` applies the same fault inventory to
actual c4 stream replies under sealed and rehash profiles, checking closure,
reaping and refusal to resume. These are contract tests, not performance data.

The validator checks receipt structure and binding; it does not independently
prove reported utility values or authenticate a supplied `verified` bit or
proof digest. It does not re-evaluate the native algorithm, establish global
optimality, prove foreign-code memory safety, or authorize deployment. The
compiler's resource and functional proof obligations remain independent.
Historical negative NDU experiments and their source identities remain intact;
this correction makes no incremental performance or AI-productivity claim.
