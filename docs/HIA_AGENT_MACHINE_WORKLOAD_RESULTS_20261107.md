# Native compiler workload and first-use follow-up — 2026-11-07

The measured workload now includes the actual checked-in Selfhost-Core compiler
compiling its own source. It qualifies the existing compact-immediate and
scratch-register choices without changing the backend or adding an ISA feature.
The public first-use example generator provides a portable synthetic fixture.
The original task file is already committed in c992d5a; a sparse local checkout
can omit its materialization. The generator does not replace that historical
task or establish an unseen maintenance request.

## Original v3 compiler workload

Run with the qualification Python environment, Linux x86-64, and GNU ld:

```sh
python -B tools/qualify_hia_selfhost_machine_plans.py run \
  --output /absolute/fresh-selfhost-plan-campaign --repetitions 7
python -B tools/qualify_hia_selfhost_machine_plans.py verify \
  --output /absolute/fresh-selfhost-plan-campaign
```

The source, Core, candidate plans, native images, linker commands and original
child inputs/outputs are retained. Each child loads an exact image in a bounded,
stdlib-only process. Candidate plans use the identical verified Core and ABI.
All arms compile the compiler and the byte-hash example seven times, with
rotated and alternating order. The observer retains every sample; no best-sample
selection is used.

| Arm | Text bytes | ELF object bytes | Shared image bytes | Median compile-self ms | Median compile-example ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| canonical | 472,815 | 492,648 | 486,528 | 1204.618 | 5.739 |
| compact_immediates | 463,555 | 483,392 | 478,336 | 1234.537 | 5.962 |
| compact_swapped_scratch | 463,555 | 483,392 | 478,336 | 1225.742 | 6.168 |

Both compact choices reduce the shared image by 8,192 bytes (1.68%). Both were
slower than the default on the median compile-self and example timings in this
run. These are finite observations in a shared development environment, with
seven samples per workload and arm. They do not demonstrate a stable speedup,
and the script does not automatically adopt a plan.

All **81 native invocations passed**:

- 42 real compilations: identical generated image lengths and complete output
  buffers across three arms, two source files and seven repetitions.
- 18 invalid-source calls: unknown opcode, missing end, duplicate SSA, wrong edge
  type, mutable alias and u32 overflow are rejected identically by all arms.
- Six short-capacity calls preserve rejection and untouched output for short
  output or workspace buffers.
- 15 executions of the generated example image match an independent Python
  byte-hash oracle, including empty input and all byte values.

Four invalid machine plans were separately rejected: stale Core identity,
forbidden value register, resource assigned to a scalar register, and aliased
scratch registers. This finite compiler/output oracle is independent of the
machine-plan encoding check; it is not a general proof of backend refinement.

The campaign wall interval was 37.146 seconds, with 8.676
seconds of parent CPU and 28.430 seconds of child CPU. It includes setup, every
build, rejected plan attempt, child launch and native check. Nested phase
intervals are retained separately and are not added to this enclosing interval.
The final inventory serialization is excluded. No model ran in this campaign;
provider usage and money remain unknown, so this is not complete Agent cost.

The initial r1 run failed in the new reporter's handling of the default plan
(`TypeError: 'NoneType' object is not subscriptable`) after its canonical build.
It did not publish a pass. Its original log and report remain retained. The
report-only fix is in this revision; r2 passed and its sealed inventory verified.
The two earlier test attempts failed because system Python and the primary
runtime lacked `jsonschema`; the existing qualification venv passed all 60
Agent/provider/NDU tests. These environment failures are not model failures.

## Exact original evidence

The following paths are observations from this run, not portable prerequisites:

- `/workspace/scratch/faa85a766e53/selfhost-machine-plans-r1/` — original failed attempt.
- `/workspace/scratch/faa85a766e53/selfhost-machine-plans-r2/` — original successful attempt and sealed inventory.
- `/workspace/scratch/faa85a766e53/agent-ndu-baseline-tests.log` and
  `agent-ndu-baseline-primary-tests.log` — missing-dependency failures.
- `/workspace/scratch/faa85a766e53/agent-ndu-baseline-venv-tests.log` — 60 passing tests.

Successful `RESULT.json` SHA-256: `ffc978a5fd69d9a6474ee3eb82d00fb861e7bb55a942df3abe8642ac5bb5bc19`.
Successful `SEALED.json` SHA-256: `47108b9fb6fb135205c3ca032041f13ebfbb7a4a255db50ab86192430ec7d5cc`.

The result binds the complete seed package, observer, plan validator and exact
compiler sources. A source change requires a new run. The inventory detects
changed retained bytes; it cannot establish model authorship or historical
provider billing.

## Agent and NDU gate remains open

The previously recorded first-use r3 task must remain in the acceptance report:
`/workspace/scratch/6b47d1317a68/first-use-novice-r3/JUDGEMENT.json` records native
task success, 42 events, no rejected/failed invocations, 256 oracle cases and a
candidate image reduction from 17,816 to 13,720 bytes. Its `p1_acceptance` is
still `HOLD`: original model interaction, fresh-session/previous-exposure
attestations, formal MCP discovery, tokens and money are absent. This follow-up
does not relabel that result or count a scripted solve as another Agent task.

The newly generated public task is an explicit synthetic example, not an unseen
maintenance demand. Its generation and broker preparation were executed
successfully. A new real study still needs an independently chosen maintenance
request and original provider evidence. Existing provider probes timed out after
45 seconds with no output; the model catalog alone does not prove a runnable
entitlement. No new successful provider run is claimed here.

The two earlier same-budget mechanism campaigns had Native NDU savings against
the strongest observed control of -111,832,528 ns and +91,885,430 ns: the sign
reversed. They also lacked actual model usage and complete economic cost. See
[the original macro results](HIA_AGENT_MACRO_CAMPAIGN_RESULTS_20261107.md).
No model-controlled Fixed/Greedy/strong Ordinary/Native NDU value conclusion is
upgraded by this compiler measurement.

No new register class, instruction or target was added. The compiler workload
is now measured, but this run did not collect a function-level dynamic hotspot
profile. Further machine expansion needs that evidence and its own preservation
and full-cost measurements.
