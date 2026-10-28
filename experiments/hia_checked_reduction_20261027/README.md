# Frozen checked-reduction mechanism experiment

Commit the complete source and `protocol.json` before execution. Exactly two
attempts use the same 18-case corpus, 31 paired samples and 50,000 repetitions
per complete corpus and backend. Each attempt executes 55,800,000 timed native
calls and 36 untimed case checks. All outcomes remain retained. There are no
adaptive repeats, trimmed samples or post-measurement threshold changes.

This is a synthetic arithmetic mechanism experiment. The loop implements a
checked unsigned repeated addition and the candidate its checked product. It
is not an unchanged external application or an industrial hot-function study.
An accepted mechanism gain cannot close the full P4 acceptance obligation.
The cases include zero and small trip counts as well as 256, 1,024 and 4,096;
six separately retained negative cases exercise overflow and preceding casts.

Both programs use the same native compiler and flags. The existing policy
requires different native artifacts, per-backend relative MAD at most 5%, at
least 2% relative saving, paired saving above three MADs and repayment of the
actual paid search plus decision reserve at a declared 100-million-call
horizon. Wall time remains the objective; process CPU observations are
informational. The 60-second search admission ceiling, 2-second decision
reserve, resource limits and 120-second cooperative deadline remain unchanged.
The 50,000 repetitions were selected before timing to increase observation
duration while remaining below the instrument's 100-million-call bound. No
host exclusivity or production workload distribution is assumed.

The actual measured baseline library, candidate library and C driver are
retained in a new per-attempt directory. Their bytes are checked before and
after execution and rehashed by the experiment coordinator. Full Core and
LLVM inputs, all samples, evaluator requests/replies, refused candidates,
subprocess results and complete CLI costs are also preserved. The experiment
grants no activation or release authority.

```sh
python experiments/hia_checked_reduction_20261027/run_frozen.py \
  --clang /absolute/path/to/clang \
  --bridge /absolute/path/to/hia-ndu-bridge \
  --bridge-sha256 ACTUAL_PINNED_BINARY_SHA256 \
  --output-directory /absolute/path/to/new-output
```

The shared runner reads this directory's exact protocol. The older three-run
fill/swap protocol and all of its negative results remain unchanged. Finish
other owned tests, compiler jobs and model inference before this experiment.
Compiler/evaluator builds, engineering, human work, energy and maintenance are
not measured by these CLI search costs and must not be reported as zero.
