{
  "schema": "hia.cli-ci-independent-static-review.v1",
  "reviewer": "audit_runtime",
  "status": "STATIC_HARNESS_LIFECYCLE_GAP_FOUND",
  "inputs": [
    {
      "git_blob": "d489b76545fd21437ce450ff0ef06a5b367d1dd6",
      "bytes": 25351,
      "sha256": "d0cd7f824b2c5736c3833c8cfc82b5a3e025f1ac36f2855dac52a0af1730741f"
    },
    {
      "git_blob": "f70171934d89d79b697ba5310e7819284a918d2d",
      "bytes": 15252,
      "sha256": "6c09835a48dc7212612c77fca333c985f300454822257b79a8a6de75cb49a443"
    }
  ],
  "execution": {
    "ast": 0,
    "vm": 0,
    "native": 0,
    "h_requests": 0
  },
  "scope": "Read-only review of new CI reconstruction driver and actual seven-image CLI ELF oracle harness; not a review of the entire executor or business owner.",
  "passed_reviewed_points": [
    "Every completed equivalence case compares the full tuple (exit status, complete stdout bytes, complete stderr bytes); no payload masks.",
    "Valid-file handoffs are explicitly OPEN exit 126, are counted separately, and are not declared business equivalence.",
    "Driver requires 193 actual cases, 176 exact equivalence cases, 17 open handoffs, 193 native child invocations and 176 reference invocations after fresh execution; old ROG counts are not claimed without new tests.",
    "CPython version is exact 3.12.14. Bundle/source/image hashes are read and source/image pins are rechecked at completion; driver binds retained B3 and produced-image receipts.",
    "Portable export inspects fixture files using lstat, records symlink target and special-file type, and stores regular bytes using lossless CAS. Only the portable export is passed to common.finish."
  ],
  "findings": [
    {
      "id": "CLI-CI-LIFETIME-01",
      "severity": "must-fix-harness-cleanup",
      "location": "test_cli_entry_ci_r1.py invoke() and external common.run timeout",
      "evidence": "Each reference/native Popen uses start_new_session=True. The harness has a 30 second local polling timeout but no parent-death binding or inherited hard CPU bound established by child_limits(). The common runner's 300 second timeout kills the harness process group, which is distinct from the child session. A child alive at that outer kill can survive without the harness polling timeout.",
      "consequence": "A failed/timed-out test harness can leave its child executing; source does not establish full fresh-child cleanup under the outer hard timeout.",
      "suggestion": "Bind each child to the actual harness parent before exec, checking the parent-PID race; retain per-call timeout and wait4 receipts. Do not broaden common group killing beyond task-owned child identity."
    },
    {
      "id": "CLI-CI-LIFETIME-02",
      "severity": "must-fix-harness-cleanup",
      "location": "test_cli_entry_ci_r1.py invoke() PTY setup through wait4",
      "evidence": "The Popen/select/read/wait4 region has no enclosing finally that terminates and reaps its child and closes both PTY descriptors. Popen or a non-EIO read/select/wait error exits before the normal master close and before a process receipt is written.",
      "consequence": "Exceptional instrumentation paths can leave a child/PTY or lose the partial per-process evidence.",
      "suggestion": "Add task-owned group termination and exact-child reap in finally, close master/slave on every path, and preserve partial stdout/stderr plus setup/error metadata; cleanup errors must not erase the original exception."
    }
  ],
  "limits": [
    "Both findings are static control-flow findings in NEW harness code; no concrete native CLI product misbehavior is asserted.",
    "The fixed executor, all imported component test bodies, and whole namespace/AgentStore implementation were not re-audited.",
    "An actual current CI run must keep its source frozen; fixes belong to a new revision with new raw output.",
    "Source/manifest headers here are private pipeline provenance, not a public authentication proof."
  ]
}
