# HIA P2/P7: native evaluator startup isolation (2026-10-26)

Status: exact-source candidate, not whole-compiler or whole-sandbox qualification.

## Reproduced security boundary

The existing HIA native scalar differential launches a Python -I child and installs seccomp inside its worker before loading an untrusted shared object. Python -I still imports system site startup hooks; -I alone does not disable sitecustomize. Additionally, the child inherited the parent environment. Linux ELF loader variables LD_PRELOAD and LD_AUDIT can run DSO constructors before Python and seccomp execute.

A real local Clang-compiled LD_PRELOAD constructor created a controlled file marker even under python -I -S with inherited LD_PRELOAD. Running with an explicitly clean environment prevented that marker from being created. This is an independent loader control, not evidence that the full HIA compiler was exercised.

## Exact production code change

The original hepta.hia_native_differential._observe_native child adds -S to the existing -I Python flags and supplies an explicit environment limited to LC_ALL=C, LANG=C and TZ=UTC. These changes block ambient Python site hooks and ELF loader injection before the seccomp installation. Existing sealed memfd publication, post-fork seccomp, exact ABI, SIGABRT qualification, resource limits, process cleanup and native observation remain the same. Unsupported dynamic loader setups are refused rather than inheriting user loader search paths.

## Acceptance commands on the exact candidate

    python -m unittest tests.test_hia_native_startup_isolation -v
    python -m unittest tests.test_hia_native_seccomp tests.test_hia_native_signal_guard tests.test_hia_native_child_protocol tests.test_hia_native_side_effects -v
    python -m unittest tests.test_hia_native_differential -v

The new regressions compile actual Clang DSO controls and use the original sealed memfd native observer. One test injects LD_PRELOAD and a marker path into the parent and rejects any marker created by the native child. Another checks that original Worker code starts without site/sitecustomize or extra environment keys and still accepts a real return and a defined SIGABRT. Exact-head full-integration tests are not claimed without execution.

This is a narrow startup-bypass fix, not proof of a complete hostile-code sandbox. Full P0-P7 language/ownership/formal source-to-LLVM, C/C++ L2/L3, GPU, real-model A/B, sustained p99 and physical hardware blockers remain open.

whole_project_blockers_closed=false.
