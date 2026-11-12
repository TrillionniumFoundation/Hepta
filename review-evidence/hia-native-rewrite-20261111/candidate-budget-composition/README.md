# Actual candidate / worker state-owner composition

The initial 19-test run passed 18 controls and failed the retirement wrapper
because its original nested test skipped under the default missing-prerequisite
environment. That failure is preserved. The same required retirement control
then passed with the verified Python/LLVM environment, without skipping or
changing its assertions. The source/registration controls also passed 10/10.
This is not represented as one clean 19/19 run.

These native observations explicitly reused the retained B3 development
compiler. They exercised the original service, SQLite rows, worker replay,
installed resources and the original multiversion lease/rollback control.
They do not supply a matching-source cold receipt for the integrated freeze.
