"""Select existing qualified tools without changing shared installations."""
import os
import sys

clang = "/workspace/scratch/8ca82272aad7/clang20/usr/lib/llvm-20/bin"
rust = "/tmp/pq-r3-rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin"
deps = "/workspace/scratch/8ca82272aad7/python-deps"
os.environ.update(
    PYTHONPATH=deps + (":" + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else ""),
    PYTHONDONTWRITEBYTECODE="1",
    CLANG=clang + "/clang",
    CLANGXX=clang + "/clang++",
    HEPTA_CLANG=clang + "/clang",
    HEPTA_LLD=clang + "/ld.lld",
    RUSTC=rust + "/rustc",
    CARGO=rust + "/cargo",
    CARGO_HOME="/tmp/pq-r3-cargo",
    CARGO_TARGET_DIR="/tmp/hepta-seven-track-29cf51-target",
    CARGO_PROFILE_DEV_DEBUG="0",
    CARGO_PROFILE_TEST_DEBUG="0",
    CARGO_INCREMENTAL="0",
    CARGO_BUILD_JOBS="2",
    PATH=clang + ":" + rust + ":" + os.environ["PATH"],
)
os.execvp(sys.argv[1], sys.argv[1:])
