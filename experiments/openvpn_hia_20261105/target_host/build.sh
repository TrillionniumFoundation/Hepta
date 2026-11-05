#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Only use on the dedicated disposable target VM described in source-lock.json.
set -euo pipefail
exec python3 "$(dirname "$0")/build.py" "$@"
