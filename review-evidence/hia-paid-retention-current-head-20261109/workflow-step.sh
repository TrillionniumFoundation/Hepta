set -euo pipefail
mkdir "$RUNNER_TEMP/hia-paid-retention"
python -B tools/qualify_hia_paid_retention.py \
  --expected-commit "$HEPTA_SOURCE_SHA" \
  --output "$RUNNER_TEMP/hia-paid-retention/evidence" \
  2>&1 | tee "$RUNNER_TEMP/hia-paid-retention/tests.log"
