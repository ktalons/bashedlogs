# ******************************************************************************
# *Title: Test Helper*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Shared bats setup: resolves the binary under test and fixtures.*
# ******************************************************************************

# BASHEDLOGS_UNDER_TEST lets CI point the same suite at dist/bashedlogs.
REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
BL="${BASHEDLOGS_UNDER_TEST:-$REPO_ROOT/bin/bashedlogs}"
FIXTURES="$REPO_ROOT/tests/fixtures"

# Fail fast with a clear message when the runtime deps for tests are missing.
setup() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "tests require jq" >&2
    return 1
  fi
  if [ ! -x "$BL" ]; then
    echo "tool under test not executable: $BL" >&2
    return 1
  fi
}
