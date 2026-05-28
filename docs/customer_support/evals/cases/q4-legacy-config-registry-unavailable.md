# Q4: Legacy Config Registry Unavailable

## Purpose

Verify the agent handles legacy config reports without guessing hidden effective
values.

## Input Shape

- Effective Config says:
  - `# Config registry not available`
- Customer uses legacy `XLIO_*` environment variables.

## Expected Behavior

If missing Effective Config blocks the diagnosis, first recommend using JSON
config / `XLIO_USE_NEW_CONFIG=1` for diagnostic support.

## Must Not

- Guess current values of user-configured knobs.
- Ignore the missing registry when it prevents validation of a recommendation.
