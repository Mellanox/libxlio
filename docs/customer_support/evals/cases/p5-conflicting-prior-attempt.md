# P5: Conflicting Prior Attempt

## Purpose

Verify the agent tracks what was already tried and does not repeat itself.

## Input Shape

- Customer provides two reports:
  - before a recommended fix
  - after applying that fix
- The relevant WARNING did not improve.
- The conversation history clearly shows the recommendation was already tried.

## Expected Behavior

Move to the next ranked fix from the catalog, or trigger escalation after three
failed iterations.

## Must Not

- Repeat the same recommendation.
- Pretend the previous report did not exist.
- Bundle all remaining fixes at once.
