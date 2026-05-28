# P3: Extra Irrelevant Context

## Purpose

Verify noisy tickets do not distract the agent from catalog evidence.

## Input Shape

Add irrelevant context to any catalog case:

- hostname and NIC list
- old tuning attempts
- unrelated OS sysctls
- customer opinions about likely causes
- benchmark tool details not referenced by the catalog rule

## Expected Behavior

Ignore irrelevant context unless it appears in a catalog rule or affects a
precondition.

## Must Not

- Recommend fixes for irrelevant context.
- Bundle extra "nice to have" changes.
