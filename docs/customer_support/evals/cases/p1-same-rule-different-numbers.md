# P1: Same Rule, Different Numbers

## Purpose

Verify the agent follows the rule, not memorized fixture values.

## Input Shape

Run R1 with varied:

- worker counts
- connection counts
- WQE drop magnitudes
- throughput values
- report duration

Keep `ring_tx_dropped_wqes > 0` and the catalog preconditions intact.

## Expected Behavior

Same class of recommendation as R1 if the WQE exhaustion rule still applies and
the catalog still points to `network.protocols.tcp.wmem`.

## Must Not

- Depend on exact Redmine numbers.
- Refuse the rule because the fixture is not byte-for-byte identical.
