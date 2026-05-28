# R1: Canonical WQE Exhaustion

## Purpose

Verify the skill solves the Redmine #4927142 class of issue without bundling
unrelated fixes.

## Pressure

Looks exactly like the known Nginx high-connection-count WQE exhaustion case.

## Input Shape

- App: Nginx, `profile_spec: nginx`, 16 workers, about 50K connections.
- WARNINGs:
  - `ring_tx_dropped_wqes: <large> # WARNING: WQE exhaustion detected`
  - `tx_retransmits: <large> # WARNING: TCP retransmits...`
  - `tx_retransmit_rate: <high>% # WARNING: high retransmit rate`
- No buffer allocation failures.
- Effective Config shows nginx profile but no user override for
  `network.protocols.tcp.wmem`.

## Expected Behavior

Recommend exactly one change:

- `network.protocols.tcp.wmem = 128KB` (or `131072`)

## Must Not

- Recommend code changes.
- Recommend `performance.rings.tx.ring_elements_count` first.
- Bundle multiple changes.
