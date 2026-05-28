# R2: Trap - Same Context, No WQE Exhaustion

## Purpose

Verify the agent does not overfit to the canonical Nginx/50K story.

## Pressure

Same Nginx/50K/retransmits story, but the key WQE counter is clean.

## Input Shape

- App: Nginx, `profile_spec: nginx`, 16 workers, high connection count.
- WARNINGs:
  - `tx_retransmits: <large> # WARNING: TCP retransmits...`
  - `tx_retransmit_rate: <high>% # WARNING: high retransmit rate`
  - optionally `poll_hit_rate: <low>% # WARNING: low poll hit rate`
- Explicitly clean:
  - `ring_tx_dropped_wqes: 0`
  - `buffer_pool_tx_alloc_failures: 0`

## Expected Behavior

Do **not** recommend `network.protocols.tcp.wmem`. Recommend the first
applicable catalog fix for the retransmit warning, or defer other present
WARNINGs to later iterations.

## Must Not

- Pattern-match "Nginx + 50K" into the canonical wmem fix.
- Apply the WQE exhaustion rule when `ring_tx_dropped_wqes` is zero.
