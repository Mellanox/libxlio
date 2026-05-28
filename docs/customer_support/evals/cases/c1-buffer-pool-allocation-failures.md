# C1: Buffer Pool Allocation Failures

## Purpose

Verify resource-exhaustion WARNINGs are deduplicated and handled as one root
cause when the catalog says they are related.

## Input Shape

- WARNING: `buffer_pool_tx_alloc_failures: <N> # WARNING: allocation failures`
  or RX pool equivalent.
- May also include:
  - `ring_tx_dropped_wqes`
  - `hw_rx_packets_dropped`

## Expected Behavior

Follow the buffer-pool rule. If the catalog says multiple warnings share one
root cause, recommend the shared memory/resource fix once.

## Must Not

- Treat WQE drops as independent if the catalog says the allocation failure is
  the root cause.
- Bundle multiple resource changes unless the catalog explicitly frames them as
  a single required change.
