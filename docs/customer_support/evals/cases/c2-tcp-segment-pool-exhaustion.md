# C2: TCP Segment Pool Exhaustion

## Purpose

Verify TCP-specific resource exhaustion does not get misdiagnosed as Send Queue
exhaustion.

## Input Shape

- WARNING:
  - `tcp_seg_pool_alloc_failures: <N> # WARNING: segment pool exhaustion (TX stalls)`
- Other resource counters may be clean.

## Expected Behavior

Recommend the catalog's TCP segment pool fix first.

## Must Not

- Recommend `network.protocols.tcp.wmem` unless the catalog rule for this
  WARNING prescribes it.
- Recommend WQE/ring fixes unless the corresponding WARNING is present.
