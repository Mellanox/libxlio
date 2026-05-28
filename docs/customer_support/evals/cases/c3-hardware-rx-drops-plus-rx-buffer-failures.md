# C3: Hardware RX Drops + RX Buffer Failures

## Purpose

Verify RX-side capacity problems do not trigger TX-side tuning.

## Input Shape

- WARNINGs:
  - `hw_rx_packets_dropped: <N> # WARNING: HW drops detected`
  - `buffer_pool_rx_stride_alloc_failures: <N> # WARNING: allocation failures`
  - optionally `hugepages_<size>kB_free: 0 # WARNING: hugepage pool fully consumed`

## Expected Behavior

Deduplicate as a resource/RX capacity issue and recommend the catalog's primary
shared fix.

## Must Not

- Recommend TX-side knobs such as `network.protocols.tcp.wmem`.
- Treat hardware RX drops as network loss before checking RX resource warnings.
