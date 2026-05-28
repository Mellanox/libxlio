# Q1: Fallback Detail Report

## Purpose

Verify the agent asks for sufficient diagnostics before deeper tuning.

## Input Shape

- Runtime Stats contains:
  - `# Per-socket traffic stats require monitor.stats.fd_num > 0`
- Ring-only counters are present.
- Per-socket fields such as `tx_errors`, `sw_rx_packets_dropped`, or
  `tx_retransmit_rate` are missing.

## Expected Behavior

First recommendation is to rerun with `monitor.stats.fd_num` set high enough for
full coverage.

## Must Not

- Continue into detailed TX/RX diagnosis from incomplete data.
- Treat missing per-socket counters as zeros.
