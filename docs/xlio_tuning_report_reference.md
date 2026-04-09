# XLIO Tuning Report Reference

The XLIO tuning report is a post-run diagnostic summary generated when a process
using XLIO exits. It captures system context, effective configuration, traffic
statistics, buffer pool health, and performance indicators — everything needed to
identify bottlenecks and tune XLIO for your workload.

## Generating a Report

Control report generation with these configuration knobs:

| Config Knob | Default | Description |
|---|---|---|
| `monitor.report.mode` | `auto` | `auto` — generate only when anomalies are detected; `enable` — always generate; `disable` — never generate |
| `monitor.report.file_path` | `/tmp/xlio_report_%d.txt` | Output path. `%d` is replaced with the process ID. |

In `auto` mode, the report is generated only when one of these anomalies is
detected during the process lifetime:

- Buffer pool allocation failures (`rx_rwqe`, `rx_stride`, or `tx` pools)
- Hardware RX packet drops
- TX WQE exhaustion

Other anomalies (software RX drops, retransmits, offload ratio issues) do **not**
trigger auto-generation. Set `mode: enable` for complete diagnostics.

## Report Structure

Every report contains these sections in order:

| # | Section | Contents |
|---|---|---|
| 1 | Preamble | Format version, timestamp, PID, process duration |
| 2 | System Context | XLIO version, kernel, NIC devices, hugepages |
| 3 | Active Profile | Which built-in profile is active |
| 4 | Effective Config | Non-default configuration values |
| 5 | Runtime Stats | Traffic counters, errors, ring diagnostics, buffer pools |
| 6 | Socket Summary | Socket counts, offload status, listen stats |
| 7 | Performance Indicators | Derived metrics with thresholds |

A complete report ends with:
```
# End of XLIO Tuning Report
# Report generated successfully
```

If `# Report generated successfully` is missing, one or more sections failed to
generate — look for `# ERROR:` annotations above.

## Report Detail Levels

The report has two detail levels depending on whether per-socket traffic stats
are enabled:

**Full detail** — all fields and all 21 WARNING conditions are available.
Requires `monitor.stats.fd_num` > 0.

**Fallback detail** — only ring-level traffic totals are available. The report
includes the annotation `# Per-socket traffic stats require monitor.stats.fd_num > 0`.
Only 12 of 21 WARNINGs can fire. Missing: `tx_errors`, `rx_errors`,
`sw_rx_packets_dropped`, `sw_rx_bytes_dropped`, `sw_rx_drop_rate`,
`tx_retransmit_rate`, `poll_hit_rate`, non-offloaded traffic ratio,
`listen_conn_dropped`.

To get full detail, set `monitor.stats.fd_num` to at least the number of
concurrent sockets your application uses.

If the stats pool is smaller than the total socket count, the report notes:
```
# Note: per-socket traffic stats cover X/Y sockets (increase monitor.stats.fd_num for full coverage)
```
Traffic split numbers in this case are underestimates.

## Field Reference

### Preamble

All preamble lines are `#`-prefixed comments, not `key: value` fields.

| Line | Description |
|---|---|
| `# report_format_version: 1` | Report format version. This document covers version 1. |
| `# Generated: <timestamp> \| PID: <pid> \| Duration: <duration>` | When the report was generated, which process, how long it ran. Duration is shown in human-readable form (e.g., `2m 18s`, `1h 5m 30s`, or `50ms` for very short runs). |

### System Context

| Field | Type | Description |
|---|---|---|
| `xlio_version` | string | XLIO library version |
| `command` | string | Command line of the process (truncated to 1024 chars) |
| `ofed_version` | string | MLNX_OFED driver version (omitted if unavailable) |
| `kernel` | string | Linux kernel version |
| `arch` | string | CPU architecture |
| `hostname` | string | Machine hostname |
| `cpu_count` | integer | Number of online CPU cores |
| `hugepages_<size>kB_total` | integer | Total hugepages allocated at this size |
| `hugepages_<size>kB_free` | integer | Free hugepages at this size |
| `nic_device` | string | NIC name, speed (Gbps/Mbps), and MTU |

Hugepage lines are only shown for sizes where `total > 0`. Multiple `nic_device`
lines may appear if multiple NICs are in use.

### Active Profile

| Field | Type | Description |
|---|---|---|
| `profile_spec` | string | Active built-in profile: `none`, `latency`, `ultra_latency`, `nginx`, `nginx_dpu`, or `nvme_bf3` |

### Effective Config

Shows only parameters that differ from their defaults. Format:

```
key: value
  # default: default_value | reason: <reason> | Human-Readable Title
```

The `reason` field indicates why the value differs from the default:

| Reason | Meaning |
|---|---|
| `User-configured` | You explicitly set this in your JSON config or `XLIO_INLINE_CONFIG` |
| `Profile` | Set by the active built-in profile |
| `Auto-corrected (description)` | XLIO adjusted the value due to a system constraint |

Special cases:
- `# All parameters at default values` — nothing is customized.
- `# Config registry not available` — the JSON config system is not active.
  This happens when using legacy `XLIO_*` environment variables without
  `XLIO_USE_NEW_CONFIG=1`.

### Runtime Stats — Traffic Counters

**Full detail fields** (require `monitor.stats.fd_num` > 0):

| Field | Type | Unit | Description |
|---|---|---|---|
| `total_rx_packets` | uint64 | count | Total received packets across all sockets |
| `total_tx_packets` | uint64 | count | Total transmitted packets across all sockets |
| `total_rx_bytes` | uint64 | bytes | Total received bytes |
| `total_tx_bytes` | uint64 | bytes | Total transmitted bytes |
| `rx_throughput` | string | Gbps/Mbps | Lifetime-average receive throughput |
| `tx_throughput` | string | Gbps/Mbps | Lifetime-average transmit throughput |
| `total_rx_os_packets` | uint64 | count | Packets received via kernel path (not offloaded) |
| `total_tx_os_packets` | uint64 | count | Packets sent via kernel path (not offloaded) |
| `sw_rx_packets_dropped` | uint64 | count | Packets dropped in software receive buffers |
| `sw_rx_bytes_dropped` | uint64 | bytes | Bytes dropped in software receive buffers |
| `tx_errors` | uint64 | count | Socket-level transmit errors |
| `rx_errors` | uint64 | count | Socket-level receive errors |
| `tx_retransmits` | uint64 | count | TCP retransmitted segments |
| `strq_total_strides` | uint64 | count | Total striding RQ strides consumed (only shown if > 0) |
| `tls_tx_bytes` | uint64 | bytes | TLS-encrypted bytes sent (uTLS builds only, shown if > 0) |
| `tls_rx_bytes` | uint64 | bytes | TLS-encrypted bytes received (uTLS builds only, shown if > 0) |

**Fallback detail fields** (when per-socket stats are unavailable):

| Field | Type | Unit | Description |
|---|---|---|---|
| `ring_total_rx_packets` | uint64 | count | Total RX packets across all rings |
| `ring_total_tx_packets` | uint64 | count | Total TX packets across all rings |
| `ring_total_rx_bytes` | uint64 | bytes | Total RX bytes across all rings |
| `ring_total_tx_bytes` | uint64 | bytes | Total TX bytes across all rings |
| `rx_throughput` | string | Gbps/Mbps | Lifetime-average receive throughput |
| `tx_throughput` | string | Gbps/Mbps | Lifetime-average transmit throughput |
| `ring_total_tx_retransmits` | uint64 | count | Ring-level TCP retransmit count (only shown if > 0) |

In full detail mode, `ring_total_*` fields are also shown alongside per-socket
fields when ring-level data is available.

### Runtime Stats — Ring Diagnostics

These fields are shown when the corresponding counters are non-zero:

| Field | Type | Unit | Description |
|---|---|---|---|
| `ring_tx_dropped_wqes` | uint64 | count | TX Work Queue Elements dropped (send queue overflow) |
| `ring_tx_tso_packets` | uint64 | count | Packets sent via TCP Segmentation Offload |
| `ring_tx_tso_bytes` | uint64 | bytes | Bytes sent via TSO |
| `ring_tls_rx_resyncs` | uint64 | count | TLS RX hardware-to-software fallback events (uTLS builds only) |
| `ring_tls_tx_resyncs` | uint64 | count | TLS TX hardware-to-software fallback events (uTLS builds only) |
| `ring_tls_rx_auth_fail` | uint64 | count | TLS hardware authentication failures (uTLS builds only) |

### Runtime Stats — Pool Statistics

| Field | Type | Unit | Description |
|---|---|---|---|
| `tcp_seg_pool_size` | uint64 | count | TCP segment pool capacity |
| `tcp_seg_pool_alloc_failures` | uint64 | count | TCP segment allocation failures |
| `buffer_pool_<type>_size` | uint64 | count | Buffer pool capacity |
| `buffer_pool_<type>_alloc_failures` | uint64 | count | Buffer pool allocation failures |

Buffer pool types: `rx_ptr`, `rx_rwqe`, `rx_stride`, `tx`, `zc`.
Only pools that exist in the current configuration are shown.

### Socket Summary

| Field | Type | Unit | Description |
|---|---|---|---|
| `total_sockets` | uint64 | count | Total sockets created |
| `tcp_sockets` | uint64 | count | TCP sockets |
| `udp_sockets` | uint64 | count | UDP sockets |
| `offloaded_sockets` | uint64 | count | Sockets accelerated by XLIO |
| `non_offloaded_sockets` | uint64 | count | Sockets using kernel path |

**Full detail only** (when per-socket stats are available and traffic exists):

| Field | Type | Unit | Description |
|---|---|---|---|
| `offloaded_rx_bytes` | uint64 | bytes | RX bytes through offloaded sockets |
| `offloaded_tx_bytes` | uint64 | bytes | TX bytes through offloaded sockets |
| `non_offloaded_rx_bytes` | uint64 | bytes | RX bytes through non-offloaded sockets |
| `non_offloaded_tx_bytes` | uint64 | bytes | TX bytes through non-offloaded sockets |
| `listen_conn_established` | uint64 | count | TCP connections established on listen sockets |
| `listen_conn_accepted` | uint64 | count | TCP connections accepted via `accept()` |
| `listen_conn_dropped` | uint64 | count | TCP connections dropped (listen backlog full) |

### Performance Indicators

| Field | Type | Unit | Threshold | Description |
|---|---|---|---|---|
| `poll_hit_rate` | percentage | % | < 80% | Fraction of polls that found data ready |
| `sw_rx_drop_rate` | percentage | % | > 0.01% | Software RX drop rate |
| `tx_retransmit_rate` | percentage | % | > 0.1% | TCP retransmit rate |
| `hw_rx_packets_dropped` | uint64 | count | > 0 | NIC-level RX drops (ring overflow) |

`poll_hit_rate` shows `N/A` when the application uses the event-driven API
(poll groups / XLIO Ultra API), which bypasses the poll/recv loop.
`sw_rx_drop_rate` and `tx_retransmit_rate` are full-detail only.
`hw_rx_packets_dropped` is always shown.

## WARNING Reference

Every `# WARNING:` annotation indicates an anomaly. The table below lists all
21 possible WARNINGs with their meaning, trigger condition, and recommended action.

### Resource Exhaustion

| WARNING | Trigger | Meaning | Action |
|---|---|---|---|
| `hugepage pool fully consumed` | `hugepages_<size>kB_free` = 0 | All hugepages of this size are in use. XLIO falls back to 4 KB pages, increasing TLB misses. | Allocate more hugepages at the OS level: `echo <N> > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`. Or reduce `core.resources.memory_limit` to lower XLIO's footprint. |
| `allocation failures` | `buffer_pool_<type>_alloc_failures` > 0 | Buffer pool exhausted. Affected path depends on pool type: `rx_rwqe`/`rx_stride` (receive), `rx_ptr` (scatter-gather RX), `tx` (transmit), `zc` (zero-copy). | Increase `core.resources.memory_limit`. Check hugepage availability. For RX: increase `performance.rings.rx.ring_elements_count`. For TX: increase `performance.rings.tx.ring_elements_count`. |
| `segment pool exhaustion (TX stalls)` | `tcp_seg_pool_alloc_failures` > 0 | TCP segment pool exhausted. Sends stall until segments are freed. Causes TX latency spikes. | Increase `core.resources.memory_limit`. Reduce `performance.buffers.tcp_segments.socket_batch_size` if many connections compete for segments. |
| `WQE exhaustion detected` | `ring_tx_dropped_wqes` > 0 | NIC send queue overflowed. Sends dropped at hardware level. | Increase `core.resources.memory_limit`. Increase `performance.rings.tx.ring_elements_count`. Enable TSO (`hardware_features.tcp.tso.enable: enable`) to reduce WQE consumption. |

### TX Issues

| WARNING | Trigger | Meaning | Action |
|---|---|---|---|
| `TX errors detected` | `tx_errors` > 0 | Socket-level send failures. Cross-reference with `ring_tx_dropped_wqes` (WQE exhaustion), `tcp_seg_pool_alloc_failures` (segment exhaustion), and `buffer_pool_tx_alloc_failures` (buffer exhaustion) to identify root cause. | Fix the underlying cause (see Resource Exhaustion). If no resource exhaustion, check for peer connection resets. |
| `TCP retransmits (congestion or packet loss)` | `tx_retransmits` > 0 | TCP segments retransmitted. Indicates network congestion, packet loss, or receiver-side drops. | Check receiver for `hw_rx_packets_dropped`. Verify MTU matches end-to-end. Consider `network.protocols.tcp.timestamps: enable`. |
| `high retransmit rate` | `tx_retransmit_rate` > 0.1% | Retransmit rate exceeds threshold. | Same as above. |
| `retransmits detected` | `ring_total_tx_retransmits` > 0 | Ring-level retransmits (fallback detail equivalent of `tx_retransmits`). | Same as above. |

### RX Issues

| WARNING | Trigger | Meaning | Action |
|---|---|---|---|
| `RX errors detected` | `rx_errors` > 0 | Receive errors at the socket level. Typically indicates protocol violations or corrupted packets. | Investigate network health. Check `dmesg` and NIC firmware logs. |
| `non-zero drops` (packets) | `sw_rx_packets_dropped` > 0 | Application didn't consume packets fast enough. XLIO dropped packets in software buffers. | Check if CPU-bound. Enable `performance.polling.rx_poll_on_tx_tcp: true` for bidirectional workloads. Enable LRO (`hardware_features.tcp.lro: enable`). |
| `non-zero drops` (bytes) | `sw_rx_bytes_dropped` > 0 | Same as above, byte count. | Same as above. |
| `non-zero drop rate` | `sw_rx_drop_rate` > 0.01% | Software RX drop rate exceeds threshold. | Same as above. |
| `HW drops detected` | `hw_rx_packets_dropped` > 0 | NIC dropped packets before XLIO could process them. Receive ring buffer overflowed. | Increase `performance.rings.rx.ring_elements_count`. Increase `performance.rings.rx.spare_buffers`. Increase `core.resources.memory_limit`. Enable LRO. |

### Offload Issues

| WARNING | Trigger | Meaning | Action |
|---|---|---|---|
| `<N>/<N> sockets are non-offloaded` | `non_offloaded_sockets` > 0 | Some sockets bypass XLIO and use the kernel stack. | Check `acceleration_control.default_acceleration` (should be `true`). Review `acceleration_control.rules`. |
| `<pct>% of RX bytes went through non-offloaded path` | Non-offloaded RX bytes > 50% of total | Majority of traffic bypasses XLIO. | Same as above. Check that XLIO is loaded before socket creation (`LD_PRELOAD` timing). |

### Hardware Offload Validation

| WARNING | Trigger | Meaning | Action |
|---|---|---|---|
| `TSO explicitly enabled but no TSO packets sent (payload may be below MSS threshold)` | `hardware_features.tcp.tso.enable` = `ON` and `ring_tx_tso_packets` = 0 and TX traffic exists | TSO was explicitly enabled but no packets used it. TSO only activates when payload exceeds the MSS (~1460 bytes for MTU 1500). | If message size < MSS, TSO won't help — expected behavior. If NIC doesn't support TSO, set `tso.enable: auto`. |
| `TLS RX resync (HW->SW fallback)` | `ring_tls_rx_resyncs` > 0 | TLS RX hardware offload fell back to software. Caused by out-of-order packets, retransmits, or record misalignment. | Fix underlying retransmits/drops. If persistent, disable HW TLS RX: `hardware_features.tcp.tls_offload.rx_enable: false`. |
| `TLS TX resync (HW->SW fallback)` | `ring_tls_tx_resyncs` > 0 | TLS TX hardware offload fell back to software. | Same as above for TX: `hardware_features.tcp.tls_offload.tx_enable: false`. |
| `TLS HW authentication failure` | `ring_tls_rx_auth_fail` > 0 | NIC detected TLS authentication failures (corrupted records). Data integrity issue. | Disable HW TLS RX offload. Update NIC firmware. |

TLS fields only appear in XLIO builds with uTLS support. If absent, TLS offload
is not applicable.

### Connection & Polling

| WARNING | Trigger | Meaning | Action |
|---|---|---|---|
| `connections dropped (backlog full?)` | `listen_conn_dropped` > 0 | Incoming TCP connections dropped because the listen backlog was full. | Increase the `backlog` argument to `listen()`. For nginx, set `applications.nginx.workers_num` to match CPU cores. |
| `low poll hit rate` | `poll_hit_rate` < 80% | XLIO polls frequently find no data. May indicate over-polling or bursty traffic. | For throughput workloads: reduce `performance.polling.iomux.poll_usec`. For latency workloads: low hit rate is the cost of low latency — no change needed. |

## Annotations Reference

The report uses three types of inline annotations:

### `# WARNING:` annotations

Anomalies requiring attention. See the WARNING Reference above for the
complete list of 21 possible WARNINGs.

### `# ERROR:` annotations

Report generation failures. If you see:
```
# ERROR: report generation failed: <message>
```
One or more sections failed to generate. The report may be incomplete.
Re-run the application and check for crashes during XLIO shutdown.

### `# Note:` annotations

Contextual information — not problems:

| Note | Meaning |
|---|---|
| `lifetime average, process ran < 5min` | Throughput includes startup overhead (device probing, memory registration, TCP slow-start). Steady-state throughput is likely higher. Run > 5 min for accurate benchmarks. |
| `per-socket traffic stats cover X/Y sockets (increase monitor.stats.fd_num for full coverage)` | Stats pool is smaller than total sockets. Traffic split numbers are underestimates. Increase `monitor.stats.fd_num`. |
| `0 accepted with established > 0 is expected when using event-driven API (poll groups) instead of accept()` | Application uses XLIO Ultra API / poll groups. Zero accepted connections is normal. |
| `event-driven API (poll groups) — poll counters not applicable` | Shown when `poll_hit_rate` is `N/A`. Not a problem. |
| `Per-socket traffic stats require monitor.stats.fd_num > 0` | Fallback detail mode indicator. Set `monitor.stats.fd_num` > 0 for full diagnostics. |

## Troubleshooting Quick Reference

Common symptoms mapped to the most relevant configuration knobs:

| Symptom | Config Knobs to Check |
|---|---|
| Buffer pool allocation failures | `core.resources.memory_limit`, `performance.rings.rx.ring_elements_count`, `performance.rings.tx.ring_elements_count` |
| Hardware RX drops | `performance.rings.rx.ring_elements_count`, `performance.rings.rx.spare_buffers`, `core.resources.memory_limit`, `hardware_features.tcp.lro` |
| Software RX drops | `performance.polling.rx_poll_on_tx_tcp`, `performance.override_rcvbuf_limit`, `hardware_features.tcp.lro` |
| TX WQE exhaustion | `core.resources.memory_limit`, `performance.rings.tx.ring_elements_count`, `hardware_features.tcp.tso.enable` |
| TCP retransmits | `network.protocols.tcp.congestion_control`, `network.protocols.tcp.timestamps`, peer-side configuration |
| Non-offloaded sockets | `acceleration_control.default_acceleration`, `acceleration_control.rules` |
| Low poll hit rate | `performance.polling.iomux.poll_usec`, `performance.polling.iomux.poll_os_ratio`, `profiles.spec` |
| Low throughput (no WARNINGs) | `network.protocols.ip.mtu` (jumbo frames), `hardware_features.tcp.tso.enable`, `hardware_features.tcp.lro`, `profiles.spec`, `core.resources.memory_limit` |
| TLS resyncs | Fix underlying retransmits/drops first; `hardware_features.tcp.tls_offload.rx_enable`, `hardware_features.tcp.tls_offload.tx_enable` |
| Listen connections dropped | Application listen backlog (`backlog` arg to `listen()`); `applications.nginx.workers_num` for nginx |

## Available Profiles

Profiles set many configuration values at once for common workload patterns:

| Profile | Use Case | Key Settings |
|---|---|---|
| `latency` | Trading, real-time control | Infinite polling, TSO off, TCP_NODELAY, GRO disabled |
| `ultra_latency` | Lowest possible latency, 100% CPU | Same as `latency` with more aggressive settings |
| `nginx` | HTTP proxy / load balancer | TSO on, RX poll on TX, CQ wait control, 3-tuple steering |
| `nginx_dpu` | nginx on NVIDIA DPU | Same as `nginx` with lower memory footprint |
| `nvme_bf3` | SPDK on NVIDIA DPU BF3 | TSO on, LRO on, large strides, TCP_NODELAY |

Set with `profiles.spec` (default: `none`).

## Report Limitations

- **No per-socket breakdown.** Traffic stats are aggregated across all sockets.
- **No timeline data.** Counters are cumulative over the process lifetime.
- **Lifetime-average throughput.** Includes startup overhead for short runs (< 5 min).
- **No peer-side visibility.** TX retransmits may originate from receiver-side drops.
- **No CPU utilization.** A clean report with low throughput may indicate a CPU bottleneck.
- **Counter overflow risk.** Per-socket counters use uint32. At high packet rates,
  counters may overflow before aggregation. If average packet size
  (`total_rx_bytes / total_rx_packets`) is outside 64–9000 bytes, suspect overflow.
- **No network topology.** MTU is shown for local NICs only, not for the path.
- **Partial stats coverage.** When `monitor.stats.fd_num` < total sockets,
  traffic split numbers are underestimates.
