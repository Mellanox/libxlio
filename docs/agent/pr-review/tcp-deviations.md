# XLIO TCP: RFC map, accepted deviations, Linux deviations

XLIO's TCP core is lwIP-derived (`src/core/lwip/`). Use this to (a) find the governing RFC for a changed area, (b) avoid false-flagging an ACCEPTED deviation, (c) spot app-compat gaps vs Linux. A capable reviewer already knows the RFCs - the load-bearing part here is the *accepted-deviation* list (so you do not raise noise) and the exact code sites.

## RFC -> code map

- Core TCP state / sequence: RFC 793 / 1122 - `lwip/tcp.c`, `tcp_in.c`, `tcp_out.c`
- RTT/RTO estimator (Van Jacobson) + Karn's algorithm: RFC 6298 - `tcp_in.c` (`tcp_receive` SRTT/RTO block), `tcp_impl.h` (clamp / initial-RTO helpers)
- Congestion control: RFC 5681 - `lwip/cc_lwip.c` `lwip_cong_signal` (`CC_NDUPACK` = fast recovery §3.2; `CC_RTO` = loss response §3.1 (last para), cwnd -> 1 SMSS; `CC_ACK` = slow-start / congestion-avoidance)
- Appropriate Byte Counting: RFC 3465 - `tcp.h` `tcp_calc_slow_start_increment` (cap 2*SMSS)
- Initial window: RFC 3390 - `tcp.h` `tcp_calc_initial_cwnd`
- Window scaling / timestamps / PAWS: RFC 1323 (superseded by 7323) - option handling in `tcp_in.c` / `tcp_out.c`
- uTLS record / TLS 1.3 offload: RFC 8446 - `proto/tls.h` (XLIO-only)

## ACCEPTED XLIO deviations - do NOT flag as bugs

A PR that merely keeps or relies on these is fine; only flag if a change *breaks* them.

- **Initial window = RFC 3390** `min(4*MSS, max(2*MSS, 4380))`, NOT Linux's IW10 (RFC 6928). Intentional (upstream lwIP). `tcp.h:92`.
- **Initial ssthresh = infinite** (`0x7FFFFFFF`) - startup governed by cwnd, Linux-like. `tcp.h`.
- **Initial RTO = 1000 ms** (RFC 6298 §2.1, compliant); RTO clamped to `[TCP_MIN_RTO_TICKS = 3 ticks, 0x7FFFU ticks]` (`opt.h`). Tick-quantized - not an aggressive sub-second min.
- **RTT/RTO state uses legacy signed `s16_t` storage** - `tcp_clamp_rto_signed_ticks` guards the negative-wrap (see its TODO). Any RTT/RTO change must respect the `s16_t` range.
- **quickack** is a supported XLIO opt-in knob that changes delayed-ACK behavior; enabling/using it is not a bug.
- **Pluggable CC** (`TCP_CC_ALGO_MOD = 1`, default `cc_lwip`) - XLIO's default is the lwIP CC, not Linux CUBIC.

## Known Linux-kernel-TCP deviations (app-compat radar)

Applications are implicitly tuned to Linux behavior. Flag only if a PR makes XLIO diverge *further* in a way that breaks app expectations; merely `note` pre-existing ones.

- Initial window: XLIO ~RFC 3390 vs Linux IW10.
- Default CC: XLIO lwIP-CC vs Linux CUBIC; XLIO has no BBR.
- Loss recovery: classic timer + dupack; no RACK-TLP and no F-RTO (RFC 5682) by default.
- Delayed-ACK / quickack semantics differ from Linux `TCP_QUICKACK` / `tcp_delack`.
- No `tcp_slow_start_after_idle`-style cwnd-restart-after-idle knob.
- SACK (RFC 2018): not implemented (`cc.h`: `CC_SACK` is marked `/* Not yet. */`); Linux has it on by default.
