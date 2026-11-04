# Packetdrill test inventory and maintenance notes

## Test hierarchy

Paths below are relative to `tests/packetdrill/`:

```text
pd                          Test runner for all three network modes
pd_common.py / pd_remote.py  Execution, reporting, and SSH wire-server supervision
packetdrill.version.json     Immutable revision of the Packetdrill executable
README.md                    Preparation and instructions for each execution mode
TESTS.md                     Corpus inventory, adaptations, and future work
cases/                       Working directory for .pkt scripts and their helpers
  packetdrill/gtests/net/     Google Packetdrill: common/ helpers and tcp/ tests
  kernel/                    Linux networking selftests and defaults.sh
  multipath-tcp/gtests/net/   Generic TCP tests from the MPTCP Packetdrill fork
  nplab/gtests/net/packetdrill/tests/
    bsd/tcp/                 nplab TCP recovery, close, and listener tests
    linux/listen/            nplab Linux listener-input test
  xlio/                      XLIO-native regressions with no upstream denominator
.cache/                      Ignored, locally built Packetdrill executable and source
runs/                        Ignored logs, metadata, JSON results, and JUnit reports
```

The directories immediately below `cases/` identify the **source**, not the test
mechanism or execution mode. Nested paths preserve each source's layout. In
particular, `gtests` is an upstream Google directory name; these scripts do not
use the C++ GoogleTest framework in XLIO's separate `tests/gtest/` directory.
`bsd` and `linux` identify the original nplab test families; the adopted tests
here run against XLIO on Linux.

Every `.pkt` is independently executable. An optional sibling `<name>.yaml`
supplies `disabled` and `tempfile` metadata for that case only; no metadata file
means defaults. A sibling `<name>-xlioconf.json` configures XLIO for that case and
is loaded automatically. Source-qualified helper references, such as
`kernel/defaults.sh`, resolve from `cases/`.
The corpus has **44 tests, 16 XLIO configuration sidecars, two YAML metadata
sidecars, three shell helpers, and one auxiliary Python helper**. Filters match
paths relative to `cases/`:

```sh
tests/packetdrill/pd list
tests/packetdrill/pd list --filter '^kernel/'
tests/packetdrill/pd list --filter 'tcp/close/'
```

For actual execution, add the interface/IP/library options for the appropriate
mode in [README.md](README.md). The default selection includes all 44 tests;
`cases/xlio/lro-data-immediate-ack.yaml` disables the LRO regression, so 43
execute and one is reported as skipped. `--include-disabled` runs selected
disabled cases. Runtime-disabled cases remain included in the executable count;
adoption-table "Skipped" counts describe tests that were not imported.

## Source snapshots and counting

Initially imported unchanged from `orshemesh/pd/xlio-tests/tests/`, using that suite's
`test-adoption-report.md` dated 2026-10-01. The import preserves its already
reviewed adaptations; it does not copy the rejected upstream tests. The
following source decisions are carried forward from that report. The sendfile
fixture setup was subsequently moved into metadata-driven runner preparation;
its syscall and packet assertions retain their original behavior.

| Source | Repository and snapshot | Executable tests here |
|---|---|---:|
| Google Packetdrill | <https://github.com/google/packetdrill>, `2c4001c4d6fc04a3bbd01d4b92be62717a37648a`; source `gtests/net/tcp/` | 23 |
| Linux kernel selftests | <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git>, `cee9395acd8043be0644b25c34bfa86623f2b935`; source `tools/testing/selftests/net/packetdrill/` | 10 |
| MPTCP Packetdrill fork | <https://github.com/multipath-tcp/packetdrill>, `5c83655df26b7d4c82973cbfe69fe689b040b154`, branch `mptcp-net-next` | 3 |
| nplab Packetdrill fork | <https://github.com/nplab/packetdrill>, `c8e048bcd2a2fa850ccb27b56f6010b80f3eaf48`, branch `master` | 7 |
| XLIO-native | `xlio/lro-data-immediate-ack.pkt`, regression for #5267303 | 1 |
| **Total** | 43 upstream-derived executable cases plus one XLIO-native case | **44** |

`packetdrill.version.json` pins the tool, not all four test repositories.
Record separate source revisions when importing or updating another corpus.
The Google source/tool checkout is the pinned revision above; the other source
snapshots and branch names come from the original adoption report.

Classifications describe differences from upstream, not differences introduced
by this import. **Adopted as-is** preserves the tested behavior; a configuration
sidecar alone does not make a case modified. **Modified** changes the script's
observable expectations or scenario. **Skipped** includes unsupported tests and
cross-source duplicates. **Pending** means not yet investigated.

| Reviewed source scope | Upstream scripts | Adopted as-is | Modified | Skipped | Pending |
|---|---:|---:|---:|---:|---:|
| Google TCP tree | 162 | 4 | 19 | 139 | 0 |
| Linux Packetdrill tree | 163 | 0 | 7 | 156 | 0 |
| MPTCP fork's reviewed tree | 288 | 0 | 3 | 285 | 0 |
| nplab TCP subset | 25 | 2 | 5 | 18 | 0 |

For each row, upstream = adopted as-is + modified + skipped + pending.
Count duplicates as skipped rather than removing them from the denominator.
The 40 retained upstream scripts produce 43 executable cases: one Linux RFC 5961
script was split into four isolated scenarios. The XLIO-native test increases
only the executable count. nplab contains 330 scripts, mostly SCTP; the table
covers only its 25 TCP-related scripts.

## Retained tests and adaptations

### Google Packetdrill

All paths in this subsection start with `cases/packetdrill/gtests/net/tcp/`.

| Group | Cases | Intent and existing adaptation |
|---|---:|---|
| `blocking/` | 4 | Accept/connect/read/write. Connect uses XLIO's SYN option layout; read uses MTU-sized reads and QUICKACK; write uses 4 KB ACK steps appropriate for XLIO's RFC 3390 initial window. |
| `close/` | 3 | Local/remote close and close during SYN-SENT. The remote-FIN case omits Linux's post-flow-destruction RST expectation. |
| `shutdown/` | 4 | SHUT_RD, SHUT_WR, SHUT_RDWR and subsequent close. One case explicitly records XLIO's RST response to data after SHUT_RD; QUICKACK stabilizes immediate ACK checks. |
| `epoll/` | 1 | `epoll_in_edge`: MTU-sized traffic, QUICKACK, and XLIO's EPOLLIN-only edge mask. A final payload-free ACK keeps remote teardown from introducing an unrelated error event. |
| `sendfile/` | 1 | Five-byte file and exact five-byte wire payload. `sendfile-simple.yaml` requests `tempfile: {size: 5}`; the runner creates a private zero-filled file and substitutes `$TEMPFILE_PATH` in a temporary script copy. The case does not delete or recreate the fixture. |
| `ioctl/` | 1 | SIOCINQ/FIONREAD receive-queue accounting before/after reads and FIN; QUICKACK preserves immediate ACK timing. |
| `validate/` | 1 | Records XLIO accepting established-state data without ACK and treating the repeated ACK-bearing segment as duplicate data. |
| `syscall_bad_arg/` | 2 | Empty iovecs, ordinary sends carrying MSG_ZEROCOPY, and safe NULL-buffer TX calls. NULL/nonzero-length RX cases are omitted because the adopted suite observed SIGSEGV. |
| `fast_retransmit/` | 1 | Three-duplicate-ACK recovery, using a 4380-byte initial flight and XLIO's two-MSS fast retransmission. |
| `nagle/` | 1 | TCP_NODELAY sends the final 54-byte POST tail without waiting for an ACK. TSO is disabled for exact MSS assertions; QUICKACK and XLIO PSH placement are explicit. |
| `mss/` | 1 | Passive handshake negotiates MSS 1100, then records unsupported getsockopt(TCP_MAXSEG) returning ENOPROTOOPT. |
| `slow_start/` | 3 | ACK-per-1, ACK-per-2, ACK-per-4. Exact wire bursts replace unsupported TCP_CC_INFO assertions; initial window, byte-counting cap and PSH flags follow XLIO. |

### Linux selftests

All paths in this subsection start with `cases/kernel/`.

| Cases | Count | Intent and existing adaptation |
|---|---:|---|
| `tcp_basic_{client,server}.pkt` | 2 | Active/passive open, data and close; XLIO options, timestamps or QUICKACK as required. |
| `tcp_close_no_rst.pkt` | 1 | Duplicate consumed payload followed by close must produce FIN rather than RST; MSS 1000 and QUICKACK. |
| `tcp_disorder_fin_in_FIN_WAIT.pkt` | 1 | An older ACK on an out-of-order FIN must not prevent acknowledgement of that FIN. |
| `tcp_rcv_zero_wnd_fin.pkt` | 1 | MTU-safe receive-buffer exhaustion; records global window scale 8 and XLIO's unconsumed FIN at zero window. |
| `tcp_rfc5961_ack-out-of-window.pkt` | 1 | Challenges ACK above SND.NXT, but records silent handling below SND.UNA minus MAX.SND.WND. |
| `tcp_rfc5961_rst-syn-recv-*.pkt` | 4 | Exact, ACK-bearing, non-exact in-window, and out-of-window RSTs. Separate processes avoid timing-dependent sequence mappings from XLIO's process-global ISN progression. |

The Linux inventory contains 81 duplicates of previously classified Google
tests, 75 other skipped tests, and seven adopted upstream scripts.

### MPTCP fork

The three `cases/multipath-tcp/gtests/net/tcp/close/mptcp-like/` scripts test
ordinary TCP abortive `SO_LINGER={1,0}` close with no data, consumed data, and
unread data. They use source-qualified helpers and XLIO's SYN-ACK MSS option;
data variants enable QUICKACK. They do **not** exercise MPTCP sockets.

The 162 Google-derived TCP tests are duplicates. Five MPTCP-like Fast Open
scripts require unsupported TFO behavior; 113 MPTCP scripts require protocol
features XLIO lacks; five tool self-tests exercise the fork rather than XLIO.

### nplab fork

All paths start with `cases/nplab/gtests/net/packetdrill/tests/`.

| Group | Cases | Intent and existing adaptation |
|---|---:|---|
| `bsd/tcp/ack_processing/tcp_dup_acks.pkt` | 1 | Warm RFC 3390 cwnd before a seven-packet loss/recovery scenario. Disable TSO; use wire assertions instead of TCP_CC_INFO. The 750 ms RTO expectation depends on the microsecond estimator and 600 ms additive floor. |
| `bsd/tcp/close/close-unread-data-rst.pkt` | 1 | Close with unread receive data emits RST. Preserve the existing 210–310 ms ACK range; irrelevant BSD receive-window values were removed. |
| `bsd/tcp/listen/` and `linux/listen/` | 5 | Malformed listener inputs followed by a valid SYN. Incoming RST and SYN+RST cases retain upstream behavior. ACK/SYN+ACK cases record missing listener RSTs; the no-flags case includes XLIO's SYN-ACK MSS option. |

`tcp_partial_ack.pkt` was not adopted because upstream marks it broken without
a defensible retransmission-timing oracle. Other skipped nplab TCP cases are
duplicates, unsupported MSS queries/TUN route operations, or unsuitable ICMP/
IPv6 router-advertisement scenarios.

### XLIO-native LRO regression

`cases/xlio/lro-data-immediate-ack.pkt` checks prompt cumulative ACK of two
back-to-back 1460-byte segments. The sidecar enables hardware LRO, disables
QUICKACK and software GRO, disables blocking RX busy polling, and sets a
400 ms TCP timer. Its 60 ms packet tolerance must not be widened to hide a
delayed ACK.

This requires an LRO-capable NIC and injection within its aggregation timeout
(32 microseconds on dor01). The original report verified offload/LRO-enabled
rings and both regular and striding RQ paths with the #5267303 fix. The wire
case sends two full MSS; aggregation whose combined payload is below one MSS
was covered separately by XLIO TCP unit tests, not by this `.pkt` file.

**Known prerequisite:** the original import used `vNext` base `513d13bc`,
which lacks the #5267303 delayed-ACK fix. The unchanged test failed with an
ACK about 260 ms late during that validation. `cases/xlio/lro-data-immediate-ack.yaml` temporarily disables this case for
both CI and developer runs, which report it as skipped. Use
`--include-disabled` to exercise it explicitly. Remove `disabled: true` from its YAML sidecar
and rerun all 44 after the fix lands. Do not weaken the test or enable QUICKACK
as a workaround.

## Reviewed tests not imported

The report completed classification of the scopes listed above; "skipped"
can become future work if XLIO gains the required mechanism. Reasons include:

| Area | Missing mechanism or unsuitable oracle |
|---|---|
| SACK/FACK/DSACK, RACK, PRR, limited transmit | XLIO lacks the required negotiation, scoreboard or recovery behavior. |
| CUBIC, HyStart, cwnd moderation | Tests assert Linux congestion-control algorithms/state rather than XLIO's lwIP/Reno behavior. |
| ECN and Accurate ECN | Negotiation, ECT marking, ACE counters and required TCP_INFO fields are incomplete or absent. |
| TCP Fast Open and MPTCP | Protocol/socket support is absent; adapting these scripts would erase their purpose. |
| TCP_INQ, NOTSENT_LOWAT, TCP_CORK, normal-socket MSG_MORE/MSG_EOR | Required APIs or skb/queue semantics are unsupported. |
| TCP MD5, urgent data/splice | Authentication, kernel inspection, OOB handling or splice interception is unavailable. |
| TX timestamping and Linux zerocopy completions | MSG_ERRQUEUE and the required ancillary/completion semantics are not implemented; XLIO's zerocopy interface differs. |
| PMTU probing, advmss, qdisc/pacing, GRO super-packets | Depend on TUN, kernel routing/ethtool controls or introspection rather than this physical-link harness. |
| Extended TCP_INFO/TCP_CC_INFO and PAWS | Tests require unpopulated counters, algorithm-specific introspection or complete timestamp validation. |
| Syncookies and kernel listener/resource behavior | Linux-only mechanisms not provided by XLIO. |
| Cross-repository duplicates | Existing source-qualified cases already cover the behavior; do not import them again to inflate coverage. |

Other sources already considered: `aschils/packetdrill_mptcp` is an old fork
superseded by `multipath-tcp/packetdrill`; `dcaratti/packetdrill` is Google-derived;
Android's networking tests are a QEMU/UML Python harness, not another substantial
Packetdrill corpus.

## XLIO/Linux differences and future work

These are the compatibility findings recorded by the adopted tests/report,
not a claim that passing this adapted suite proves Linux equivalence. Recheck
the implementation and original upstream expectations when addressing a row.
Paths in this table are relative to `cases/`.

| Test or group | Linux kernel behavior | Current XLIO behavior | Potential XLIO compatibility work |
|---|---|---|---|
| `packetdrill/gtests/net/tcp/*` outbound SYN/SYN-ACK expectations | Advertises SACK when enabled and emits the corresponding padded TCP option layout. | Does not advertise or implement SACK; adopted tests remove outbound `sackOK`. | Implement SACK option negotiation, scoreboard processing, and SACK-based recovery before restoring the upstream expectations. |
| `packetdrill/gtests/net/tcp/blocking/blocking-write.pkt` and `packetdrill/gtests/net/tcp/slow_start/slow-start-ack-per-*pkt` | Uses an IW10 initial congestion window, so upstream tests begin with ten MSS in flight. | Uses the RFC 3390 initial window: 4 MSS for MSS 1000 and 3 MSS for MSS 1460. Adopted tests use smaller initial flights and ACK steps. | Adopt Linux/RFC 6928 IW10 if Linux wire compatibility is desired. The existing XLIO behavior remains standards-based. |
| `packetdrill/gtests/net/tcp/close/close-remote-fin-then-close.pkt` | After the socket record is gone, a later segment for the closed port causes the kernel to emit RST. | After XLIO destroys the offloaded flow, the later segment receives no RST from XLIO. | Add closed-port response handling or a safe handoff to the kernel so stray post-close segments receive Linux-compatible RSTs. |
| `packetdrill/gtests/net/tcp/shutdown/shutdown-rd-wr-close.pkt` | Linux retains its historical post-`SHUT_RD` quirk: incoming data is ACKed, queued, and remains readable. | XLIO rejects incoming data after `SHUT_RD` with RST. | Emulate Linux's post-`SHUT_RD` receive behavior if application compatibility requires it. |
| `packetdrill/gtests/net/tcp/epoll/epoll_in_edge.pkt` | A new EPOLLIN edge requeues the fd; `epoll_wait()` then reports the complete current mask, including EPOLLOUT while the socket remains writable. | Returns only the newly triggered EPOLLIN bit after the initial EPOLLOUT edge was consumed. | When an edge requeues an fd, calculate and return the complete current readiness mask to match Linux epoll semantics. |
| `packetdrill/gtests/net/tcp/validate/validate-established-no-flags.pkt` | Drops a data segment without ACK in ESTABLISHED state, leaving the receive queue empty. | Accepts and queues the 1000-byte payload even though the ACK flag is absent. | Enforce established-state ACK validation and discard payload from segments without ACK before receive-queue insertion. |
| `packetdrill/gtests/net/tcp/syscall_bad_arg/syscall-invalid-buf-ptr.pkt` | `write`, `send`, `sendto`, `read`, `recv`, and `recvfrom` return `-1/EFAULT` for a NULL buffer with nonzero length. | TX calls skip the NULL iovec and return zero. RX calls reach `memcpy()` with a NULL destination and crash with SIGSEGV. | Validate nonzero-length TX and RX buffer pointers at syscall entry and return `EFAULT` before queueing or copying. |
| `packetdrill/gtests/net/tcp/fast_retransmit/fr-4pkt.pkt` | After three duplicate ACKs, retransmits only the first inferred-lost MSS. | Fast retransmit occurs, but XLIO retransmits the first two MSS (2920 bytes). | Limit the initial fast retransmission to one lost MSS to avoid unnecessary duplicate data and match Linux behavior. |
| `packetdrill/gtests/net/tcp/nagle/https_client.pkt` and `packetdrill/gtests/net/tcp/slow_start/slow-start-ack-per-*pkt` | Marks intermediate cwnd-limited/TCP_NODELAY bursts with PSH as well as the final write tail. | Sends intermediate bursts without PSH and reserves PSH for the final burst completing the application write. | Align PSH placement with Linux when segmenting a single application write if exact wire compatibility is required. |
| `packetdrill/gtests/net/tcp/mss/mss-getsockopt-tcp_maxseg-server.pkt` | `getsockopt(TCP_MAXSEG)` returns the negotiated peer MSS, 1100 in this test. | Returns `-1/ENOPROTOOPT` and leaves the output zero even though the TCP PCB stores the negotiated MSS. | Implement the offloaded `getsockopt(TCP_MAXSEG)` case by returning the PCB's negotiated MSS. |
| `packetdrill/gtests/net/tcp/slow_start/slow-start-ack-per-*pkt` inline cwnd checks | Packetdrill can query `TCP_INFO` and `TCP_CC_INFO`, then evaluate `tcpi_snd_cwnd` assertions. | XLIO exposes basic cwnd through `TCP_INFO` but rejects `TCP_CC_INFO` with `ENOPROTOOPT`, causing Packetdrill's evaluator to abort. | Implement compatible `TCP_CC_INFO`, or allow Packetdrill-style basic TCP_INFO introspection without requiring algorithm-specific CC info. |
| `kernel/tcp_rcv_zero_wnd_fin.pkt` window scaling | Selects window scale 0 for a socket with a 4000-byte receive buffer. | Advertises window scale 8, derived from global stack initialization, despite the small per-socket buffer. | Select or constrain window scaling using the effective per-socket receive-buffer size to match Linux behavior. |
| `kernel/tcp_rcv_zero_wnd_fin.pkt` FIN handling | Accepts an in-sequence FIN while the receive window is zero and advances the ACK from 4001 to 4002, preventing a FIN/ACK loop. | Leaves `rcv_nxt` at 4001 and responds `ACK 4001, win 0`, so the FIN is not consumed. | Accept an in-sequence FIN at zero receive window and advance the ACK as Linux does. |
| `kernel/tcp_rfc5961_ack-out-of-window.pkt` | Sends a challenge ACK for ACK values above SND.NXT and below SND.UNA minus MAX.SND.WND. | Challenges the upper-edge violation but silently ignores the lower-edge violation. | Implement the RFC 5961 lower-bound ACK-window check and send the required challenge ACK. |
| `kernel/tcp_rfc5961_rst-syn-recv-*.pkt` | In SYN-RECEIVED, accepts an exact RST, challenges a non-exact in-window RST, and silently ignores an out-of-window RST while preserving the request. | Removes the request for exact, non-exact, ACK-bearing, and out-of-window RSTs; no challenge ACK is sent. A later ACK to the exactly reset request also receives no closed-endpoint RST. | Validate RST sequence numbers before deleting SYN-RECEIVED requests; challenge non-exact in-window RSTs, ignore out-of-window RSTs, and provide Linux-compatible closed-endpoint responses. |
| `kernel/tcp_rfc5961_rst-syn-recv.pkt` upstream combined test: XLIO initial sequence generation | Uses per-connection ISNs designed to be unpredictable and robust across repeated four-tuples. | `tcp_next_iss()` starts from a process-global static value and increments it by `tcp_ticks`, producing closely spaced, timing-dependent ISNs. | Implement RFC 6528-style keyed per-connection ISN generation instead of the static `tcp_ticks` progression. |
| `nplab/gtests/net/packetdrill/tests/bsd/tcp/listen/listen-incoming-{ack,syn-ack}.pkt` | A bare ACK or SYN+ACK targeting a listening socket receives a bare RST; the listener remains usable. | Sends no RST, although the listener remains usable for the following valid SYN. The listener path calls `tcp_rst()` with a NULL PCB, and `tcp_rst()` returns without transmitting. | Construct and transmit the required listener-side bare RST even when no connection PCB exists. |
| `nplab/gtests/net/packetdrill/tests/bsd/tcp/ack_processing/tcp_dup_acks.pkt` | NewReno retransmits the next unacknowledged segment immediately on a partial ACK during fast recovery and avoids retransmitting data already cumulatively accounted for. | Three duplicate ACKs trigger fast retransmit, but the following partial ACK waits about 750 ms for RTO with the microsecond estimator and default 600 ms additive floor. After the next cumulative ACK, XLIO retransmits every remaining outstanding MSS, including segments the scripted receiver had already received. | Implement NewReno partial-ACK processing so recovery remains active, retransmits the next inferred loss immediately, and does not retransmit the entire remaining flight. |


## Rules for future additions and updates

1. Record the repository, immutable revision, upstream script and dependencies.
   Keep the source prefix; put XLIO-native coverage under `cases/xlio/`.
2. Inventory and classify the source group before importing more scripts.
   Keep duplicates in the skipped count and keep pending work visible.
3. Preserve the behavior being tested. Explain changes to syscalls, packets,
   timing or assertions before making them. Existing outbound SACK removal is
   documented; injected peer `sackOK` must not be removed incidentally.
4. Use a sibling sidecar for case-specific timestamps, QUICKACK, TSO, LRO or
   polling requirements. Shared settings belong in the runner. Audit helper
   commands and extend sysctl/fixture cleanup when a new test touches state
   beyond the current helpers.
5. Add the script, sidecar and any helper/fixture to `tests/Makefile.am` so a
   source tarball runs the same suite as a checkout. Preserve license notices.
6. Run the narrow case first, then the complete suite. Confirm offload for the
   **test connection**, including passive flows with local port 8080 and an
   ephemeral peer port; control-port 8081 offload alone is insufficient.
7. Diagnose failures before adapting: separate relocation/configuration issues,
   missing APIs, semantic differences, test defects and timing flakes. Do not
   widen the global tolerance or remove assertions to make a run green.
8. When XLIO fixes a documented difference, restore the upstream expectation,
   update the classification/backlog, and rerun the individual and full suites.
   Keep source counts and executable counts separate when splitting scenarios.

Temporary enable/disable decisions belong in the affected test's same-stem
`.yaml` sidecar, with a reason and issue number in a `#` comment. Use
`--include-disabled` to validate a fix and remove `disabled: true` after the fix
lands. Metadata applies to one test; unknown top-level or nested attributes are
errors. Include new metadata sidecars in `tests/Makefile.am`.

The original report noted one unexplained `blocking-read` timeout before later
paired reruns and a successful complete suite. Treat a recurrence as a failure
to investigate, not permission to silently retry or weaken its oracle. The
nplab partial-ACK RTO expectation is estimator/configuration dependent and
should be revisited when that implementation changes.

