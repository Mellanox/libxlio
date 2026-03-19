# XLIO Configuration Reference

This file documents all 125 XLIO runtime configuration parameters with their types, defaults, environment variables, and constraints.

> **Auto-generated** from the JSON schema by `generate_docs.py`. Do not edit manually.

## Table of Contents

- **[ACCELERATION_CONTROL](#acceleration_control)**
  - [`acceleration_control.app_id`](#acceleration_controlapp_id) — Application ID
  - [`acceleration_control.default_acceleration`](#acceleration_controldefault_acceleration) — Enable acceleration by default for all sockets
  - [`acceleration_control.rules`](#acceleration_controlrules) — Acceleration control rules
- **[APPLICATIONS](#applications)**
  - [`applications.nginx.distribute_cq`](#applicationsnginxdistribute_cq) — Distribute completion queue interrupts across workers
  - [`applications.nginx.src_port_stride`](#applicationsnginxsrc_port_stride) — Source port stride
  - [`applications.nginx.udp_pool_size`](#applicationsnginxudp_pool_size) — UDP socket pool size
  - [`applications.nginx.udp_socket_pool_reuse`](#applicationsnginxudp_socket_pool_reuse) — RX buffer reclaim threshold for pooled sockets
  - [`applications.nginx.workers_num`](#applicationsnginxworkers_num) — Number of Nginx workers
- **[CORE](#core)**
  - [`core.daemon.dir`](#coredaemondir) — Daemon working directory
  - [`core.daemon.enable`](#coredaemonenable) — Enable XLIO daemon
  - [`core.exception_handling.mode`](#coreexception_handlingmode) — Exception handling mode
  - [`core.quick_init`](#corequick_init) — Quick initialization
  - [`core.resources.external_memory_limit`](#coreresourcesexternal_memory_limit) — External memory limit (bytes)
  - [`core.resources.heap_metadata_block_size`](#coreresourcesheap_metadata_block_size) — Heap metadata block size
  - [`core.resources.hugepages.enable`](#coreresourceshugepagesenable) — Enable hugepages
  - [`core.resources.hugepages.size`](#coreresourceshugepagessize) — Hugepage size (bytes)
  - [`core.resources.memory_limit`](#coreresourcesmemory_limit) — Memory limit (bytes)
  - [`core.signals.sigint.exit`](#coresignalssigintexit) — Exit on SIGINT
  - [`core.signals.sigsegv.backtrace`](#coresignalssigsegvbacktrace) — Print backtrace on SIGSEGV
  - [`core.syscall.allow_privileged_sockopt`](#coresyscallallow_privileged_sockopt) — Allow privileged socket options
  - [`core.syscall.avoid_ctl_syscalls`](#coresyscallavoid_ctl_syscalls) — Avoid system control calls on TCP
  - [`core.syscall.deferred_close`](#coresyscalldeferred_close) — Defer closing of file descriptors
  - [`core.syscall.dup2_close_fd`](#coresyscalldup2_close_fd) — Support dup2 calls
  - [`core.syscall.fork_support`](#coresyscallfork_support) — Enable fork support
  - [`core.syscall.sendfile_cache_limit`](#coresyscallsendfile_cache_limit) — Sendfile byte limit
- **[HARDWARE_FEATURES](#hardware_features)**
  - [`hardware_features.striding_rq.enable`](#hardware_featuresstriding_rqenable) — Enable striding receive queues
  - [`hardware_features.striding_rq.stride_size`](#hardware_featuresstriding_rqstride_size) — Size of each stride (bytes)
  - [`hardware_features.striding_rq.strides_num`](#hardware_featuresstriding_rqstrides_num) — Number of strides per WQE
  - [`hardware_features.tcp.lro`](#hardware_featurestcplro) — Large Receive Offload policy
  - [`hardware_features.tcp.tls_offload.dek_cache_max_size`](#hardware_featurestcptls_offloaddek_cache_max_size) — DEK max cache size
  - [`hardware_features.tcp.tls_offload.dek_cache_min_size`](#hardware_featurestcptls_offloaddek_cache_min_size) — DEK min cache size
  - [`hardware_features.tcp.tls_offload.rx_enable`](#hardware_featurestcptls_offloadrx_enable) — Enable TLS RX offload
  - [`hardware_features.tcp.tls_offload.tx_enable`](#hardware_featurestcptls_offloadtx_enable) — Enable TLS TX offload
  - [`hardware_features.tcp.tso.enable`](#hardware_featurestcptsoenable) — TCP segmentation offload policy
  - [`hardware_features.tcp.tso.max_size`](#hardware_featurestcptsomax_size) — Maximum TSO size
- **[MONITOR](#monitor)**
  - [`monitor.log.colors`](#monitorlogcolors) — Colored log output
  - [`monitor.log.details`](#monitorlogdetails) — Log details level
  - [`monitor.log.file_path`](#monitorlogfile_path) — Log file path
  - [`monitor.log.level`](#monitorloglevel) — Log level
  - [`monitor.report.file_path`](#monitorreportfile_path) — Tuning report file path
  - [`monitor.report.mode`](#monitorreportmode) — Tuning report mode
  - [`monitor.stats.cpu_usage`](#monitorstatscpu_usage) — Enable CPU usage statistics
  - [`monitor.stats.fd_num`](#monitorstatsfd_num) — Max tracked file descriptors
  - [`monitor.stats.file_path`](#monitorstatsfile_path) — Statistics file path
  - [`monitor.stats.shmem_dir`](#monitorstatsshmem_dir) — Shared memory directory
- **[NETWORK](#network)**
  - [`network.multicast.mc_flowtag_acceleration`](#networkmulticastmc_flowtag_acceleration) — Accelerate flowtag for multicast
  - [`network.multicast.mc_loopback`](#networkmulticastmc_loopback) — Enable multicast loopback
  - [`network.multicast.wait_after_join_msec`](#networkmulticastwait_after_join_msec) — Delay after multicast join (msec)
  - [`network.neighbor.arp.uc_delay_msec`](#networkneighborarpuc_delay_msec) — Unicast ARP delay (msec)
  - [`network.neighbor.arp.uc_retries`](#networkneighborarpuc_retries) — Unicast ARP retries
  - [`network.neighbor.errors_before_reset`](#networkneighborerrors_before_reset) — Errors before neighbor reset
  - [`network.neighbor.update_interval_msec`](#networkneighborupdate_interval_msec) — Neighbor update interval (msec)
  - [`network.protocols.ip.mtu`](#networkprotocolsipmtu) — MTU size
  - [`network.protocols.tcp.congestion_control`](#networkprotocolstcpcongestion_control) — TCP congestion control algorithm
  - [`network.protocols.tcp.linger_0`](#networkprotocolstcplinger_0) — Abort TCP connections on close
  - [`network.protocols.tcp.mss`](#networkprotocolstcpmss) — Maximum Segment Size
  - [`network.protocols.tcp.nodelay.byte_threshold`](#networkprotocolstcpnodelaybyte_threshold) — Data threshold for flush
  - [`network.protocols.tcp.nodelay.enable`](#networkprotocolstcpnodelayenable) — Disable Nagle's algorithm
  - [`network.protocols.tcp.push`](#networkprotocolstcppush) — Set TCP Push flag
  - [`network.protocols.tcp.quickack`](#networkprotocolstcpquickack) — Enable quick ACKs
  - [`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) — TCP timer interval (msec)
  - [`network.protocols.tcp.timestamps`](#networkprotocolstcptimestamps) — TCP timestamps mode
  - [`network.protocols.tcp.wmem`](#networkprotocolstcpwmem) — Write buffer size (bytes)
  - [`network.timing.hw_ts_conversion`](#networktiminghw_ts_conversion) — Timestamp conversion mode
- **[PERFORMANCE](#performance)**
  - [`performance.buffers.batching_mode`](#performancebuffersbatching_mode) — Buffer batching mode
  - [`performance.buffers.rx.buf_size`](#performancebuffersrxbuf_size) — RX buffer size
  - [`performance.buffers.rx.prefetch_before_poll`](#performancebuffersrxprefetch_before_poll) — Prefetch before polling
  - [`performance.buffers.rx.prefetch_size`](#performancebuffersrxprefetch_size) — RX prefetch size
  - [`performance.buffers.tcp_segments.pool_batch_size`](#performancebufferstcp_segmentspool_batch_size) — Pool segment batch size
  - [`performance.buffers.tcp_segments.ring_batch_size`](#performancebufferstcp_segmentsring_batch_size) — Ring segment batch size
  - [`performance.buffers.tcp_segments.socket_batch_size`](#performancebufferstcp_segmentssocket_batch_size) — Socket segment batch size
  - [`performance.buffers.tx.buf_size`](#performancebufferstxbuf_size) — TX buffer size
  - [`performance.buffers.tx.prefetch_size`](#performancebufferstxprefetch_size) — TX prefetch size
  - [`performance.completion_queue.interrupt_moderation.adaptive_change_frequency_msec`](#performancecompletion_queueinterrupt_moderationadaptive_change_frequency_msec) — Adaptive change frequency (msec)
  - [`performance.completion_queue.interrupt_moderation.adaptive_count`](#performancecompletion_queueinterrupt_moderationadaptive_count) — Adaptive moderation count threshold
  - [`performance.completion_queue.interrupt_moderation.adaptive_interrupt_per_sec`](#performancecompletion_queueinterrupt_moderationadaptive_interrupt_per_sec) — Target interrupts per second
  - [`performance.completion_queue.interrupt_moderation.adaptive_period_usec`](#performancecompletion_queueinterrupt_moderationadaptive_period_usec) — Adaptive moderation period (µsec)
  - [`performance.completion_queue.interrupt_moderation.enable`](#performancecompletion_queueinterrupt_moderationenable) — Enable interrupt moderation
  - [`performance.completion_queue.interrupt_moderation.packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count) — Packet count threshold
  - [`performance.completion_queue.interrupt_moderation.period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec) — Moderation period (µsec)
  - [`performance.completion_queue.keep_full`](#performancecompletion_queuekeep_full) — Keep completion queue full
  - [`performance.completion_queue.periodic_drain_max_cqes`](#performancecompletion_queueperiodic_drain_max_cqes) — Max CQEs per periodic drain
  - [`performance.completion_queue.periodic_drain_msec`](#performancecompletion_queueperiodic_drain_msec) — Periodic drain interval (msec)
  - [`performance.completion_queue.rx_drain_rate_nsec`](#performancecompletion_queuerx_drain_rate_nsec) — RX drain rate (nsec)
  - [`performance.max_gro_streams`](#performancemax_gro_streams) — Maximum GRO streams
  - [`performance.override_rcvbuf_limit`](#performanceoverride_rcvbuf_limit) — Override OS receive buffer limit
  - [`performance.polling.blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) — RX poll duration (µsec)
  - [`performance.polling.iomux.poll_os_ratio`](#performancepollingiomuxpoll_os_ratio) — OS file descriptor polling ratio
  - [`performance.polling.iomux.poll_usec`](#performancepollingiomuxpoll_usec) — Select/poll duration (µsec)
  - [`performance.polling.iomux.skip_os`](#performancepollingiomuxskip_os) — Skip OS polling frequency
  - [`performance.polling.max_rx_poll_batch`](#performancepollingmax_rx_poll_batch) — Max RX buffers per poll
  - [`performance.polling.nonblocking_eagain`](#performancepollingnonblocking_eagain) — Return EAGAIN on nonblocking send
  - [`performance.polling.offload_transition_poll_count`](#performancepollingoffload_transition_poll_count) — Offload transition poll count
  - [`performance.polling.rx_cq_wait_ctrl`](#performancepollingrx_cq_wait_ctrl) — RX completion queue wait control
  - [`performance.polling.rx_kernel_fd_attention_level`](#performancepollingrx_kernel_fd_attention_level) — RX kernel FD attention level
  - [`performance.polling.rx_poll_on_tx_tcp`](#performancepollingrx_poll_on_tx_tcp) — Poll RX queues on transmit
  - [`performance.polling.skip_cq_on_rx`](#performancepollingskip_cq_on_rx) — Skip completion queue checks on RX
  - [`performance.polling.yield_on_poll`](#performancepollingyield_on_poll) — Yield CPU during RX polling loop
  - [`performance.rings.max_per_interface`](#performanceringsmax_per_interface) — Maximum rings per interface
  - [`performance.rings.rx.allocation_logic`](#performanceringsrxallocation_logic) — RX ring allocation logic
  - [`performance.rings.rx.migration_ratio`](#performanceringsrxmigration_ratio) — RX ring migration ratio
  - [`performance.rings.rx.post_batch_size`](#performanceringsrxpost_batch_size) — RX WRE batch size
  - [`performance.rings.rx.ring_elements_count`](#performanceringsrxring_elements_count) — RX Receive Queue depth (WREs per ring)
  - [`performance.rings.rx.spare_buffers`](#performanceringsrxspare_buffers) — Spare RX buffers
  - [`performance.rings.rx.spare_strides`](#performanceringsrxspare_strides) — Spare stride descriptor cache size
  - [`performance.rings.tx.allocation_logic`](#performanceringstxallocation_logic) — TX ring allocation logic
  - [`performance.rings.tx.completion_batch_size`](#performanceringstxcompletion_batch_size) — TX WRE completion batch size
  - [`performance.rings.tx.max_inline_size`](#performanceringstxmax_inline_size) — Max TX inline size
  - [`performance.rings.tx.max_on_device_memory`](#performanceringstxmax_on_device_memory) — Max TX memory on device (KB)
  - [`performance.rings.tx.migration_ratio`](#performanceringstxmigration_ratio) — TX ring migration ratio
  - [`performance.rings.tx.ring_elements_count`](#performanceringstxring_elements_count) — TX Send Queue depth (WREs per ring)
  - [`performance.rings.tx.tcp_buffer_batch`](#performanceringstxtcp_buffer_batch) — TCP buffer batch size
  - [`performance.rings.tx.udp_buffer_batch`](#performanceringstxudp_buffer_batch) — TX buffer batch size
  - [`performance.steering_rules.disable_flowtag`](#performancesteering_rulesdisable_flowtag) — Disable hardware flow tag
  - [`performance.steering_rules.tcp.2t_rules`](#performancesteering_rulestcp2t_rules) — Enable 2-tuple rules
  - [`performance.steering_rules.tcp.3t_rules`](#performancesteering_rulestcp3t_rules) — Enable 3-tuple rules
  - [`performance.steering_rules.udp.3t_rules`](#performancesteering_rulesudp3t_rules) — Enable 3-tuple rules
  - [`performance.steering_rules.udp.only_mc_l2_rules`](#performancesteering_rulesudponly_mc_l2_rules) — Use only L2 rules for multicast
  - [`performance.threading.cpu_affinity`](#performancethreadingcpu_affinity) — CPU affinity
  - [`performance.threading.cpuset`](#performancethreadingcpuset) — CPU set path
  - [`performance.threading.internal_handler.behavior`](#performancethreadinginternal_handlerbehavior) — TCP control flow behavior
  - [`performance.threading.internal_handler.timer_msec`](#performancethreadinginternal_handlertimer_msec) — Timer resolution (msec)
  - [`performance.threading.mutex_over_spinlock`](#performancethreadingmutex_over_spinlock) — Use mutex instead of spinlocks
  - [`performance.threading.worker_threads`](#performancethreadingworker_threads) — XLIO Worker Threads number
- **[PROFILES](#profiles)**
  - [`profiles.spec`](#profilesspec) — Application spec profile

---

## ACCELERATION_CONTROL

### `acceleration_control.app_id`

> **Type:** string
>
> **Maps to:** `XLIO_APPLICATION_ID`

Specify a group of rules from libxlio.conf for XLIO to apply.

**Example:** 'XLIO_APPLICATION_ID=iperf_server'.
The default matches only the '*' group rule.

**Default:** `XLIO_DEFAULT_APPLICATION_ID`

### `acceleration_control.default_acceleration`

> **Type:** boolean
>
> **Maps to:** `XLIO_OFFLOADED_SOCKETS`

Create all sockets as offloaded/not-offloaded by default.
Value of true is for offloaded, false for not-offloaded.

**Default:** `true`

### `acceleration_control.rules`

> **Type:** array

Maps to configuration in libxlio.conf file.
Rules defining transport protocol and offload settings for
specific applications or processes.

**Default:** `[]`

---

## APPLICATIONS

### `applications.nginx.distribute_cq`

> **Type:** boolean
>
> **Maps to:** `XLIO_DISTRIBUTE_CQ`

Distributes completion queue interrupts across CPU cores.

**Behavior:**

- Enabled: Each worker's completion queues are assigned to a distinct completion vector,
  spreading interrupt processing across CPUs.
- Disabled: All completion queues share the same completion vector, typically concentrating
  interrupt processing on a single CPU.

Only affects interrupt-driven I/O (epoll/blocking). No effect in busy polling mode.

**Tradeoffs:**

- *false* (default): All completion queues share a single completion vector. Simple and
  predictable. Interrupt processing for all workers is handled by one CPU.
- *true*: Distributes interrupts across CPUs, which can improve latency in interrupt-driven
  mode by reducing per-CPU interrupt processing load.

**Auto-enabled** by the nginx profile ([`profiles.spec`](#profilesspec)=nginx).

**Example:** 8 Nginx workers with 16 completion vectors: Workers 0-7 use comp_vectors 0-7,
spreading interrupts across 8 different completion vectors instead of concentrating all on
completion vector 0.

**Default:** `false`

### `applications.nginx.src_port_stride`

> **Type:** integer (min: 2)
>
> **Maps to:** `XLIO_NGINX_SRC_PORT_STRIDE`

Controls how incoming connections are distributed across Nginx worker processes using hardware flow
steering rules based on source port patterns.

**How It Works:**
XLIO creates hardware flow steering rules that match incoming packets based on their source port.
Each Nginx worker is assigned a unique range of source port values. The stride controls how far
apart these ranges are spaced.

Internally, XLIO rounds the worker count up to the nearest power of 2, then builds a bitmask from
the rounded count and the stride. The bitmask intentionally excludes the least significant bit of
the port number (see "Why Minimum is 2" below). Each worker is assigned a unique value within that
mask, and the NIC routes packets whose source port matches the worker's value.

**Why Minimum is 2:**
The minimum value of 2 ensures the least significant bit of
the source port is excluded from steering decisions. Linux
connect() preferentially allocates even ephemeral ports, so
the least significant bit is typically 0 for all incoming
connections — including it in the mask would provide no
differentiation between workers.

**Example with 4 workers and stride=2 (default):**
XLIO examines bits 1-2 of each source port (ignoring bit 0). The four workers receive packets
based on those two bits:

- Worker 0: source ports where bits 1-2 are 00 (e.g., 0, 1, 8, 9, 16, 17, ...)
- Worker 1: source ports where bits 1-2 are 01 (e.g., 2, 3, 10, 11, 18, 19, ...)
- Worker 2: source ports where bits 1-2 are 10 (e.g., 4, 5, 12, 13, 20, 21, ...)
- Worker 3: source ports where bits 1-2 are 11 (e.g., 6, 7, 14, 15, 22, 23, ...)

**Low Values (e.g., 2 - default):**

**Benefits:**

- Supports more workers with the same hardware flow steering capacity
- Uses fewer bits from the 16-bit port space per steering rule
- Works well with high worker counts (8, 16, 32+ Nginx workers)
- Lower hardware resource usage per steering rule

**Drawbacks:**

- Connection distribution depends more heavily on client source port patterns
- Adjacent workers may receive similar traffic volumes if client ports cluster

**High Values (e.g., 4, 8, 16):**

**Benefits:**

- May provide more uniform distribution for certain client traffic patterns
- Greater separation between worker port ranges reduces steering conflicts
- Can help when clients generate ports with specific bit patterns

**Drawbacks:**

- Limits maximum supported workers: the product of the rounded worker count
  and the stride must fit within the 16-bit port space
- Uses more bits in the port mask, potentially overlapping with meaningful port ranges
- Diminishing returns for most real-world traffic patterns

**Non-Power-of-2 Workers:**
When [`workers_num`](#applicationsnginxworkers_num) is not a power of 2 (e.g., 3, 5, 6, 7 workers), XLIO automatically:
1. Rounds up to the next power of 2 for flow steering rules
2. Creates secondary rules for some workers to balance the load
3. Workers with lower IDs receive additional connection slots

For example, with 3 workers (rounded to 4 slots):

- Worker 0: receives 2 slots (primary + secondary rule)
- Worker 1: receives 1 slot
- Worker 2: receives 1 slot

**Recommended Settings:**

- For most deployments: Use default value of 2
- For power-of-2 worker counts (2, 4, 8, 16): Default works optimally
- For high worker counts (32+): Stick with 2 to maximize supported workers
- Only increase if you observe uneven distribution with default settings
  and have analyzed your client source port patterns

**Default:** `2`

### `applications.nginx.udp_pool_size`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NGINX_UDP_POOL_SIZE`

Maximum number of UDP sockets to keep in a per-worker pool for reuse.

**Behavior:** When close() is called on a UDP socket, it is placed into a pool instead
of being destroyed. When socket() is called, XLIO reuses a pooled socket if available,
avoiding kernel file descriptor allocation and internal socket object construction.

Only applies to Nginx worker processes, not the master process.

**Value Tradeoffs:**

*0 (Disabled - Default):*
Standard behavior. Use when UDP socket churn is low or connections are long-lived.

*Sizing guidance:*
Pool size should match peak concurrent short-lived UDP sockets per worker.
Divide expected concurrent UDP sockets by number of NGINX workers.
For long-lived connections (seconds+): pool provides marginal benefit, use small values.
For rapid socket cycling (sub-second lifetimes): size to expected concurrent count.

*Example:*
8 workers, expecting 1000 concurrent UDP upstream sockets with rapid turnover:
~125 sockets/worker → udp_pool_size of 100-150 captures most reuse benefit.

*Memory cost:* udp_pool_size × ~2-4KB per worker.
(100 pool × 8 workers ≈ 1.6-3.2MB held in reserve)

**Related:** [`applications.nginx.udp_socket_pool_reuse`](#applicationsnginxudp_socket_pool_reuse) controls receive buffer recycling.

**Default:** `0`

### `applications.nginx.udp_socket_pool_reuse`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NGINX_UDP_POOL_REUSE_BUFFS`

How many receive buffers a pooled UDP socket accumulates
before returning them in bulk. Only applies when
[`applications.nginx.udp_pool_size`](#applicationsnginxudp_pool_size) > 0.

For most deployments, leave at 0 (default). The nginx
profile ([`profiles.spec`](#profilesspec)) sets a batch size that balances
throughput and resource usage without tuning.

**When to adjust:**

- *Value too high:* Each buffered descriptor holds a
  hardware receive slot. If too many slots are held
  across pooled sockets, the NIC cannot post new
  receives and drops packets.
  **Symptom:** "HW RX Packets dropped:" counter
  increases in `xlio_stats` CQ output (`xlio_stats -v3`).
- *Value too low:* Buffers are returned one at a time,
  increasing internal lock contention.
  **Symptom:** reduced throughput under high packet
  rates with no other bottleneck visible.

**Default:** `0`

### `applications.nginx.workers_num`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NGINX_WORKERS_NUM`

Number of Nginx worker processes. **Must be > 0 to enable XLIO offloading for Nginx.**

**Behavior:** When set to a value greater than 0, XLIO
activates the nginx profile ([`profiles.spec`](#profilesspec)), creates
hardware flow steering rules per worker, and scales
memory allocation.

**Sizing:** Set to match your Nginx worker_processes configuration exactly.

*Power-of-2 values (2, 4, 8, 16, ...):* Optimal. Equal traffic distribution per worker.

*Non-power-of-2 values:* XLIO rounds up to the next power of 2 internally. The extra flow
steering slots are distributed as secondary rules to the lowest-numbered workers, so those
workers handle more traffic.

**Memory:** Auto-scaled per worker by the nginx profile;
see [`core.resources.memory_limit`](#coreresourcesmemory_limit) for sizing details.

**Example:** 3 workers (rounded up to 4 slots): Worker 0 gets 2 port slots (primary +
secondary rule), Workers 1-2 get 1 slot each. Using 4 workers avoids this imbalance.

**Default:** `0`

---

## CORE

### `core.daemon.dir`

> **Type:** string
>
> **Maps to:** `XLIO_SERVICE_NOTIFY_DIR`

Directory where XLIO writes files for communication with xliod daemon.

**Files created per process:**

- `xlioagent.<pid>.sock` - Unix domain socket for state messages
- `xlioagent.<pid>.pid` - PID file for termination monitoring

If you override this path, pass the same value to xliod
via `--notify-dir`. Both default to `/tmp/xlio`.

**Recommendation:** Use tmpfs (default /tmp/xlio is typically tmpfs on Linux).
Slow filesystems (NFS, spinning disk) add latency to socket initialization.

**Permissions:** Directory must be readable and writable by all XLIO processes
and the xliod daemon. Default /tmp/xlio with mode 0777 satisfies this.

**Default:** `/tmp/xlio`

### `core.daemon.enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_SERVICE_ENABLE`

Enables xliod daemon communication for TCP connection cleanup on abnormal process termination.

**Why This Matters:** When XLIO offloads TCP to userspace, the kernel is unaware of connections.
If an application crashes, remote peers never receive RST packets and wait for TCP timeout
(potentially minutes). The daemon monitors process termination via fanotify/inotify and sends
RST packets to all established TCP peers on behalf of crashed processes.

**Tradeoffs:**

*false (default):*
No overhead. Connection state changes are not reported. Remote peers wait for TCP timeout
on application crashes.

*true:*
Each TCP state change sends a message to xliod via Unix socket. Adds slight latency to
connection setup for high connection-rate workloads. Crash cleanup ensures immediate
notification to remote peers.

**Auto-enabled** on Microsoft Hyper-V environments regardless of user configuration.

**Default:** `false`

### `core.exception_handling.mode`

> **Type:** integer or string
>
> **Values:** -2/"exit", -1/"handle_debug", 0/"log_debug_undo_offload", 1/"log_error_undo_offload", 2/"log_error_return_error", 3/"log_error_abort"
>
> **Maps to:** `XLIO_EXCEPTION_HANDLING`

Controls XLIO behavior when encountering unsupported socket API calls (fcntl, ioctl,
setsockopt with unknown options).

**Modes (lenient to strict):**

- "exit" (-2): Exit application on XLIO startup failure only. No effect at runtime.

- "handle_debug" (-1, DEFAULT): Log at DEBUG level. Socket remains offloaded.
  Silent operation for production.

- "log_debug_undo_offload" (0): Log at DEBUG, un-offload socket to kernel stack.
  Socket loses acceleration but continues working via OS.

- "log_error_undo_offload" (1): Log at ERROR, un-offload socket.
  Makes issues visible in logs while maintaining stability.

- "log_error_return_error" (2): Log at ERROR, return EINVAL to application.
  Socket stays offloaded but API call fails.

- "log_error_abort" (3): Log at ERROR, abort application.
  Immediately surfaces incompatibilities.

**Tradeoffs:**
Un-offloading (modes 0, 1) moves traffic to kernel stack: higher latency, lower throughput.
Strict modes (2, 3) surface incompatibilities immediately but may break applications.

**Guidance:** Production: -1 or 0. Development/testing: 2 or 3.

**Default:** `"handle_debug" (-1)`

### `core.quick_init`

> **Type:** boolean
>
> **Maps to:** `XLIO_QUICK_START`

Skips hugepage residency validation during startup when enabled.

**Behavior:** When disabled (false), XLIO calls mincore() for each allocated hugepage to verify
pages are resident before use. When enabled (true), this validation is skipped.

**Value Tradeoffs:**

*false (Default):*
Safe. Catches cgroup misconfigurations that would cause SIGBUS crashes on first memory access.
Adds startup latency proportional to hugepage count.

*true:*
Faster startup. Risk: In cgroup-limited environments (containers, Kubernetes), mmap() may succeed
even when hugepages exceed the limit. First memory access triggers SIGBUS with no earlier warning.

**Decision guide:**

- Containers, Kubernetes, cgroup-limited: Keep disabled (runtime SIGBUS is worse than startup delay)
- Bare metal with verified hugepage config: Safe to enable for faster startup

**Default:** `false`

### `core.resources.external_memory_limit`

> **Type:** integer (bytes, min: 0) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_MEMORY_LIMIT_USER`

Memory block size XLIO requests from a user-provided
allocator.

**Applies only** to applications using XLIO's Extra API
(xlio_init_ex) with custom memory_alloc and memory_free
callbacks. No effect for standard POSIX applications.

**Behavior:** The effective block size is
max(this value, [`core.resources.memory_limit`](#coreresourcesmemory_limit)). XLIO
will never request less than [`memory_limit`](#coreresourcesmemory_limit) — this
parameter can only increase the block size, not
decrease it.

- 0 (default): XLIO requests blocks sized by
  [`core.resources.memory_limit`](#coreresourcesmemory_limit).
- Non-zero: XLIO requests blocks of
  max(this value, [`memory_limit`](#coreresourcesmemory_limit)).

**Sizing:** Your allocator must be able to provide a
contiguous block of at least [`core.resources.memory_limit`](#coreresourcesmemory_limit).
Set this parameter only if your allocator can provide
a larger block than [`memory_limit`](#coreresourcesmemory_limit) and XLIO needs it.

**Profile override:** nvme_bf3 profile sets this to 2GB.

**Supports suffixes:** B, KB, MB, GB.

**Default:** `0`

### `core.resources.heap_metadata_block_size`

> **Type:** integer (bytes, min: 0) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_HEAP_METADATA_BLOCK`

Block size for metadata heap allocations. This is regular
heap memory, NOT registered with RDMA hardware.

**What it stores:** Buffer descriptors (tracking buffer
state, ownership, reference counts) and TCP segment
objects share the same metadata heap.

**Behavior:** The heap grows in blocks of this size
during warmup as buffer pools and TCP segment pools
expand. Once the pools have enough cached objects for
steady-state traffic, the heap stabilizes and does not
grow further.

**Sizing:** The default (32MB) is sufficient for most
workloads. Only reduce if memory is constrained and you
accept more mmap syscalls during warmup.

**Tradeoffs:**

- *Higher values:* Fewer heap expansions during warmup,
  more memory allocated upfront.
- *Lower values:* Less initial memory, but more mmap
  syscalls during warmup.

**Profile override:** Nginx master processes
automatically use 2MB (no traffic handling).

**Supports suffixes:** B, KB, MB, GB.

**Default:** `32MB`

### `core.resources.hugepages.enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_MEM_ALLOC_TYPE`

Controls whether XLIO uses huge pages instead of regular pages
for buffer allocation. XLIO supports all hugepage sizes
available on the system (auto-detected from
`/sys/kernel/mm/hugepages/`); see
[`hugepages.size`](#coreresourceshugepagessize) to override.

**Why it matters:** Huge pages improve TLB cache footprint and
NIC internal cache utilization, reducing address-translation
overhead for both CPU and network hardware.

**Behavior:**

- true (default): Allocates using huge pages. Falls back to regular pages if unavailable.
- false: Uses regular pages for all memory allocation, including metadata (buffer descriptors, TCP segments), which normally uses huge pages.

**rdma-core integration:** When enabled, sets RDMAV_HUGEPAGES_SAFE=1 and MLX_QP_ALLOC_TYPE/
MLX_CQ_ALLOC_TYPE to "ALL" (if default hugepage ≤32MB) or "PREFER_CONTIG".
When disabled, sets to "ANON".

**Tradeoffs:**

- *true*: Lower latency (fewer TLB misses), faster RDMA registration. Requires system
  hugepage config. May waste memory due to alignment.
- *false*: No system config required. Higher TLB miss rate with large allocations.

**Auto-disabled** for Nginx master process (workers handle traffic).

**Default:** `true`

### `core.resources.hugepages.size`

> **Type:** integer (bytes, min: 0) or string with size suffix (B, KB, MB, GB) — must be a power of 2, or 0
>
> **Maps to:** `XLIO_HUGEPAGE_SIZE`

Forces a specific hugepage size for XLIO memory allocations.

**Behavior:**

- 0 (default): Auto-selects optimal size per allocation from /sys/kernel/mm/hugepages/
- Non-zero: Uses specified size (must be power of 2, system-supported)

**Auto-selection algorithm (largest-first):**
1. "Optimal": fills ≥1 page, OR wastes ≤2MB, OR wastes ≤10%
2. "Acceptable" fallback: wastes ≤256MB OR ≤50%

**Sizing guidance:**
Leave at 0 (auto) for most deployments. Force a specific size only if:

- Auto-selection wastes excessive memory for your allocation pattern
- You need to reserve larger hugepages (1GB) for other applications

**Common sizes:** 2MB (x86_64 default, good balance) or 1GB (multi-gigabyte allocations only).

Must be power of 2, or 0. Supports suffixes: B, KB, MB, GB.

**Default:** `0`

### `core.resources.memory_limit`

> **Type:** integer (bytes, min: 0) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_MEMORY_LIMIT`

Pre-allocates memory for XLIO's hardware-registered buffer pools (RX/TX buffers, stride descriptors).

**Behavior:** XLIO allocates a contiguous block at startup, registers it with RDMA hardware for
DMA operations, and carves it into buffer pools. Memory is reserved upfront even when idle.

**Sizing:** Match to peak buffer demand. Both RX and TX buffer
pools draw from this pool. RX consumption depends on ring count
and whether Striding RQ is enabled (see
hardware_features.striding_rq settings). TX consumption grows
with active connections.

**Profile defaults:**

- ultra_latency: 128MB (single-ring focus)
- nginx: 4GB per worker (16 workers or fewer) or 3GB per worker (more than 16), divided per worker
- nginx_dpu: 1GB per worker (or 512MB per worker with exactly 16 workers), divided per worker
- nvme_bf3: 256MB

**Tradeoffs:**

- *Higher values*: Handle traffic bursts without drops. Essential for multi-ring deployments.
  Requires more hugepages, reserves memory even when idle.
- *Lower values*: Smaller footprint, faster startup. Risk pool exhaustion under load
  ("No buffers error" stat increases, packets dropped).

**Monitoring:** Run `xlio_stats -p <pid> -v 3` (full view) to check buffer pool stats:

- "No buffers error:" non-zero → increase `memory_limit` (pool exhaustion)
- "Expands:" continuously increasing → increase `memory_limit` (reduce runtime growth overhead)

**Supports suffixes:** B, KB, MB, GB.

**Default:** `2GB`

### `core.signals.sigint.exit`

> **Type:** boolean
>
> **Maps to:** `XLIO_HANDLE_SIGINTR`

Controls whether XLIO intercepts SIGINT (Ctrl+C) to enable graceful shutdown.

**Behavior:**

- true (default): XLIO wraps signal()/sigaction() for SIGINT. Sets internal exit flag
  that terminates polling loops and socket operations. Chains to application's original
  handler. Ensures cleanup of buffer pools, hugepages, and completion queues.
- false: Signal passes directly to kernel. Exit flag is never set, so XLIO polling loops
  and socket operations won't exit gracefully. May cause resource leaks during shutdown.

**Tradeoffs:**

- *true*: Graceful shutdown, proper resource cleanup. Slight signal interception overhead.
- *false*: Application has full signal control. Use for complex signal handling that
  conflicts with XLIO, custom process managers, or signal debugging.

**Default:** `true`

### `core.signals.sigsegv.backtrace`

> **Type:** boolean
>
> **Maps to:** `XLIO_HANDLE_SIGSEGV`

Registers a SIGSEGV handler to print stack backtraces on crash.

**Behavior:**

- true: On segfault, XLIO prints a demangled C++ backtrace, then terminates with SIGKILL.
  No core dump is generated (SIGKILL prevents it).
- false (default): Standard OS crash behavior. Core dumps generated if ulimit allows.
  Debuggers (gdb, valgrind) work normally.

**Tradeoffs:**

- *true*: Immediate crash visibility without core dumps. Useful in development or when
  core dumps are impractical.
- *false*: Full core dump and debugger support. Better for production post-mortem analysis.

**Default:** `false`

### `core.syscall.allow_privileged_sockopt`

> **Type:** boolean
>
> **Maps to:** `XLIO_ALLOW_PRIVILEGED_SOCK_OPT`

Suppresses EPERM errors from privileged socket options, returning success to the application.

**How it works:**
Some socket options (e.g., SO_BINDTODEVICE) require CAP_NET_RAW or root privileges.
When enabled and the kernel returns EPERM, XLIO suppresses the error and returns success.
XLIO still processes the option internally regardless of kernel result.

**Affected socket option:** SO_BINDTODEVICE (bind socket to a specific network interface)

**Tradeoffs:**

- *true* (default): Applications can use SO_BINDTODEVICE without root. XLIO handles
  binding internally. May mask permission issues indicating configuration problems.
- *false*: EPERM errors propagate to application. Stricter error handling exposes
  actual kernel failures. Better for debugging permission-related issues.

**Default:** `true`

### `core.syscall.avoid_ctl_syscalls`

> **Type:** boolean
>
> **Maps to:** `XLIO_AVOID_SYS_CALLS_ON_TCP_FD`

For connected TCP sockets, handles common control operations in userspace without
kernel syscalls.

**Intercepted operations (connected sockets only):**

- fcntl(F_GETFL/F_SETFL): Get/set blocking state from XLIO internal flag
- ioctl(FIONBIO): Set non-blocking mode in XLIO only
- setsockopt(): Supported options apply to XLIO state only

Unsupported operations still go to kernel.

**Tradeoffs:**

- *false* (default): All control operations go through kernel. Guaranteed
  kernel/XLIO state consistency. Higher latency for control operations.
- *true*: Eliminates syscall overhead. Significant latency
  improvement for apps that frequently toggle blocking mode or query socket flags.
  Risk: kernel and XLIO state may diverge for edge cases.

**Auto-enabled** by [`profiles.spec`](#profilesspec)=ultra_latency or [`profiles.spec`](#profilesspec)=latency.

**When to disable:** Applications reading socket state via /proc/net/tcp, or when
debugging requires kernel state inspection.

**Default:** `false`

### `core.syscall.deferred_close`

> **Type:** boolean
>
> **Maps to:** `XLIO_DEFERRED_CLOSE`

Postpones the kernel close(2) syscall from close() to the socket destructor,
ensuring the file descriptor is released only after all XLIO cleanup is complete.

**The Problem:**
XLIO derives flow steering rules from file descriptor numbers and
port bindings. Without deferral, close() releases the fd immediately
but socket destruction (including flow rule teardown) can be
delayed — for example, by TCP TIME_WAIT (up to ~2 minutes).
During this window:

- A new socket may receive the same fd, reusing the old flow tag
- A new socket may bind the same port while the old steering rule
  is still active

This can cause steering rule creation failure for the new socket,
packet misrouting, or other hard-to-diagnose symptoms.
Primarily relevant for outgoing and listening sockets;
incoming (accepted) TCP sockets are generally unaffected.

**Tradeoffs:**

- *false* (default): Immediate fd release for faster resource recycling. Lower fd usage.
- *true*: File descriptors remain open until destructor runs. Higher fd usage, may hit
  fd limits sooner. Required for applications with rapid socket churn.

**When to enable:** Applications creating/destroying sockets rapidly,
or applications experiencing steering rule creation failures after socket close.

**Default:** `false`

### `core.syscall.dup2_close_fd`

> **Type:** boolean
>
> **Maps to:** `XLIO_CLOSE_ON_DUP2`

When enabled, XLIO cleans up internal socket structures before dup2() forwards to the kernel.

**How it works:**
dup2(oldfd, newfd) atomically closes newfd and makes it a copy of oldfd.
When newfd is an XLIO-managed socket, XLIO must release its internal resources first.

**Tradeoffs:**

- *true* (default): Small per-call overhead. Prevents resource leaks and undefined behavior
  when dup2() closes XLIO sockets.
- *false*: No interception overhead. Only safe if application never uses dup2() to close
  XLIO-offloaded sockets; otherwise causes memory leaks and stale internal state.

**Default:** `true`

### `core.syscall.fork_support`

> **Type:** boolean
>
> **Maps to:** `XLIO_FORK`

Controls whether XLIO initializes libibverbs for fork-safe operation via ibv_fork_init().

**How it works:**
ibv_fork_init() marks RDMA memory regions with madvise(MADV_DONTFORK), preventing the kernel
from copying them to child processes. Without this, parent and child share RDMA hardware
resources, causing data corruption or crashes.

**Tradeoffs:**

- *true* (default): Adds initialization latency and per-memory-region madvise() overhead.
  Required if the application may call fork().
- *false*: Faster startup, no madvise() overhead. If fork() occurs, undefined behavior:
  memory corruption, crashes, or hardware hangs.

**Warning:** Many operations implicitly fork: system(), popen(), backtrace(), some logging
libraries. Disable only with complete control over the application and guarantee of no fork().

**Default:** `true`

### `core.syscall.sendfile_cache_limit`

> **Type:** integer (bytes, min: 0) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_ZC_CACHE_THRESHOLD`

Memory limit for the zero-copy mapping cache used by sendfile().

**Supports suffixes:** B, KB, MB, GB.

**How it works:**
Files sent via sendfile() are mmap'd, registered with RDMA hardware (ibv_reg_mr), and cached
by file identity (device + inode). Different file descriptors to the same file share one mapping.
When the cache exceeds this limit, LRU eviction removes oldest unused mappings.

**Tradeoffs:**

- *Higher values (default 10GB):* More files cached, better throughput for file-serving.
  Memory is only consumed when files are actually mapped.
- *Lower values:* Smaller footprint, but more frequent cache misses trigger mmap/registration
  overhead.
- *0:* Disables caching. Every sendfile() performs fresh mmap/register/unmap cycle.

**Sizing:** Set to total size of frequently-accessed files (working set).
For web servers or content delivery: 1-2x the hot content size.

**Example:** Serving 50 files averaging 200MB each, frequently accessed:
working set = 10GB → default 10GB is appropriate.

**Note:** This cache is global across all sockets and threads.

**Default:** `10GB`

---

## HARDWARE_FEATURES

### `hardware_features.striding_rq.enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_STRQ`

Enable/Disable Striding Receive Queues for optimized packet processing.

**How it works:**
With regular Receive Queues, each Work Queue Element receives exactly one packet.
With Striding Receive Queues, each Work Queue Element is divided into multiple strides
(slots), allowing a single element to receive many packets. This significantly reduces
Work Queue Element replenishment overhead under high packet rates.

**Tradeoffs:**

- true (default): Higher packet rates with lower CPU overhead for Work Queue Element
  management. Better batching with fewer doorbell writes. Dynamic stride allocation from
  an expandable pool. Recommended for most workloads, especially high packet-rate scenarios.
- false: Required for legacy compatibility, debugging, or environments where Striding
  Receive Queues are not supported by hardware. Also disables LRO (Large Receive Offload)
  with default settings, since LRO payload size is derived from the stride buffer
  configuration. See [`hardware_features.tcp.lro`](#hardware_featurestcplro).

**Memory:** Each Work Queue Element buffer = strides per element × stride size.
With defaults (2048 × 64 bytes), each element can hold up to 2048 small packets
or fewer large packets that span multiple strides.

**Default:** `true`

### `hardware_features.striding_rq.stride_size`

> **Type:** integer (range: 64 to 8192) — must be a power of 2, or 0
>
> **Maps to:** `XLIO_STRQ_STRIDE_SIZE_BYTES`

Size in bytes of each stride (slot) in a Striding Receive Queue Work Queue Element.
Must be power of two in range [64 - 8192].

Packets larger than `stride_size` span multiple strides (e.g., 1500-byte packet with
`stride_size`=64 uses 24 strides).

Sizing depends on LRO (Large Receive Offload) setting:

With LRO enabled (default=auto): LRO aggregates TCP segments into large chunks (up to 64KB)
that span multiple strides. Smaller `stride_size` is more efficient because waste only occurs
at segment boundaries. Default 64 bytes is optimal for LRO.

**With LRO disabled:** Each packet occupies enough strides to fit its full size (rounded up).
Any leftover bytes in the last stride are wasted. For example, a 1500-byte packet with
64-byte strides uses 24 strides (1536 bytes), wasting 36 bytes.
Match `stride_size` to typical packet size to minimize both waste and stride count.

**Tradeoffs:**

- 64 (default): Optimal for LRO (most workloads), small packets (UDP, TCP ACKs).
  Without LRO, large packets consume many strides.
- 256-512: Better for jumbo frames (MTU 9000) with LRO disabled.
- 2048-8192: Storage workloads (NVMe-oF) with large transfers and LRO disabled.

**Constraint:** the product of strides per element and stride size must be at least MTU + 18 bytes (Ethernet headers).

**Default:** `64`

### `hardware_features.striding_rq.strides_num`

> **Type:** integer (range: 512 to 65536) — must be a power of 2, or 0
>
> **Maps to:** `XLIO_STRQ_NUM_STRIDES`

Number of strides (packet slots) per receive Work Queue Element.
Must be power of two in range [512 - 65536].

**Memory:** Each Work Queue Element buffer = strides per element × stride size.
Default: 2048 × 64 = 128KB per element. Total receive memory is approximately the product of
strides per element, stride size, and receive queue depth ([`hardware_features.striding_rq.stride_size`](#hardware_featuresstriding_rqstride_size)
and [`performance.rings.rx.ring_elements_count`](#performanceringsrxring_elements_count)).

**Sizing:** Match to expected burst size between replenishment cycles. Default 2048 handles
most workloads. Increase for high packet rates (millions per second) where replenishment
overhead becomes significant. Decrease for memory-constrained environments.

**Tradeoffs:**

- *Lower (512):* Smaller buffers, faster recycling, more frequent replenishment overhead.
- *Higher (65536):* Better for high packet rates, larger buffers held until all consumed.

**Constraint:** The product of strides per element and receive queue depth
([`performance.rings.rx.ring_elements_count`](#performanceringsrxring_elements_count)) must not exceed 4,194,304 (hardware Completion Queue
Entry limit). If exceeded, the receive queue depth is automatically reduced.

**Default:** `2048`

### `hardware_features.tcp.lro`

> **Type:** integer or string
>
> **Values:** -1/"auto", 0/"disable", 1/"enable"
>
> **Maps to:** `XLIO_LRO`

Large Receive Offload aggregates multiple TCP segments from the same stream into larger buffers
(up to 64KB), reducing per-packet CPU overhead at the cost of added latency.

**Values:**

- "auto" or -1 (default): Enabled based on ethtool setting (check: ethtool -k <iface> | grep lro)
- "disable" or 0: Each TCP segment delivered individually
- "enable" or 1: Force enabled if adapter supports it

**Tradeoffs:**

- Enabled: Higher throughput, lower CPU for bulk transfers (file serving, backup, streaming).
  Segments coalesce up to 64KB before delivery. May add latency waiting for aggregation.
- Disabled: Lower latency, immediate per-packet delivery. Required for latency-sensitive
  workloads (trading, real-time). Higher CPU at high packet rates.

**Striding Receive Queue Interaction:**
The maximum LRO payload is the smaller of the total stride buffer size (strides per element × stride size) and 64KB, rounded to 256 bytes.
With defaults (2048 × 64 = 128KB), LRO can coalesce full 64KB segments.
Lower stride configurations may limit aggregation size.

**When to change:** Disable for latency-sensitive applications. Enable (or leave auto) for
throughput-oriented workloads.

**Default:** `"auto" (-1)`

### `hardware_features.tcp.tls_offload.dek_cache_max_size`

> **Type:** integer
>
> **Maps to:** `XLIO_HIGH_WMARK_DEK_CACHE_SIZE`

Maximum number of Data Encryption Key objects to cache for TLS TX offload.

**How it works:** XLIO caches DEK objects from closed connections
for reuse by new ones, reducing NIC firmware operations. This
value sets the maximum cache capacity.

**Sizing:** Match to peak concurrent TLS connections. The cache holds DEKs from closed
connections for reuse by new ones. If connection churn exceeds cache size, new DEKs must
be created (slower). For short-lived connections with high turnover, size to expected
concurrent count. For long-lived connections, default is sufficient.

**Tradeoffs:**

- Higher values: Fewer firmware operations, smoother latency. Higher NIC memory usage.
- Lower values: Lower NIC resource consumption. More frequent firmware operations with high churn.

Only affects TLS TX offload ([`tx_enable`](#hardware_featurestcptls_offloadtx_enable)). RX offload creates DEKs directly without caching.

**Default:** `1024`

### `hardware_features.tcp.tls_offload.dek_cache_min_size`

> **Type:** integer
>
> **Maps to:** `XLIO_LOW_WMARK_DEK_CACHE_SIZE`

Low watermark threshold that controls when to create new Data Encryption Keys versus
recycling existing keys.

**Behavior:** When a new TLS connection needs a key and no
recycled keys are available:

- Cached keys <= min_size: Create a new key via NIC firmware
- Cached keys > min_size: Recycle cached keys via a firmware
  operation

**Sizing:** Match to concurrent TLS connection count during peak traffic bursts.
During connection spikes (new connections arriving faster than old ones close):

- Value too low: Frequent firmware operations cause latency spikes
- Value too high: Unnecessary keys created, wasting hardware memory

For workloads with gradual connection turnover, the default (512) is sufficient.

**Constraint:** Must be < [`dek_cache_max_size`](#hardware_featurestcptls_offloaddek_cache_max_size). If >= [`dek_cache_max_size`](#hardware_featurestcptls_offloaddek_cache_max_size), auto-adjusted to [`dek_cache_max_size`](#hardware_featurestcptls_offloaddek_cache_max_size) / 2.

Only affects TLS TX offload ([`tx_enable`](#hardware_featurestcptls_offloadtx_enable)).

**Default:** `512`

### `hardware_features.tcp.tls_offload.rx_enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_UTLS_RX`

Offloads TLS decryption to the NIC's crypto engine using the Linux kTLS API.

**Limitation:** Each TLS RX session consumes a hardware TIR (Transport Interface Receive)
object. TIRs are a system-wide resource (typically 64K total, shared across all processes
and non-TLS uses), so the practical TLS RX session count is lower.

**Why default is false:** RX offload can perform worse than software decryption due to resync
overhead.

**Tradeoffs:**

- false (default): Predictable performance, no NIC resources, works on any hardware.
  Higher CPU usage, lower throughput ceiling.
- true: Lower CPU, higher throughput. Packet loss or out-of-order delivery triggers
  partial software fallback (resyncs). Monitor "TLS Rx Resyncs" in xlio_stats.

**Monitoring:** Check xlio_stats for "TLS Rx Resyncs" (should be low) and "TLS Rx fallback"
counters. High values indicate RX offload may hurt performance.

**OpenSSL dependency:** The application must be linked against OpenSSL. XLIO searches for
OpenSSL symbols (EVP_Decrypt/EVP_Encrypt) at runtime in the application's address space.
These symbols are required for software decryption fallback, which handles records that the
NIC cannot decrypt (out-of-order packets, resyncs). Without OpenSSL, TLS RX offload setup
fails per connection.

**Prerequisites:** ConnectX-6 DX or later, XLIO built with --enable-utls.

**Default:** `false`

### `hardware_features.tcp.tls_offload.tx_enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_UTLS_TX`

Offloads TLS encryption to the NIC's crypto engine using the Linux kTLS API, freeing
the CPU from AES-GCM encryption work.

**Tradeoffs:**

- true (default): NIC handles encryption. Lower CPU, higher throughput, lower latency.
  Requires ConnectX-6 DX+ and kTLS-enabled TLS library. Consumes NIC resources (Data
  Encryption Key cache, Transport Interface Send contexts).
- false: CPU handles encryption. Works on any hardware, simpler debugging, no NIC resources.
  Higher CPU usage, lower throughput ceiling. Use when debugging TLS issues, hardware lacks
  offload support, or very high connection count exhausts NIC Data Encryption Key cache.

**Monitoring:** In xlio_stats, "TLS Tx Offload" confirms offload is active; "TLS Tx Resyncs"
shows retransmission-triggered resyncs (unlike RX, TX resync has no performance impact).

**Prerequisites:** ConnectX-6 DX or later, TLS library or application with kTLS support,
XLIO built with --enable-utls.

XLIO automatically falls back to software encryption if hardware offload is unavailable.

**Default:** `true`

### `hardware_features.tcp.tso.enable`

> **Type:** integer or string
>
> **Values:** -1/"auto", 0/"disable", 1/"enable"
>
> **Maps to:** `XLIO_TSO`

TCP Segmentation Offload sends buffers larger than MTU to the NIC, which handles segmentation
in hardware (sequence numbers, checksums, headers per segment).

**Values:**

- "auto" or -1 (default): Enables based on adapter capability and ethtool setting
- "disable" or 0: Forces TSO off
- "enable" or 1: Forces TSO on if hardware supports it

**Tradeoffs:**

- Enabled: Higher throughput (line-rate on 100Gbps+), lower CPU, fewer work requests per byte.
- Disabled: Useful for network debugging (packet capture shows pre-segmentation sizes).

**Note:** TSO aggregation is limited by congestion window. During slow start with small cwnd,
TSO cannot aggregate large segments regardless of [`hardware_features.tcp.tso.max_size`](#hardware_featurestcptsomax_size).

**Check status:** ethtool -k <iface> | grep tcp-segmentation-offload

**Default:** `"auto" (-1)`

### `hardware_features.tcp.tso.max_size`

> **Type:** integer (bytes, min: 1) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_MAX_TSO_SIZE`

Maximum bytes aggregated into a single TSO segment before NIC segmentation.

The actual TSO segment payload is the smallest of: the configured `max_size`,
hardware capability, and the TCP congestion window.

**Sizing:** Default (256KB) handles most workloads. Increase for sustained bulk transfers.
Decrease for latency-sensitive apps or to reduce burstiness on shared networks.

**Tradeoffs:**

- Higher: Fewer work requests per byte, higher throughput. Risk: bursty traffic.
- Lower: Smoother traffic, faster first-byte. Risk: may not hit line-rate on 100Gbps+.

**Hardware warning:** If NIC capability exceeds 256KB, XLIO logs a suggestion to increase max_size.

**Supports suffixes:** B, KB, MB (e.g., "128KB", "256KB").

**Default:** `256KB`

---

## MONITOR

### `monitor.log.colors`

> **Type:** boolean
>
> **Maps to:** `XLIO_LOG_COLORS`

Use color scheme when logging.
Red for errors, purple for warnings and dim for low level debugs.
`monitor.log.colors` is automatically disabled when logging is directed
to a non terminal device (e.g. [`monitor.log.file_path`](#monitorlogfile_path) is configured).

**Default:** `true`

### `monitor.log.details`

> **Type:** integer (range: 0 to 3)
>
> **Maps to:** `XLIO_LOG_DETAILS`

Add details on each log line:
   - 0=Basic log line
   - 1=ThreadId
   - 2=ProcessId+ThreadId
   - 3=Time + ProcessId + ThreadId [Time is in milli-seconds from start of process].

**Default:** `0`

### `monitor.log.file_path`

> **Type:** string
>
> **Maps to:** `XLIO_LOG_FILE`

Redirect all logging to a file.
Useful when raising [`monitor.log.level`](#monitorloglevel).

A '%d' in the path is replaced with the process ID,
so each process writes its own log file.

**Example:** "/tmp/xlio.log"

**Default:** `""`

### `monitor.log.level`

> **Type:** integer or string
>
> **Values:** -2/"init", -1/"none", 0/"panic", 1/"error", 2/"warn", 3/"info", 4/"details", 5/"debug", 6/"fine", 7/"finer", 8/"all"
>
> **Maps to:** `XLIO_TRACELEVEL`

Controls library logging verbosity. Use string names for consistency across config methods.

**Levels (from quietest to most verbose):**

- "none": No logging at all
- "panic": Fatal errors causing exceptions (memory allocation failures). Rarely used.
- "error": Runtime errors (OS/verbs call failures, internal logic bugs)
- "warn": Non-disruptive warnings (config issues, address resolution failures,
  unsupported functions)
- "info" (default): General information, startup configuration
- "details": Complete XLIO configuration, high-level decision logging
- "debug": All socket API calls logged, internal control channel activity
- "fine": TX/RX fast path logging. **Lowers performance.**
- "finer": Very detailed runtime logging. **Drastically lowers performance.**
- "all": Same as finer

**Note on numeric values:** Integer values can be used in JSON config files (0=panic
through 8=all), but numeric string aliases in XLIO_TRACELEVEL env var use different
mapping for some levels. Use string names to avoid confusion.

**When to change:**

- Production: Keep "info" (default) or use "error" to reduce log noise
- Debugging socket issues: Use "debug"
- Deep troubleshooting: Use "fine" or "finer" with [`monitor.log.file_path`](#monitorlogfile_path) to avoid
  console overhead

**Example:** `monitor.log.level`="debug"

**Default:** `"info" (3)`

### `monitor.report.file_path`

> **Type:** string
>
> **Maps to:** `XLIO_REPORT_FILE`

Output path for the tuning report.
A '%d' in the path is replaced with the process ID.

See [Tuning Report Reference](xlio_tuning_report_reference.md)
for report interpretation and troubleshooting guidance.

**Default:** `/tmp/xlio_report_%d.txt`

### `monitor.report.mode`

> **Type:** integer or string
>
> **Values:** -1/"auto", 0/"disable", 1/"enable"
>
> **Maps to:** `XLIO_PRINT_REPORT`

Controls tuning report generation at process exit.

- "auto" (-1): Generate only when anomalies are detected
  (buffer allocation failures, hardware receive drops, or
  transmit work-request exhaustion). A summary is logged
  with the full report path.
- "disable" (0): Never generate.
- "enable" (1): Always generate.

The default triggers reports only when something needs
attention — no action required for most deployments.

**Default:** `"auto" (-1)`

### `monitor.stats.cpu_usage`

> **Type:** boolean
>
> **Maps to:** `XLIO_CPU_USAGE_STATS`

Calculate XLIO CPU usage during polling HW loops.
This information is available through XLIO stats utility.

**Default:** `false`

### `monitor.stats.fd_num`

> **Type:** integer (range: 0 to 1024)
>
> **Maps to:** `XLIO_STATS_FD_NUM`

Maximum number of sockets monitored by XLIO statistic mechanism.
This affects the number of sockets that xlio_stats and
[`monitor.stats.file_path`](#monitorstatsfile_path) can report simultaneously.
xlio_stats tool is additionally limited by 1024 sockets.

**Default:** `0`

### `monitor.stats.file_path`

> **Type:** string
>
> **Maps to:** `XLIO_STATS_FILE`

Redirect socket statistics to a file.
Statistics are written per socket when the socket closes.

A '%d' in the path is replaced with the process ID.

**Example:** "/tmp/xlio_stats.log"

**Default:** `""`

### `monitor.stats.shmem_dir`

> **Type:** string
>
> **Maps to:** `XLIO_STATS_SHMEM_DIR`

Set the directory path for the library to create the shared memory files for xlio_stats.
No files will be created when setting this value to empty string "".

**Default:** `/tmp/xlio`

---

## NETWORK

### `network.multicast.mc_flowtag_acceleration`

> **Type:** boolean
>
> **Maps to:** `XLIO_MC_FORCE_FLOWTAG`

Forces the use of flow tag acceleration for multicast flows where
(SO_REUSEADDR) is set.
Applicable if there are no other sockets opened for the same flow in system.

**Default:** `false`

### `network.multicast.mc_loopback`

> **Type:** boolean
>
> **Maps to:** `XLIO_TX_MC_LOOPBACK`

This parameter sets the initial value used by XLIO internally
to control the multicast loopback packets behavior during transmission.
An application that calls setsockopt() with IP_MULTICAST_LOOP will
override the initial value set by this parameter.

**Default:** `true`

### `network.multicast.wait_after_join_msec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_WAIT_AFTER_JOIN_MSEC`

This parameter indicates the time of delay in milliseconds for the first packet
sent after receiving the multicast JOINED event from the SM.
This is helpful to overcome loss of first few packets of an outgoing stream due to
SM lengthy handling of MFT configuration on the switch chips.

**Default:** `0`

### `network.neighbor.arp.uc_delay_msec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NEIGH_UC_ARP_DELAY_MSEC`

Time in milliseconds to wait between unicast ARP attempts.

**Default:** `10000`

### `network.neighbor.arp.uc_retries`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NEIGH_UC_ARP_QUATA`

Number of unicast ARP retries before sending
broadcast ARP when neigh state is NUD_STALE.

**Default:** `3`

### `network.neighbor.errors_before_reset`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NEIGH_NUM_ERR_RETRIES`

Number of retries to restart the neighbor state machine after receiving an ERROR event.

**Default:** `1`

### `network.neighbor.update_interval_msec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_NETLINK_TIMER`

Sets the interval in milliseconds between neighbor table updates.

**Default:** `10000`

### `network.protocols.ip.mtu`

> **Type:** integer (range: 0 to 9000)
>
> **Maps to:** `XLIO_MTU`

Size of each Rx and Tx data buffer (Maximum Transfer Unit).
This value sets the fragmentation size of the packets
sent by the library.

- 0: Follow each interface's actual MTU.
- Greater than 0: Override all interfaces with this value.

**Default:** `0`

### `network.protocols.tcp.congestion_control`

> **Type:** integer or string
>
> **Values:** 0/"lwip", 1/"cubic", 2/"disable"
>
> **Maps to:** `XLIO_TCP_CC_ALGO`

TCP congestion control algorithm.
The default algorithm coming with LwIP is a variation of Reno.
The new Cubic algorithm was adapted from FreeBSD implementation.

Use:
   - "lwip" or 0 for LwIP algorithm.
   - "cubic" or 1 for Cubic algorithm.
   - "disable" or 2 to disable the congestion algorithm.

**Default:** `"lwip" (0)`

### `network.protocols.tcp.linger_0`

> **Type:** boolean
>
> **Maps to:** `XLIO_TCP_ABORT_ON_CLOSE`

Controls whether close() sends RST (abortive) or FIN (graceful) to terminate TCP connections.

**Behavior:**

- *false*: Sends FIN, completes four-way handshake, enters TIME_WAIT (120 seconds).
- *true*: Sends RST immediately, discards TCP state and pending data. No TIME_WAIT.

**Additional abort triggers:** Even when false, XLIO sends RST if application has unread
data in the receive buffer, or SO_LINGER is set with l_linger=0.

**Tradeoffs:**

- *false* (default): Reliable delivery, all pending data transmitted. TIME_WAIT consumes
  memory and ephemeral ports. Keep for data integrity critical
  workloads (databases, file transfers, financial systems).
- *true*: Instant teardown, no TIME_WAIT. Pending data is DISCARDED. Enable when TIME_WAIT
  accumulation limits throughput (10K connections/second → 600K sockets in TIME_WAIT), for
  storage/NVMe workloads, or short-lived connection servers with port exhaustion.

**Auto-enabled by:** nvme_bf3 profile

**Default:** `false`

### `network.protocols.tcp.mss`

> **Type:** integer (range: 0 to 8960)
>
> **Maps to:** `XLIO_MSS`

Global upper bound on TCP segment payload size. Can only **limit** MSS, not increase it.

**How MSS is determined:** The final MSS is the smallest of: configured MSS (if non-zero),
interface MTU minus 40 bytes (IP + TCP headers), and the peer-advertised MSS. The default (0) auto-calculates optimally from interface MTU.

This parameter is rarely needed. Common misconceptions:

- Want jumbo frames? Set interface MTU instead: ip link set dev eth0 mtu 9000
- Want larger segments? MSS cannot exceed interface MTU - 40. Configure MTU, not MSS.
- No XLIO profiles configure this parameter.

When to use (rare edge cases):

- An intermediate link has a smaller MTU than either endpoint.
  Since XLIO does not perform Path MTU Discovery, oversized packets
  are silently dropped. Force a smaller MSS as a workaround.
- Testing/debugging TCP behavior with specific segment sizes.

**Values:**

- 0 (default): Auto-calculate per interface. Correct for nearly all deployments.
- Non-zero: Force upper bound. Actual MSS may still be lower based on interface or peer.

**Maximum value:** 8960.

**Default:** `0`

### `network.protocols.tcp.nodelay.byte_threshold`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_TCP_NODELAY_TRESHOLD`

Effective only if [`network.protocols.tcp.nodelay.enable`](#networkprotocolstcpnodelayenable) is true.
Minimum size (bytes) of the first unsent segment before send; smaller segments
are batched until the threshold is reached.

When non-zero, acts as a hybrid: writes smaller than the threshold
fall back to Nagle's algorithm (buffered until ACK or MSS), while
writes at or above the threshold are sent immediately (standard
nodelay). Useful for applications that send a header and payload as
separate write calls and want them coalesced into a single packet.

**Behavior:** With nodelay enabled, data is sent only when the first unsent
segment length is >= `byte_threshold`; smaller writes are buffered until then.

**Tradeoffs:** 0 (default) = every write sends immediately (standard TCP_NODELAY),
lowest latency, highest packet and CPU overhead. Non-zero = batches small
writes to reduce overhead, adds latency for those writes; values >= maximum
segment size (MSS) make nodelay largely ineffective.

**What value to set:** Use 0 for lowest latency (trading, gaming). For mixed
small and large writes, set slightly below your typical message size to avoid
splitting single messages across packets. For most applications, default 0 is
correct.

**Default:** `0`

### `network.protocols.tcp.nodelay.enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_TCP_NODELAY`

When true, disables Nagle's algorithm at socket init so segments are sent as
soon as possible; when false, small writes are batched.

**Nagle (enable=false):** TCP holds small writes until all prior data is
acknowledged or unsent data reaches one MSS.
Fewer small packets; adds latency; can interact with the remote peer's
delayed ACK to stall write-write-read patterns (by up to the delayed
ACK timeout plus RTT).

**Behavior:** true = send immediately (lowest latency; more packets and CPU).
false (default) = batch until acknowledgement or segment-sized buffer (better
throughput; delayed ACK and RTT can add latency for small writes).

**Tradeoffs:** false (default) = bulk transfer, streaming, file copy; default is
correct for most workloads. true = low-latency or request-response (trading,
gaming, interactive); consider [`network.protocols.tcp.quickack`](#networkprotocolstcpquickack) for symmetric low latency.

**Override:** Per-socket via setsockopt(TCP_NODELAY).

**Default:** `false`

### `network.protocols.tcp.push`

> **Type:** boolean
>
> **Maps to:** `XLIO_TCP_PUSH_FLAG`

Controls whether the TCP PUSH (PSH) flag is set on sent segments, signaling the receiver to deliver data immediately.

**Behavior:** When true, XLIO sets PUSH on sent segments; the
receiver is signaled to deliver data immediately. When false, no PUSH flags are
set; the receiver may buffer until more segments arrive.

**Tradeoffs:** true (default): receiver delivers immediately; lower latency for
request-response and interactive; more delivery events and CPU on receiver. false:
receiver can batch; better throughput for bulk or streaming (used by NGINX
profile); higher latency and can cause timeouts in request-response or interactive.

**What value to set:** Keep default (true) for interactive, request-response, or
mixed workloads; default is correct for most applications. Set false only for
maximum-throughput bulk or streaming where latency is acceptable; re-enable if
you see latency issues or timeouts after disabling.

**Default:** `true`

### `network.protocols.tcp.quickack`

> **Type:** boolean
>
> **Maps to:** `XLIO_TCP_QUICKACK`

Disables TCP delayed acknowledgments, causing immediate ACKs after each received packet.

**Delayed ACKs (when quickack=false):** TCP acknowledges every second
full-size segment immediately (per RFC); if only one segment arrives,
the ACK is deferred until the `timer_msec` timer fires.
LRO/GRO aggregated segments are ACKed immediately as they represent
multiple segments. Reduces ACK packet count by up to 50%.

**Nagle interaction:** When sender uses Nagle (nodelay=false) and receiver uses delayed ACKs,
both wait for each other, causing latency spikes up to the delayed ACK timeout plus RTT. Enable quickack with nodelay for
symmetric low latency.

**Tradeoffs:**

- *false* (default): Efficient for bulk transfers, streaming, high-throughput. ACKs batched,
  lower packet rate and CPU. Adds up to `timer_msec` ACK latency.
- *true*: Lower round-trip latency, faster congestion window growth (more ACKs trigger cwnd
  increases in slow start). Higher packet rate and CPU overhead.

**When to enable:** Latency-sensitive applications (trading, gaming, real-time),
request-response protocols, or when experiencing latency spikes with small messages.

**Override:** Per-socket via setsockopt(TCP_QUICKACK).

**Default:** `false`

### `network.protocols.tcp.timer_msec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_TCP_TIMER_RESOLUTION_MSEC`

Resolution in milliseconds for TCP internal timers.

**Two timer mechanisms:**

- *Fast timer* (fires every timer_msec): Sends delayed ACKs. Maximum ACK delay = timer_msec.
- *Slow timer* (fires every timer_msec × 2): Retransmission timeout detection, persist probes
  (zero-window), keepalive probes, connection state cleanup (FIN_WAIT, TIME_WAIT, etc.).

**Tradeoffs:**

- *Lower (10-50ms):* Faster packet loss detection, lower delayed ACK
  latency when quickack is disabled. Higher CPU overhead and more
  frequent internal thread lock contention from timer processing.
- *Higher (200-500ms):* Lower CPU overhead, less timer thread
  contention, better for high connection counts. Slower loss
  detection, higher ACK latency, less responsive state machine.

**Sizing:** Match to your latency tolerance. Default 100ms balances responsiveness and CPU.
Reduce if delayed ACKs are in use and latency matters. Increase for CPU-constrained servers
with many connections.

**Constraints:**

- Minimum: [`performance.threading.internal_handler.timer_msec`](#performancethreadinginternal_handlertimer_msec) (auto-clamped if set lower)
- Maximum: 500ms per RFC 1122 (delayed ACK must be < 500ms)

**Default:** `100`

### `network.protocols.tcp.timestamps`

> **Type:** integer or string
>
> **Values:** 0/"disable", 1/"enable", 2/"os"
>
> **Maps to:** `XLIO_TCP_TIMESTAMP_OPTION`

Enables the TCP timestamp option (RFC 1323) which adds a 12-byte timestamp field to each
TCP segment header.

**Values:**

- "disable" or 0 (default): Timestamps disabled
- "enable" or 1: Timestamps enabled
- "os" or 2: Follow OS setting (/proc/sys/net/ipv4/tcp_timestamps)

**Limitation:** XLIO's LwIP stack does not implement RFC 1323's Round-Trip Time Measurement
or Protection Against Wrapped Sequences. Timestamps are echoed for peer compatibility but
provide no local benefit.

**Tradeoffs:**

- *Disabled (default):* No header overhead. Recommended since advanced timestamp features
  are not implemented.
- *Enabled:* 12-byte overhead per segment reduces payload efficiency, especially for small
  messages. Only enable for interoperability with peers requiring timestamps.

**Default:** `"disable" (0)`

### `network.protocols.tcp.wmem`

> **Type:** integer (bytes, min: 0) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_TCP_SEND_BUFFER_SIZE`

Maximum data queued for transmission before sender receives ACKs. Memory is allocated per socket.

**Supports suffixes:** B, KB, MB, GB.

**Sizing formula:** For optimal throughput, buffer >= bandwidth × round-trip-time.

**Example:** 10 Gbps link with 1ms RTT = 10 Gbps × 0.001s = 1.25 MB.

**Tradeoffs:**

- *Higher (2MB+):* Better throughput on high bandwidth-delay product networks. Application can
  queue more data without blocking (fewer EAGAIN). Risk: higher memory per socket, bufferbloat
  (increased latency as more data queued before flow control kicks in).
- *Lower (64KB-256KB):* Smaller memory footprint (important with thousands of connections), faster
  flow control feedback, better latency. Risk: may limit throughput on high-latency networks,
  more frequent EAGAIN on non-blocking sockets.

**When to change:** Increase for bulk transfers over high-latency links. Decrease for latency-
sensitive apps or high connection counts. Default 1MB suits most datacenter and LAN environments.

**Override:** Per-socket via setsockopt(SO_SNDBUF). XLIO doubles the
requested value (matching Linux kernel behavior), but counts only
payload bytes (kernel includes metadata overhead). Ultra API ignores
this buffer.

**Auto-modified:** set to 2MB by the nginx and
nginx_dpu profiles ([`profiles.spec`](#profilesspec)).

**Default:** `1MB`

### `network.timing.hw_ts_conversion`

> **Type:** integer or string
>
> **Values:** 0/"disable", 1/"raw_hw", 2/"best_possible", 3/"system", 4/"ptp", 5/"rtc"
>
> **Maps to:** `XLIO_HW_TS_CONVERSION`

Controls how NIC hardware timestamps (HCA clock cycles) are converted to usable time format.

**Global constraint:** If ANY device doesn't support the requested mode, XLIO falls back to
disable for all devices to ensure consistent behavior across interfaces.

**Mode options:**

- "disable" or 0: No timestamps. Zero overhead. SOF_TIMESTAMPING_RAW_HARDWARE returns EPERM.
- "raw_hw" or 1: Converts HCA cycles to seconds.nanoseconds. No timer. Relative time only
  (not comparable to gettimeofday or other hosts). Use for latency deltas, jitter measurement.
- "best_possible" or 2: Auto-selects best supported mode: system → raw_hw → disable.
- "system" or 3 (default): Syncs with CLOCK_REALTIME via 1-second timer. Timestamps comparable
  to gettimeofday(). Best for most applications needing wall-clock time.
- "ptp" or 4: Uses NIC's Precision Time Protocol clock for sub-microsecond accuracy. 100ms
  timer. Requires PTP infrastructure (ptp4l, phc2sys). Falls back to disable if unavailable.
- "rtc" or 5: Native Real-Time Clock format (wall-clock since Unix epoch). Bit manipulation
  only, no timer - fastest wall-clock conversion. Requires ConnectX-6 Dx or newer.
  Falls back to disable if unavailable.

**Performance (overhead low to high):** disable < raw_hw ≈ rtc < system < ptp

**When to change:**

- No timestamps needed: "disable" (0)
- Relative timing only (latency deltas between packets): "raw_hw" (1)
- Wall-clock time for most applications: "system" (3) - default is correct
- Sub-microsecond precision with PTP infrastructure: "ptp" (4)
- Modern hardware (ConnectX-6 Dx+), wall-clock with minimal overhead: "rtc" (5)

**Default:** `"system" (3)`

---

## PERFORMANCE

### `performance.buffers.batching_mode`

> **Type:** integer or string
>
> **Values:** 0/"disable", 1/"enable_and_reuse", 2/"enable"
>
> **Maps to:** `XLIO_BUFFER_BATCHING_MODE`

Controls whether sockets cache RX buffers locally for reuse or return them immediately.
TX buffers are always returned to the ring immediately regardless of this setting.
Batching amortizes lock overhead; reclaim prevents idle sockets from hoarding buffers.

**Values:**

- "disable" or 0: No caching. Every buffer return goes through the ring
  lock. With per-thread ring allocation and no socket migration,
  contention is minimal. Forces
  [`tcp_buffer_batch`](#performanceringstxtcp_buffer_batch)=1, [`udp_buffer_batch`](#performanceringstxudp_buffer_batch)=1. Lowest memory.
- "enable_and_reuse" or 1 (default): Caching with periodic reclaim. Every
  `timer_msec` tick, idle cached buffers are returned to ring. Uses two-phase mechanism: first tick
  marks buffers pending, second tick returns if still unused (prevents returning active buffers).
  Prevents buffer starvation deadlock where idle sockets hold all buffers, blocking FIN packets.
- "enable" or 2: Caching without periodic reclaim. Buffers are still
  returned when the batch threshold is reached, but idle sockets keep
  buffers indefinitely. Lowest latency variance, but risk of buffer
  exhaustion if many sockets go idle.

**Threshold behavior (modes 1 and 2):** Buffers accumulate in socket's local cache until count
reaches the batch threshold, triggering batch return. At 2x threshold, forced immediate return.

**When to change:**

- 0 (disable): Thousands of mostly-idle connections, memory-constrained, or seeing "unable to
  allocate buffer" errors with many idle sockets. Deterministic memory usage for capacity planning.
- 1 (default): Most workloads. Safe default that balances performance with resource efficiency.
- 2 (enable): All sockets continuously active (no idle connections), latency consistency paramount
  (high-frequency trading), memory abundant. Profile first and test under peak load.

**Buffer starvation risk (mode 2):** Without periodic reclaim, idle sockets
hold buffers indefinitely. With Striding Receive Queue (default), each
held buffer pins an entire receive WQE, amplifying the impact. New
connections may fail to allocate buffers; FIN packets cannot be
processed, causing connection leaks. Only use if all sockets remain
active.

**Monitoring:** Run `xlio_stats -p <pid> -v 3` (full view). If "No buffers error:" is non-zero
with mode=2, switch to mode=1 (idle sockets hoarding buffers). If already mode=1, see
[`core.resources.memory_limit`](#coreresourcesmemory_limit) for memory sizing guidance.

**Auto-set to mode 0** by the nginx_dpu profile
([`profiles.spec`](#profilesspec)=nginx_dpu).

**Related:** [`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) controls reclaim frequency in mode 1.

**Default:** `"enable_and_reuse" (1)`

### `performance.buffers.rx.buf_size`

> **Type:** integer (bytes, min: 0, max: 65280) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_RX_BUF_SIZE`

Size of each receive buffer element. Supports suffixes: B, KB, MB, GB.

**With Striding Receive Queue enabled (default):** Does not affect
buffer allocation size (determined by stride settings). However, a
non-zero value caps LRO maximum aggregation size, which may reduce
throughput. Keep at default (0) unless you need to limit LRO
aggregation.

**Without Striding Receive Queue:** Controls actual buffer allocation
size.

**Values:**

- *0* (default): Auto-calculate from max MTU across all interfaces
- *Non-zero*: Force specific size. Clamped to max 65280 bytes.
  Reset to 0 if value <= Maximum Segment Size (MTU - 40).

**When to change:** Without Striding RQ, set to control buffer
allocation. With Striding RQ, set only to limit LRO aggregation.
Otherwise keep default (0).

**Default:** `0`

### `performance.buffers.rx.prefetch_before_poll`

> **Type:** integer
>
> **Maps to:** `XLIO_RX_PREFETCH_BYTES_BEFORE_POLL`

Speculatively prefetches the next expected receive buffer into CPU L1
cache BEFORE polling the Completion Queue, reducing cache-miss latency.

**Differs from [`performance.buffers.rx.prefetch_size`](#performancebuffersrxprefetch_size):** [`performance.buffers.rx.prefetch_size`](#performancebuffersrxprefetch_size) prefetches the current
packet AFTER a completion. This prefetches the NEXT buffer BEFORE
checking for completions. Both can be enabled simultaneously.

**When it helps:** At low packet rates or bursty traffic, CPU evicts
receive buffers from cache between packets. This keeps the next buffer
warm (avoiding cache miss penalties). At sustained
high packet rates, buffers stay warm naturally and this is redundant.

**Sizing:** Default (256) is sufficient for most workloads. Cost: one
prefetch per 64-byte cache line covered by this value (rounded up),
paid even when no packet is waiting.

**Striding Receive Queue:** Value automatically clamped to stride_size.

**Tradeoffs:**

- *0* (default): No overhead. Best for continuous high-throughput traffic.
- *256*: Good for latency-sensitive or bursty workloads. Negligible cost.

**Auto-enabled by:** ultra_latency, latency, and nvme_bf3 profiles (256).

**Range:** 0 (disabled), 32-2044 when enabled.

**Default:** `0`

### `performance.buffers.rx.prefetch_size`

> **Type:** integer (min: 32)
>
> **Maps to:** `XLIO_RX_PREFETCH_BYTES`

Bytes to prefetch into CPU L1 cache after polling a Completion Queue
Entry, so the subsequent memcpy to user space during recv() hits warm
cache instead of causing L1 misses.

**How it works:** After finding a packet completion, XLIO issues
one prefetch instruction per 64-byte cache line, starting after the
Ethernet header. The first prefetched bytes are protocol headers
(IP + TCP/UDP), not application payload.

**Sizing:** Default (256) is sufficient for most workloads.
Prefetching beyond packet size wastes instructions but is otherwise
harmless.

**Tradeoffs:**

- *Lower (32-128):* Minimal overhead but mostly prefetches headers,
  not payload. Use at millions of packets per second where per-packet
  instruction cost matters.
- *256* (default): Good balance for mixed workloads.
- *Higher (512-2044):* More payload pre-warmed. Better for large
  packets. Higher per-packet instruction cost and L1 cache pressure.

**When ineffective:** If packets queue in the ready list before the
application calls recv(), L1 data gets evicted before being read.
Common in worker thread mode where prefetch and recv() run on
different threads with timing gaps exceeding ~10 microseconds.

**Related:** [`prefetch_before_poll`](#performancebuffersrxprefetch_before_poll) prefetches the NEXT buffer BEFORE
polling (speculative). This prefetches the CURRENT packet AFTER
completion. Both can be enabled simultaneously.

**Range:** 32-2044.

**Default:** `256`

### `performance.buffers.tcp_segments.pool_batch_size`

> **Type:** integer (min: 1)
>
> **Maps to:** `XLIO_TX_SEGS_POOL_BATCH_TCP`

Number of TCP segment structures allocated from heap in a single
expansion when the global TCP segment pool is exhausted. Pool only grows; memory
is never returned until process exit.

**Caching hierarchy:** Sockets fetch from ring caches
([`socket_batch_size`](#performancebufferstcp_segmentssocket_batch_size), default 64), rings fetch from global pool
([`ring_batch_size`](#performancebufferstcp_segmentsring_batch_size), default 1024), global pool expands by
pool_batch_size. Each tier reduces lock contention on the tier below.

**Memory per expansion:** With the default value, each expansion
allocates approximately 2-4 MB. With hugepages (default), allocation
rounds up to hugepage boundaries, so the actual segment count per
expansion may exceed the configured value.

**Tradeoffs:**

- *Higher:* Fewer pool expansions (each acquires global spinlock),
  lower latency variance during startup and traffic spikes. More
  memory upfront.
- *Lower:* Smaller footprint, gradual growth. More pool expansions
  under load cause brief latency hits from heap allocation and
  spinlock.

**Default:** `16384`

### `performance.buffers.tcp_segments.ring_batch_size`

> **Type:** integer (min: 1)
>
> **Maps to:** `XLIO_TX_SEGS_RING_BATCH_TCP`

Segments a ring fetches at once from the global TCP segment pool.
Middle tier of the 3-level cache: sockets fetch from rings
([`socket_batch_size`](#performancebufferstcp_segmentssocket_batch_size)), rings from global pool (this parameter),
pool expands from heap ([`pool_batch_size`](#performancebufferstcp_segmentspool_batch_size)). When a ring
accumulates > 2 x `ring_batch_size` segments, half are returned
(hysteresis).

**Tradeoffs:**

- *Higher:* Fewer global pool lock acquisitions, lower send
  latency variance. More memory per ring.
- *Lower:* Less memory, faster redistribution across rings.
  More global spinlock contention may increase send latency
  variance.

Default is sufficient for most per_thread deployments.

**Default:** `1024`

### `performance.buffers.tcp_segments.socket_batch_size`

> **Type:** integer (min: 1)
>
> **Maps to:** `XLIO_TX_SEGS_BATCH_TCP`

Segments a socket fetches from its ring cache
at once. Top tier of the 3-level segment cache (socket > ring >
global pool). Socket access is lock-free; only ring refills
acquire the per-ring lock.

**Return:** Excess segments returned to ring when count exceeds
2 x `socket_batch_size` and fewer than half are in active use.

**Value of 1:** Bypasses caching; each send acquires ring lock.
Better CPU cache locality for single-stream latency workloads
only.

**Tradeoffs:**

- *Higher (64-256):* Fewer ring lock acquisitions, better
  throughput. Higher memory per connection.
- *Lower (2-16):* Less memory, faster redistribution. More
  ring lock contention under high send rates.
- *1:* Best CPU cache for single-stream. Every send touches
  ring lock.

Default is sufficient for most workloads.

**Default:** `64`

### `performance.buffers.tx.buf_size`

> **Type:** integer (bytes, min: 0, max: 256KB) or string with size suffix (B, KB, MB, GB)
>
> **Maps to:** `XLIO_TX_BUF_SIZE`

Size of each transmit buffer element (allocated as buf_size + 92
bytes for Ethernet/IP/TCP headers). Supports suffixes: B, KB, MB, GB.

**Values:**

- 0 (default): Auto-calculate as Maximum Segment Size (MTU - 40).
  Standard MTU 1500 gives ~1460 bytes; jumbo MTU 9000 gives ~8960.
- Non-zero: Force specific size. Clamped to max 256KB.
  Reset to 0 if value <= Maximum Segment Size.

**TCP Segmentation Offload interaction:** Maximum data per TSO segment is the smaller of this buffer size and the TSO max payload size.
Without TCP Segmentation Offload, segments stay at Maximum Segment
Size regardless of buffer size — setting a larger value only wastes
memory.

**Sizing:** For non-zerocopy heavy TX workloads, increase to improve
TSO utilization (64KB+ for bulk transfers). For TLS TX offload,
16KB is optimal (matches TLS record size). For zerocopy sends
without TLS, keep default (0) to minimize memory.

**Tradeoffs:**

- 0/auto: Lowest memory. TCP Segmentation Offload limited to one
  Maximum Segment Size per TSO segment, limiting bulk throughput.
- 64KB+: Full TCP Segmentation Offload utilization, fewer buffer
  allocations, higher throughput. More memory per buffer.

**Auto-modified by:** [`worker_threads`](#performancethreadingworker_threads) > 0 forces 256KB.

**Default:** `0`

### `performance.buffers.tx.prefetch_size`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_TX_PREFETCH_BYTES`

Bytes to prefetch into CPU L1 cache before writing headers and
payload to UDP transmit buffers, reducing write-stall latency
from cache misses.

**Scope:** UDP send path only. Inline sends (payload + headers <
[`max_inline_size`](#performanceringstxmax_inline_size)) bypass TX buffer copy, making prefetch
irrelevant.

**How it works:** Before copying into a TX buffer, XLIO issues
one prefetch instruction per 64-byte cache line covered by
this value (rounded up). The actual prefetch is limited to
the payload size. 0 disables.

**Sizing:** Default (256) is sufficient for most workloads. Increase
for large-payload UDP (jumbo frames). Reduce or disable if profiling
shows prefetch overhead at high packet rates.

**Tradeoffs:**

- 0: No overhead. Risk: CPU write-stalls on cold TX buffers.
- 256 (default): Good balance for small-to-medium payloads.
- Higher: Warms more buffer for large payloads. Risk: L1 cache
  pollution and instruction overhead at high packet rates.

**Default:** `256`

### `performance.completion_queue.interrupt_moderation.adaptive_change_frequency_msec`

> **Type:** integer
>
> **Maps to:** `XLIO_CQ_AIM_INTERVAL_MSEC`

Interval in milliseconds between adaptive interrupt moderation
recalculations.

**How it works:** A periodic timer measures packets received per ring
over this interval, computes the average packet rate, and adjusts
hardware Completion Queue moderation count and period. Computed values
are capped by [`adaptive_count`](#performancecompletion_queueinterrupt_moderationadaptive_count) and [`adaptive_period_usec`](#performancecompletion_queueinterrupt_moderationadaptive_period_usec).

**Value of 0:** Disables adaptive moderation entirely. Moderation uses
static [`packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count) and [`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec) values only.

**Dependency:** Forced to 0 (disabled) if [`performance.completion_queue.interrupt_moderation.enable`](#performancecompletion_queueinterrupt_moderationenable)
is false, or if polling modes make interrupts inapplicable.

**Sizing:** Match to how quickly your traffic rate changes. The
algorithm needs one full interval to measure the new rate before
adapting. Connections that close before one interval elapses never
benefit; for short-lived connections, tune [`packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count) and
[`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec) instead.

**Tradeoffs:**

- *Lower (e.g., 250ms):* Faster adaptation when traffic rate shifts
  frequently. Slightly more overhead from recalculations.
- *Higher (e.g., 2000ms):* Stable settings, less overhead. May miss
  brief traffic rate changes.
- *Default (1000ms):* Sufficient for most workloads.

**Auto-disabled by:** nvme_bf3 profile.

**Default:** `1000`

### `performance.completion_queue.interrupt_moderation.adaptive_count`

> **Type:** integer
>
> **Maps to:** `XLIO_CQ_AIM_MAX_COUNT`

Caps the maximum packet count the adaptive interrupt moderation
algorithm can set per interrupt cycle.

**How it works:** The adaptive algorithm divides the measured packet rate
by the target interrupt rate, then caps the result at this value. Higher
values allow more packets batched per interrupt under heavy traffic.

**Hardware cap:** Also clamped at startup to half of the total receive
completion capacity (determined by strides per element and receive queue
depth with Striding Receive Queue, or receive queue depth alone without).

**Sizing:** Set to peak_packet_rate / [`adaptive_interrupt_per_sec`](#performancecompletion_queueinterrupt_moderationadaptive_interrupt_per_sec) to
allow full adaptive range without capping. Example: 5 million packets
per second with default 10000 interrupts per second = 500, which the
default handles. Only increase if your peak rate requires it.

**Tradeoffs:**

- *Higher:* More batching under heavy traffic, fewer interrupts,
  lower CPU. Risk: worst-case interrupt latency grows proportionally.
- *Lower:* Bounds maximum batching even during bursts. More
  predictable latency at higher CPU cost under heavy traffic.

**Dependency:** Only effective when interrupt moderation is enabled
and [`adaptive_change_frequency_msec`](#performancecompletion_queueinterrupt_moderationadaptive_change_frequency_msec) > 0.

**Default:** `500`

### `performance.completion_queue.interrupt_moderation.adaptive_interrupt_per_sec`

> **Type:** integer
>
> **Maps to:** `XLIO_CQ_AIM_INTERRUPTS_RATE_PER_SEC`

Target interrupt rate for the adaptive moderation algorithm. Primary
knob for the latency-versus-CPU tradeoff.

**How it works:** Each adaptive interval, the algorithm divides the
measured packet rate by this value to compute the moderation packet
count (capped by [`adaptive_count`](#performancecompletion_queueinterrupt_moderationadaptive_count)), and derives a coalescing period
(capped by [`adaptive_period_usec`](#performancecompletion_queueinterrupt_moderationadaptive_period_usec)).
The NIC interrupts when the computed packet count accumulates OR the
computed period elapses, whichever comes first.

**Sizing:** 1000000 / value = target microseconds between interrupts.
If you need interrupts every N microseconds, set value = 1000000 / N.
Default (10000) targets ~100 microsecond intervals, sufficient for
most general-purpose workloads.

**Tradeoffs:**

- *Higher (e.g., 20000 = 50 microsecond intervals):* Lower latency,
  higher CPU usage. Better for request-response workloads.
- *Lower (e.g., 2000 = 500 microsecond intervals):* Lower CPU,
  higher latency. Better for streaming and bulk transfers.

For ultra-low-latency workloads (trading, real-time control),
disable moderation entirely ([`performance.completion_queue.interrupt_moderation.enable`](#performancecompletion_queueinterrupt_moderationenable)=false)
rather than setting a very high value here.

**Dependency:** Only effective when [`performance.completion_queue.interrupt_moderation.enable`](#performancecompletion_queueinterrupt_moderationenable) is
true and [`adaptive_change_frequency_msec`](#performancecompletion_queueinterrupt_moderationadaptive_change_frequency_msec) > 0.

**Default:** `10000`

### `performance.completion_queue.interrupt_moderation.adaptive_period_usec`

> **Type:** integer
>
> **Maps to:** `XLIO_CQ_AIM_MAX_PERIOD_USEC`

Caps the maximum hold time (microseconds) the adaptive moderation
algorithm can configure for Completion Queue interrupt coalescing.

**How it works:** The algorithm computes the ideal coalescing period from
the target interrupt rate and measured packet rate, then caps it at this
value. This parameter bounds worst-case latency. Under steady traffic,
count thresholds typically trigger before the period expires, so
actual latency is usually well below this cap.

**Sizing:** Set to your maximum tolerable interrupt delay in
microseconds. Default (1000 = 1 millisecond) is sufficient for
most workloads. Only reduce if worst-case latency matters more
than CPU efficiency (e.g., 250-500 for latency-sensitive apps).

**Tradeoffs:**

- *Lower (250-500):* Tighter worst-case latency bound. May cause
  unnecessary interrupts when traffic is near the target rate.
- *Higher (2000-5000):* More algorithm flexibility, better CPU
  efficiency. Risk: latency spikes when traffic drops.

**Dependency:** Only effective when [`performance.completion_queue.interrupt_moderation.enable`](#performancecompletion_queueinterrupt_moderationenable) is
true and [`adaptive_change_frequency_msec`](#performancecompletion_queueinterrupt_moderationadaptive_change_frequency_msec) > 0.

**Default:** `1000`

### `performance.completion_queue.interrupt_moderation.enable`

> **Type:** boolean
>
> **Maps to:** `XLIO_CQ_MODERATION_ENABLE`

Master switch for Completion Queue interrupt moderation. When enabled,
the NIC batches completion notifications and generates interrupts based
on [`packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count) and [`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec) thresholds rather than per-packet.

**Tradeoffs:**

- *true* (default): Hardware coalesces interrupts. Lower CPU usage at
  the cost of added latency (bounded by [`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec), default
  50 microseconds). Adaptive algorithm dynamically adjusts thresholds
  when [`adaptive_change_frequency_msec`](#performancecompletion_queueinterrupt_moderationadaptive_change_frequency_msec) > 0.
- *false*: Per-packet interrupts for lowest latency. Higher CPU overhead
  from interrupt processing. Also disables adaptive moderation entirely.

**Auto-disabled by:** ultra_latency and latency profiles (they set
[`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec)=-1 for continuous polling, making interrupt-driven
notification redundant). Setting [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) or
[`performance.polling.iomux.poll_usec`](#performancepollingiomuxpoll_usec) to -1 manually has the same effect. Explicit user
override still takes precedence.

**When to disable:** Ultra-low-latency applications (trading, real-time
systems) where sub-millisecond added latency from batching is
unacceptable. For most workloads, keep enabled.

**Default:** `true`

### `performance.completion_queue.interrupt_moderation.packet_count`

> **Type:** integer
>
> **Maps to:** `XLIO_CQ_MODERATION_COUNT`

Number of packet completions to accumulate before the NIC generates
an interrupt.

**Dual role:** Initial value when moderation is first enabled, and
fallback when adaptive moderation detects zero traffic (resets
hardware to this count + [`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec) defaults).

**Trigger:** The NIC interrupts when EITHER this count is reached
OR [`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec) expires, whichever comes first. Under heavy traffic,
count is usually reached first; under light traffic, [`period_usec`](#performancecompletion_queueinterrupt_moderationperiod_usec)
acts as the safety net.

**Maximum cap:** Clamped at startup to half of the total receive
completion capacity (determined by strides per element and receive
queue depth with Striding Receive Queue, or receive queue depth
alone without).

**Sizing:** The adaptive algorithm (when
[`adaptive_change_frequency_msec`](#performancecompletion_queueinterrupt_moderationadaptive_change_frequency_msec) > 0) overrides this value
dynamically, so it mainly matters during startup and when traffic
drops to zero. Set to your desired packets-per-interrupt for those
transition periods. Default (48) is a balanced starting point.

**Tradeoffs:**

- *Lower:* More frequent interrupts, lower latency, higher CPU
  overhead from interrupt processing.
- *Higher:* Fewer interrupts, better CPU efficiency, packets wait
  longer before processing.

**Default:** `48`

### `performance.completion_queue.interrupt_moderation.period_usec`

> **Type:** integer
>
> **Maps to:** `XLIO_CQ_MODERATION_PERIOD_USEC`

Maximum time in microseconds the NIC holds a completed packet before
generating an interrupt. Acts as a safety net: even if traffic is too
light to reach [`packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count), an interrupt fires within this period.

**Dual role:** Initial value when moderation is first enabled, and
fallback value when adaptive moderation detects zero traffic
(resets hardware to this period + [`packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count) defaults).

**Sizing:** Set to your maximum tolerable interrupt delay in
microseconds. Under heavy traffic, [`packet_count`](#performancecompletion_queueinterrupt_moderationpacket_count) is usually reached
first, so actual latency is well below this value. This parameter
mainly affects light or bursty traffic where packets arrive slower
than the count threshold.

**Tradeoffs:**

- *Lower (e.g., 25):* Tighter worst-case latency bound under light
  traffic. Higher interrupt rate when few packets arrive, more CPU
  overhead from interrupt processing.
- *Higher (e.g., 500):* Better CPU efficiency, fewer interrupts.
  Risk: packets held up to this many microseconds under light traffic,
  adding noticeable latency.

Default (50) keeps worst-case interrupt delay under 50 microseconds,
sufficient for most workloads. For ultra-low-latency requirements,
consider disabling moderation entirely (enable=false) rather than
using very low values.

**Default:** `50`

### `performance.completion_queue.keep_full`

> **Type:** boolean
>
> **Maps to:** `XLIO_CQ_KEEP_QP_FULL`

Controls how XLIO handles buffer shortages when replenishing the
hardware Receive Queue after processing received packets.

**Behavior:** XLIO tracks a "debt" of consumed-but-not-replenished
buffers.

- *true* (default): Replenish after every packet. If no buffers
  available, re-post the same buffer (packet data is dropped) to
  keep the Receive Queue at full capacity. Drops are counted in
  xlio_stats "SW RX Packets dropped:".
- *false*: Accumulate debt and batch-replenish later. No drops
  unless debt reaches the full queue size (all posted buffers
  consumed). Lower per-packet CPU overhead and latency jitter.

**Tradeoffs:**

- *true*: Receive Queue always full, best for bursty traffic or
  throughput workloads. Risk: software packet drops under memory
  pressure (visible in xlio_stats).
- *false*: Batched replenishment, lower CPU and jitter. Receive
  Queue may temporarily have fewer buffers. Risk: hardware drops
  if sustained traffic outpaces replenishment. Mitigate with
  larger [`spare_buffers`](#performanceringsrxspare_buffers) and ring_elements_count.

**Symptom of wrong setting:** Rising "SW RX Packets dropped:" in
xlio_stats means buffers are scarce - increase [`spare_buffers`](#performanceringsrxspare_buffers) or
[`core.resources.memory_limit`](#coreresourcesmemory_limit) before switching to false.

**Auto-set to false by:** ultra_latency, latency, nvme_bf3 profiles.

**Default:** `true`

### `performance.completion_queue.periodic_drain_max_cqes`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_PROGRESS_ENGINE_WCE_MAX`

Maximum Completion Queue Entries processed per periodic drain by
the internal thread. Does NOT affect application-path polling
(controlled by [`performance.polling.max_rx_poll_batch`](#performancepollingmax_rx_poll_batch), default 16).

**How it works:** Every [`periodic_drain_msec`](#performancecompletion_queueperiodic_drain_msec), the internal thread
attempts to lock each ring (non-blocking) and drains up to this many
completions. The lock is held for the entire drain of each ring.

**Latency impact:** Lock hold time scales linearly with max_cqes.
High values can block application threads on the same ring under
heavy load. Reduce to bound jitter.

**Sizing:** Match to acceptable worst-case lock hold time:

- Latency-sensitive: 100-500 (lock hold 10-250 microseconds)
- Throughput: 10000 (default, clears backlogs efficiently)
- Apps that poll sockets frequently: 0 (disables periodic
  draining; same effect as [`periodic_drain_msec`](#performancecompletion_queueperiodic_drain_msec)=0)

**Monitoring:** In xlio_stats, "Drained max:" shows peak
completions per drain. If it consistently equals this value,
consider increasing.

**Pair with:** [`periodic_drain_msec`](#performancecompletion_queueperiodic_drain_msec) (either set to 0 disables).

**Default:** `10000`

### `performance.completion_queue.periodic_drain_msec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_PROGRESS_ENGINE_INTERVAL`

Interval (milliseconds) at which XLIO's internal thread polls all
Completion Queues, independently of application socket calls.

TCP requires execution context for ACKs, retransmissions, window
updates, and keepalives. If the application has idle phases between
socket calls, this timer prevents TCP stalls. If the application
already drained the Completion Queue, the thread returns immediately
(no redundant work).

**Sizing:** Match to the longest gap between the application's
socket API calls. Tight event loops or busy-poll should disable (0).

**Tradeoffs:**

- *10* (default): Balanced for most applications.
- *Lower:* Faster retransmission detection during application idle
  phases. Higher CPU and lock contention with application threads.
- *Higher:* Lower CPU. Risk: TCP throughput drops if the
  application goes idle longer than the interval.
- *0*: No background overhead. Application MUST poll frequently.

**Auto-modified by:** ultra_latency (0), latency (100),
nginx/nginx_dpu (0), nvme_bf3 (0), worker threads mode (0),
delegate TCP timers mode (0).

**Monitoring:** In xlio_stats, "Drained max:" per ring.
Consistently 0 = safe to disable. Consistently high = do not
increase.

**Default:** `10`

### `performance.completion_queue.rx_drain_rate_nsec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_RX_CQ_DRAIN_RATE_NSEC`

UDP only. Minimum interval (nanoseconds) between forced Completion
Queue polls when the socket's ready queue already has packets.

**Behavior:** When a UDP recv() finds packets already queued:

- *0* (default): Returns immediately. Only polls when queue is empty.
- *Non-zero*: Polls the Completion Queue if at least this many
  nanoseconds elapsed since the last poll. Otherwise returns
  from the ready queue immediately.

**Global timestamp:** The last-poll time is shared across ALL UDP
sockets in the process. Any socket's poll resets the timer for all
others, naturally throttling poll rate with many active sockets.

**Sizing:** Set to the maximum staleness your application tolerates.
At millions of recv()
calls per second, even small values add measurable CPU overhead.

**Recommended range when enabled:** 100-5000 nanoseconds.

**Tradeoffs:**

- *0* (default): Lowest latency, no extra CPU. Application may miss
  recently-arrived packets until the ready queue empties. Sufficient
  for single-threaded apps or apps that drain sockets completely.
- *Non-zero:* Periodic Completion Queue refresh for more accurate
  queue state. Required for multi-threaded UDP where threads must
  see packets arriving during another thread's work.

**Default:** `0`

### `performance.max_gro_streams`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_GRO_STREAMS_MAX`

Maximum TCP flows per ring using software Generic Receive Offload.
Coalesces consecutive segments from the same flow into larger
packets (up to 32 segments or ~64KB), reducing per-packet CPU
overhead. Flows exceeding the limit bypass aggregation.

**Sizing:** Match to concurrent bulk-transfer TCP flows per ring.
Only flows with pending packets consume slots; idle connections
do not. Default (32) handles most server workloads.

**Tradeoffs:**

- *0*: Disabled. Lowest per-packet latency, higher CPU. Use when
  latency-sensitive or Large Receive Offload already coalesces.
- *32* (default): Typical server workloads (web, proxy).
- *128+*: Many concurrent bulk flows per ring.

**Symptom of too-low value:** In xlio_stats, "GRO frags per
packet" near 1.0 means flows exceed slots or are out of order.
Large Receive Offload (hardware) aggregates before Generic Receive
Offload (software); both work together.

**Auto-disabled by:** ultra_latency, latency, nginx, nginx_dpu,
and nvme_bf3 profiles.

**Default:** `32`

### `performance.override_rcvbuf_limit`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_RX_BYTES_MIN`

Minimum UDP socket receive buffer limit (bytes). When an application
sets SO_RCVBUF below this value, XLIO overrides it. Does not affect
TCP sockets (TCP uses flow control via the receive window instead).

**Behavior:** UDP packets queue until the application calls recv().
When queued bytes reach the limit, new packets are silently dropped.
effective_limit = max(SO_RCVBUF x 2, `override_rcvbuf_limit`)
(Linux doubles SO_RCVBUF internally; XLIO applies the same convention.)
Value of 0 disables the minimum; the application's SO_RCVBUF is used
directly.

**Sizing formula:** buffer >= arrival_rate x max_stall_time.
Example at 10 Gbps with 1500-byte packets (~833K packets per second):
64KB holds ~52 microseconds, 1MB holds ~820 microseconds of data.
Size to cover the longest gap between recv() calls (including garbage
collection pauses, context switches, or computation phases).

**Tradeoffs:**

- *Lower (8-16KB):* Less latency (stale data discarded), lower memory.
  Risk: drops during any processing hiccup.
- *64KB* (default): Handles typical jitter (~40-50 full-size packets).
  Sufficient for most general-purpose UDP applications.
- *Higher (256KB+):* Absorbs bursts when application temporarily stalls.
  Risk: stale data buffered, higher per-socket memory.

**Monitoring:** In xlio_stats per-socket output, check
"Rx byte: cur X / max Y / dropped Z". Non-zero "dropped" means
packets are being lost -- increase the limit or improve consumption
rate. At socket close, XLIO logs "Rx byte : max X / dropped Y (Z%)".

**Default:** `65536`

### `performance.polling.blocking_rx_poll_usec`

> **Type:** integer (range: -1 to 100000000)
>
> **Maps to:** `XLIO_RX_POLL`

Busy-poll loop count on the hardware Completion Queue before
switching to interrupt-driven sleep. Despite the name, this is
a loop count, not microseconds.

On blocking recv()/read(), XLIO loops up to this count checking
for completions (sub-microsecond return on hit). When exhausted,
arms interrupts and sleeps (added wakeup latency). Non-blocking sockets always perform exactly 1 poll.

**Special values:** -1 = infinite polling (never sleeps, 100%
CPU -- pin thread to a dedicated core). 0 = converted to 1
(at least one poll before sleeping).

**Sizing:** Higher values trade CPU for lower latency. Default
(100000) ≈ 10-50ms busy-wait, sufficient for most workloads.
Use -1 when latency is critical and dedicated cores are
available. Decrease to 1000-10000 when CPU is constrained.

**Symptoms:** Too high: receive thread at 100% CPU during idle.

**Too low:** elevated latency; in xlio_stats full view (mode 3),
"Rx poll: X / Y (Z%) [miss/hit]" shows >50% miss rate.

**Auto-modified by:** ultra_latency (-1), latency (-1).

**Default:** `100000`

### `performance.polling.iomux.poll_os_ratio`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_SELECT_POLL_OS_RATIO`

Controls how often XLIO checks the OS for non-offloaded file
descriptors during the Completion Queue polling loop of
select()/poll()/epoll_wait().

**Mechanism:** A countdown starts at this value, decrements each
Completion Queue poll. At zero, a zero-timeout OS syscall checks
non-offloaded file descriptors, then resets.

**Sizing:**

- **0:** OS never polled; non-offloaded file descriptors only
  checked entering blocking mode (starvation risk).
  Set by the "ultra_latency" profile.
- **Higher:** Fewer syscalls, longer non-offloaded gaps.
  The "latency" profile uses 100.

**Cause-effect:**

- *Too low:* Excessive kernel transitions per OS poll, higher
  latency variance for offloaded traffic.
- *Too high:* Non-offloaded traffic (timers, signals,
  non-offloaded sockets) becomes unresponsive.

For most mixed workloads, the default (10) is sufficient. Tune
lower for non-offloaded responsiveness, higher for latency.

**Related:** [`skip_os`](#performancepollingiomuxskip_os) (OS priority per N calls),
[`poll_usec`](#performancepollingiomuxpoll_usec) (polling duration).

**Default:** `10`

### `performance.polling.iomux.poll_usec`

> **Type:** integer (range: -1 to 100000000)
>
> **Maps to:** `XLIO_SELECT_POLL`

Controls how long (in microseconds) XLIO busy-polls the
hardware Completion Queue during select()/poll()/epoll_wait()
before arming interrupts and sleeping.

**Mechanism:** Polls the Completion Queue for up to this many
microseconds (capped by the application timeout). On expiry
without data, arms Completion Queue interrupts and sleeps.

- **-1:** Infinite polling; never sleeps; 100% CPU. Set by
  "ultra_latency" and "latency" profiles. Auto-disables
  Completion Queue interrupt moderation.
- **0:** Single poll then sleep (interrupt-driven). Set by
  the nginx profile ([`profiles.spec`](#profilesspec)).

**Sizing:** Match to expected packet inter-arrival time.
Monitor "Polls [miss/hit]" in xlio_stats: a high miss
rate means the budget exceeds traffic frequency, wasting
CPU spinning before every sleep transition.

**Cause-effect:**

- *Too low:* Frequent misses cause interrupt + context-switch
  latency on each wakeup.
- *Too high / -1:* Thread spins idle, starving co-located
  threads on the same core.

For most workloads the default (100000 = 100 milliseconds)
is sufficient. Use -1 only with dedicated CPU cores.

**Auto-set to -1** in threads mode.

**Related:** [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) (same for recv()/read()),
[`poll_os_ratio`](#performancepollingiomuxpoll_os_ratio) (OS polling within the busy-poll loop).

**Default:** `100000`

### `performance.polling.iomux.skip_os`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_SELECT_SKIP_OS`

Controls how often the OS gets first-priority polling at the
start of select()/poll()/epoll_wait(), before checking
offloaded sockets.

**Mechanism:** A counter resets to this value after each
OS-priority poll and decrements every iomux call. At zero,
the OS is polled first; otherwise [`poll_os_ratio`](#performancepollingiomuxpoll_os_ratio) governs
the Completion Queue-to-OS ratio within the polling loop.

**Effective frequency:** one OS-priority poll every N calls.

**Sizing:**

- **0 or 1:** OS gets priority every call (most overhead).
  Set by the "ultra_latency" profile (0).
- **Higher values:** Fewer OS-priority polls per sequence.
  The nginx profile ([`profiles.spec`](#profilesspec)) uses 1000.

**Cause-effect:**

- *Too low:* Syscall on each iomux entry; offloaded packets
  wait while OS is checked first.
- *Too high:* Non-offloaded file descriptors (timers,
  signals, pipes) wait longer for priority checks.

For most mixed workloads the default (4, meaning OS
priority every fourth call) is sufficient. Increase for
offloaded-dominant workloads; decrease if non-offloaded
responsiveness is critical.

**Related:** [`poll_os_ratio`](#performancepollingiomuxpoll_os_ratio) (Completion Queue-to-OS ratio
within polling loops), [`poll_usec`](#performancepollingiomuxpoll_usec) (polling phase duration).

**Default:** `4`

### `performance.polling.max_rx_poll_batch`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_CQ_POLL_BATCH_MAX`

Maximum packets drained from the Completion Queue per
recv()/select()/poll()/epoll_wait() call. Range: 1-32768.

**Mechanism:** Drains the software receive queue then
hardware Completion Queue up to this limit, flushes TCP
segment coalescing, and returns. Re-polls when the limit
is reached (Completion Queue not fully drained).

**Sizing:** Only matters when packets arrive faster than
the application consumes; otherwise the queue empties
before the limit. Default (16) suits most workloads.

- **Latency-sensitive:** 4-8. Delivers first queued
  packet sooner; holds ring lock briefly.
- **Throughput-oriented:** 64-256. Amortizes per-call
  overhead (lock, TCP segment coalescing flush).
- **Shared rings:** 8-32 to limit ring lock hold time.

**Cause-effect:**

- *Too low:* More poll calls, lock acquisitions, flushes;
  lower peak throughput.
- *Too high:* First-packet latency and jitter increase;
  ring lock starves threads on shared rings.

**Set to 128** by the nginx profile
([`profiles.spec`](#profilesspec)=nginx).

**Related:** [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) (recv() poll duration),
[`hardware_features.tcp.lro`](#hardware_featurestcplro) (larger batches improve coalescing).

**Default:** `16`

### `performance.polling.nonblocking_eagain`

> **Type:** boolean
>
> **Maps to:** `XLIO_TX_NONBLOCKED_EAGAINS`

Controls the return value when a non-blocking UDP send
cannot allocate transmit buffers (sends outpace
completions). Only affects UDP sockets.

- **false** (default): Returns success (byte count) and
  silently discards the datagram. The application receives
  no indication of the drop.
- **true:** Returns -1 with errno EAGAIN, letting the
  application apply backpressure or log the drop.

For most applications the default (false) is sufficient;
fire-and-forget senders expect silent drops. Enable (true)
only when the application handles EAGAIN on send and needs
explicit feedback for flow control or loss monitoring.

**Monitoring:** In xlio_stats per-socket view, the "eagain"
column of the "Tx:" row counts returns (meaningful only
when enabled). Ring-level drops from a full Send Queue
appear as "TX Dropped Send Reqs:" in ring stats.

**Related:** [`performance.rings.tx.ring_elements_count`](#performanceringstxring_elements_count) (transmit queue depth),
[`udp_buffer_batch`](#performanceringstxudp_buffer_batch) (buffers fetched per send batch).

**Default:** `false`

### `performance.polling.offload_transition_poll_count`

> **Type:** integer (range: -1 to 100000000)
>
> **Maps to:** `XLIO_RX_POLL_INIT`

Busy-poll iterations for UDP blocking sockets while
no rings are attached. Non-blocking sockets always poll once.

**Mechanism:** New UDP sockets start with this count for
blocking recv()/recvfrom(). While no rings are attached,
the receive path loops, sampling the OS socket and polling
any Completion Queues that exist. When a ring attaches
(ADD_MEMBERSHIP or flow steering), [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec)
takes over. If all rings detach, reverts to this value.
Applies to passthrough/non-offloaded sockets where rings
never attach.

**Sizing:**

- **UDP multicast:** Default (0) is sufficient; transition
  (creation to ADD_MEMBERSHIP) is typically brief.
- **UDP unicast (offloaded):** Only applies before rings
  attach (socket() to bind/connect) or after all rings detach.
- **UDP unicast (passthrough/non-offloaded):** Controls
  lifetime busy-poll budget before epoll wait.
- **-1:** Infinite polling; 100% CPU. Dedicated cores only.
- **0:** No polling; immediate interrupt-driven wait.

**Cause-effect:**

- *Too low / 0:* recv() falls to epoll wait sooner
  (added wakeup latency per call).
- *Too high / -1:* CPU spins, starving co-located threads.

**Related:** [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) (takes over post-ring
attach), [`yield_on_poll`](#performancepollingyield_on_poll) (CPU yielding during poll loop).

**Default:** `0`

### `performance.polling.rx_cq_wait_ctrl`

> **Type:** boolean
>
> **Maps to:** `XLIO_RX_CQ_WAIT_CTRL`

Controls whether Completion Queue channel file descriptors are registered
permanently or on-demand on each socket's internal epoll descriptor
used for blocking receives. These file descriptors must be on the epoll
so the socket wakes when packets arrive on a shared ring.

**Tradeoffs:**

- *false* (default): Registered permanently when ring is associated.
  One syscall per blocking wait. Kernel wakeup cost is O(total sockets
  sharing the ring) -- at 100,000+ connections this causes high kernel
  CPU (%sy in top) and latency spikes.
- *true*: Registered before sleep, removed on wakeup. Three syscalls
  per blocking wait (add + wait + remove). Kernel wakeup cost is
  O(sleeping sockets only) -- scales at any connection count but adds
  overhead when few connections exist.

Enable when many sockets share few rings (per_interface or per_thread
allocation) and connections exceed ~10,000. Symptoms: high kernel CPU
with many idle connections, latency spikes scaling with connection
count. For fewer than 10,000 connections, per_socket ring allocation,
or primarily non-blocking I/O, the default (false) is sufficient.

**Auto-enabled** by the nginx and nginx_dpu profiles
([`profiles.spec`](#profilesspec)=nginx or nginx_dpu).

**Default:** `false`

### `performance.polling.rx_kernel_fd_attention_level`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_RX_UDP_POLL_OS_RATIO`

Number of Completion Queue polls between each OS kernel
socket check (ioctl FIONREAD) during UDP receive. Set to
0 to disable OS checking during polling entirely.

A per-socket counter increments each Completion Queue
poll; at this threshold XLIO checks the OS socket for
pending data and falls back to OS receive if found. After
a successful OS read, the next receive re-checks
immediately. Even with offloading, some UDP traffic
reaches the OS (packets bypassing flow steering, IP
fragments, traffic before multicast join).

**Sizing:** Value = Completion Queue polls per OS check.
Lower catches non-offloaded packets faster; higher
reduces ioctl syscall overhead.

- *0:* OS packets arrive only via epoll sleep/wake. Use
  when all UDP traffic is hardware-steered.
- *Smaller values:* Check OS more often. For frequent
  multicast join/leave or significant non-steered traffic.
- *100 (default):* ~1% overhead. Sufficient when
  non-offloaded traffic is rare.

**Too low:** high ioctl rate visible in strace/perf, most
finding nothing. Too high or 0: non-offloaded packets
delayed or lost.

**Auto-set to 0** by the ultra_latency profile
(XLIO_SPEC=ultra_latency).

**Default:** `100`

### `performance.polling.rx_poll_on_tx_tcp`

> **Type:** boolean
>
> **Maps to:** `XLIO_RX_POLL_ON_TX_TCP`

When enabled, each TCP send() polls the receive Completion
Queue for incoming acknowledgments before transmitting,
freeing send buffer space in a single call. Only affects
POSIX sockets; XLIO Ultra API sockets poll independently
and ignore this setting.

**Tradeoffs:**

- *false* (default): send() transmits without polling
  receive. Lower per-call latency, but the send buffer
  can fill when acknowledgments accumulate unprocessed
  (send-only loops with no recv or epoll_wait).
- *true*: send() first drains acknowledgments, then
  transmits. Higher per-call latency but sustained
  throughput for bulk transfers because send buffer
  space is reclaimed immediately.

Enable for transmit-heavy workloads that do not regularly
poll for receive events (blocking bulk senders, delegate
internal handler mode). For event-driven servers that
already call epoll_wait frequently, the default (false)
is sufficient because acknowledgments are processed there.

**Auto-enabled** by the nginx profile
([`profiles.spec`](#profilesspec)=nginx).

**Default:** `false`

### `performance.polling.skip_cq_on_rx`

> **Type:** integer or string
>
> **Values:** 0/"disable", 1/"enable", 2/"enable_epoll_only"
>
> **Maps to:** `XLIO_SKIP_POLL_IN_RX`

Controls whether TCP recv() skips direct Completion Queue
polling, checking only the socket's ready packet list.

**Values:**

- *disable (0, default):* recv() polls the Completion
  Queue, acquires ring locks, and processes completions.
  Lowest arrival-to-delivery latency. Works with or
  without epoll.
- *enable (1):* recv() never polls the Completion Queue;
  only returns packets already queued by epoll_wait,
  worker threads, or delegate internal handler. Without
  an external poller, recv() spins returning EAGAIN.
  Lowest per-call CPU; eliminates redundant polling and
  ring lock contention.
- *enable_epoll_only (2):* Like disable (0) until the
  socket joins an epoll instance (epoll_ctl ADD), then
  like enable (1). Reverts on epoll_ctl DEL. Safe for
  mixed I/O patterns.

Use enable (1) or enable_epoll_only (2) for event-driven
servers where epoll_wait already drains Completion Queues.
Use disable (0) when recv() is the sole packet driver or
first-byte latency is critical. The default is sufficient
when the application naturally interleaves recv() and
epoll_wait, or uses per-socket ring allocation.

**Default:** `"disable" (0)`

### `performance.polling.yield_on_poll`

> **Type:** integer
>
> **Maps to:** `XLIO_RX_POLL_YIELD`

Inserts periodic sched_yield() calls during the blocking
receive busy-poll loop (controlled by
[`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec)), letting other threads run when
multiple threads share CPU cores.

**Protocol behavior:**

- *UDP:* Yields every N iterations (at N-1, 2N-1, ...).
- *TCP:* No yield for the first N iterations; yields on
  every iteration thereafter.

**Sizing:** Match to thread-to-core oversubscription.
With dedicated cores (threads <= cores), leave at 0. At
4:1 oversubscription, ~100-500 balances fairness and
polling density.

**Cause-effect:**

- *Too low:* Frequent context switches add latency
  variance to receives.
- *Too high or 0:* Threads monopolize the core for the
  full [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) budget, starving neighbors.

No effect when [`blocking_rx_poll_usec`](#performancepollingblocking_rx_poll_usec) is 0 (no busy-poll
loop runs).

**Default:** `0`

### `performance.rings.max_per_interface`

> **Type:** integer
>
> **Maps to:** `XLIO_RING_LIMIT_PER_INTERFACE`

Caps rings created per network interface. When 0 (default),
one ring per allocation unit (thread, socket, or core)
with no cap.

When the cap is reached, new requests redirect to the
existing ring with the fewest users. Shared rings
serialize on per-ring locks.

**Sizing:** Set to roughly half the thread count for
event-driven servers (Nginx, HAProxy) where threads
rarely access rings simultaneously. Keep at 0 for
CPU-intensive workloads with continuous packet
processing -- sharing adds lock contention there.

**Cause-effect:**

- *Too few rings:* Per-ring lock contention reduces
  throughput under load.
- *Too many (or 0):* Higher memory use; global buffer
  pool contention can reduce throughput at 32+ threads.

The limit applies per interface. With two ports and
limit of 16, up to 32 rings total. Monitor buffer
exhaustion via xlio_stats "No buffers error:" counter.

**Default:** `0`

### `performance.rings.rx.allocation_logic`

> **Type:** integer or string
>
> **Values:** 0/"per_interface", 1/"per_ip_address", 10/"per_socket", 20/"per_thread", 30/"per_cpuid", 31/"per_core"
>
> **Maps to:** `XLIO_RING_ALLOCATION_LOGIC_RX`

Determines how receive rings (Queue Pair, Completion
Queue, buffers, per-ring lock) are grouped.

**Values:**

- *per_interface (0):* One ring per network interface.
  Lowest memory; highest lock contention.
- *per_ip_address (1):* One ring per local IP.
- *per_socket (10):* Dedicated ring per socket.
  Maximum isolation; highest resource cost.
- *per_thread (20, default):* One ring per thread.
- *per_cpuid (30):* One ring per CPU core.
- *per_core (31):* Like per_cpuid, but pins the
  thread to the core for consistent assignment.

**Sizing:** per_thread (20) suits most workloads. At
32+ threads, cap with [`max_per_interface`](#performanceringsmax_per_interface) (half the
thread count) to limit global buffer pool contention.
select()/poll() callers should prefer fewer rings --
those calls iterate every ring each invocation.

**Too few rings:** lock contention serializes receive
processing. Too many: memory grows linearly and at
32+ rings buffer pool contention can hurt throughput.

**Auto-set to per_interface (0)** by the nginx and
nginx_dpu profiles ([`profiles.spec`](#profilesspec)). Forced to
per_thread (20) when
[`performance.threading.internal_handler.behavior`](#performancethreadinginternal_handlerbehavior)=delegate.

**Default:** `"per_thread" (20)`

### `performance.rings.rx.migration_ratio`

> **Type:** integer (min: -1)
>
> **Maps to:** `XLIO_RING_MIGRATION_RATIO_RX`

Controls when to reassign a socket's receive ring to the
thread currently polling it. Only applies when
[`performance.rings.rx.allocation_logic`](#performanceringsrxallocation_logic) is per_thread, per_cpuid, or per_core.

**Mechanism:** A counter increments each recv()/poll()/
epoll_wait(). At this value XLIO checks whether the
polling thread differs from the ring owner. On mismatch,
a candidate must remain stable for 20 more accesses
before migration executes (total: value + 20). Migration
updates hardware flow steering, drains the old Completion
Queue, and transfers buffers — expensive.

**Sizing:** Based on how often sockets change threads:

- **-1** (default): Disabled; zero overhead.
- **50-100:** Fast adaptation for connection hand-off or
  work-stealing patterns.
- **500-10000:** Infrequent checks; lower per-packet
  overhead but slower adaptation.

**Cause-effect:**

- *Too low:* Transient thread sharing triggers needless
  migrations (flow steering updates, lock contention).
- *Too high:* Socket polls the wrong ring longer; every
  Completion Queue access is a cross-CPU cache miss.

For single-threaded or thread-per-connection servers the
default (-1) is sufficient. Enable only when sockets are
regularly polled by a different thread than their creator.

**Monitoring:** "Ring migrations Rx:" in xlio_stats.

**Related:** [`performance.rings.rx.allocation_logic`](#performanceringsrxallocation_logic) (ring assignment mode),
[`performance.rings.tx.migration_ratio`](#performanceringstxmigration_ratio) (transmit side equivalent).

**Default:** `-1`

### `performance.rings.rx.post_batch_size`

> **Type:** integer (range: 1 to 1024)
>
> **Maps to:** `XLIO_RX_WRE_BATCHING`

Buffers consumed from the Receive Queue are posted back in
one doorbell write after this many accumulate. Range: 1-1024.

**Mechanism:** A debt counter increments per buffer consumed.
At this threshold XLIO posts the accumulated batch with a
single doorbell (memory barrier + PCIe write), amortizing
the per-doorbell overhead across multiple buffers.

**Striding Receive Queue:** Runtime default drops to 1
because each Work Queue Element holds many packet slots
(default 2048, set by [`hardware_features.striding_rq.strides_num`](#hardware_featuresstriding_rqstrides_num)) — one doorbell already replenishes 2048
receive slots. The schema default (1024) only takes effect
when Striding Receive Queue is disabled.

**Sizing:** With Striding Receive Queue (default), leave
at 1. Without it, the default (1024) suits throughput
workloads; the "ultra_latency" and "latency" profiles
reduce to 4 for lowest jitter.

**Cause-effect:**

- *Too low:* More doorbell writes per packet, lower peak
  throughput.
- *Too high:* Replenishment bursts increase tail latency.
  Ring lock held longer on shared rings.

**Constraints:** Receive queue depth is auto-raised to
2 × this value. [`spare_buffers`](#performanceringsrxspare_buffers) is auto-raised to this value.

**Related:** [`spare_buffers`](#performanceringsrxspare_buffers) (buffer pool feeding batches),
[`performance.rings.rx.ring_elements_count`](#performanceringsrxring_elements_count) (Receive Queue depth).

**Default:** `1024`

### `performance.rings.rx.ring_elements_count`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_RX_WRE`

Work Request Elements in the hardware Receive Queue per
ring. Rounded up to the next power of 2 at runtime.

**Striding Receive Queue override:** With Striding Receive
Queue (default), runtime default drops to 128 because each
element holds many packet slots (default 2048, set by
[`hardware_features.striding_rq.strides_num`](#hardware_featuresstriding_rqstrides_num)) — effective
capacity = this value × strides per element. Without Striding
Receive Queue, each element holds one packet.

**Memory per ring:** With Striding Receive Queue: this value ×
strides per element × stride size. Without: this value × receive
buffer size. Actual footprint depends on hugepage allocation
rounding.

**Sizing:** Match to burst depth (packets arriving faster
than the application drains). Profile values:

- "ultra_latency" / "latency": 4 (Striding Receive Queue)
  or 256 (without).

For most workloads the defaults are sufficient.

**Cause-effect:**

- *Too low:* NIC silently drops packets. Check
  `ethtool -S <dev>` counter "rx_out_of_buffer".
- *Too high:* Higher per-ring memory; larger Completion
  Queue may add latency variance.

**Constraints:** Auto-raised to 2 × post_batch_size. With
Striding Receive Queue, capped so the product of strides per
element and this value does not exceed 4,194,304 (maximum
Completion Queue entries).

**Related:** [`post_batch_size`](#performanceringsrxpost_batch_size) (replenishment batch),
[`spare_buffers`](#performanceringsrxspare_buffers) (defaults to half this value).

**Default:** `32768`

### `performance.rings.rx.spare_buffers`

> **Type:** integer
>
> **Maps to:** `XLIO_QP_COMPENSATION_LEVEL`

Per-ring local buffer cache for Receive Queue replenishment
without locking the global buffer pool.

**Mechanism:** On depletion, XLIO fetches this many buffers
from the global pool (one lock acquisition). When the
cache exceeds 2x this value, excess drains back to 1x.

**Runtime default:** Half the receive queue depth. Striding Receive Queue: 64; without: 16384.

**Sizing:** Match to expected burst depth (packets arriving
faster than the application drains).

**Cause-effect:**

- *Too low:* Frequent global pool lock contention.
  "SW RX Packets dropped:" in xlio_stats Completion Queue
  view signals buffer exhaustion.
- *Too high:* Memory reserved per ring even when idle
  (total = value x buffer_size x rings x 2).

For most workloads the runtime default is sufficient.

**Constraints:** Auto-raised to post_batch_size.

**Related:** [`performance.rings.rx.ring_elements_count`](#performanceringsrxring_elements_count) (Receive Queue depth),
[`post_batch_size`](#performanceringsrxpost_batch_size) (replenishment batch), [`keep_full`](#performancecompletion_queuekeep_full) (drop
behavior on buffer shortage).

**Default:** `32768`

### `performance.rings.rx.spare_strides`

> **Type:** integer
>
> **Maps to:** `XLIO_STRQ_STRIDES_COMPENSATION_LEVEL`

Per-ring stride descriptor cache size. Only applies with
Striding Receive Queue enabled (the default). Stride
descriptors are metadata tracking packet positions; they hold no packet data ([`spare_buffers`](#performanceringsrxspare_buffers)
manages data buffers).

**Mechanism:** On empty cache, XLIO fetches this many
from the global pool (one lock acquisition). At 2x
this value, excess returns to the global pool. If the
pool cannot supply the batch, XLIO panics.

**Sizing:** Memory scales with value × ring count (cache
grows to 2x). Cap rings via [`max_per_interface`](#performanceringsmax_per_interface) to
limit total memory.

**Cause-effect:**

- *Too low:* Global pool lock contention hurts
  throughput. On exhaustion XLIO panics with "Unable
  to retrieve strides from global pool".
- *Too high:* Descriptor memory reserved per ring
  even when idle; may crowd out data buffers.

For most workloads the default (32768) is sufficient.
Auto-set to 32 for the nginx master process.

**Related:** [`spare_buffers`](#performanceringsrxspare_buffers) (data buffer cache),
[`hardware_features.striding_rq.enable`](#hardware_featuresstriding_rqenable).

**Default:** `32768`

### `performance.rings.tx.allocation_logic`

> **Type:** integer or string
>
> **Values:** 0/"per_interface", 1/"per_ip_address", 10/"per_socket", 20/"per_thread", 30/"per_cpuid", 31/"per_core"
>
> **Maps to:** `XLIO_RING_ALLOCATION_LOGIC_TX`

Determines how transmit rings (Queue Pair, Completion
Queue, buffers, per-ring lock) are grouped.

**Values:**

- *per_interface (0):* One ring per network interface.
  Lowest memory; highest lock contention.
- *per_ip_address (1):* One ring per local IP.
- *per_socket (10):* Dedicated ring per socket.
  Maximum isolation; highest resource cost.
- *per_thread (20, default):* One ring per thread.
- *per_cpuid (30):* One ring per CPU core.
- *per_core (31):* Like per_cpuid, but pins the
  thread to the core for consistent assignment.

**Sizing:** per_thread (20) suits most workloads. At
32+ threads, cap with [`max_per_interface`](#performanceringsmax_per_interface) (e.g. half
the thread count) to limit global buffer pool
contention. select()/poll() callers should prefer
fewer rings (each invocation iterates every ring).

**Cause-effect:**

- *Too few:* Lock contention serializes sends.
- *Too many:* Memory grows linearly; buffer pool
  contention rises with ring count.

**Auto-set to per_interface (0)** by the nginx and
nginx_dpu profiles ([`profiles.spec`](#profilesspec)). Forced to
per_thread (20) when
[`performance.threading.internal_handler.behavior`](#performancethreadinginternal_handlerbehavior)=delegate.

**Related:** [`max_per_interface`](#performanceringsmax_per_interface) (ring cap),
[`performance.rings.tx.migration_ratio`](#performanceringstxmigration_ratio) (ring reassignment; disabled when
TCP Segmentation Offload is enabled).

**Default:** `"per_thread" (20)`

### `performance.rings.tx.completion_batch_size`

> **Type:** integer (range: 1 to 64)
>
> **Maps to:** `XLIO_TX_WRE_BATCHING`

Controls how many transmit Work Request Elements are posted before
XLIO requests a completion from the NIC. Range: 1-64.

**Behavior:**
XLIO counts unsignaled sends. At zero, the next send requests a
completion (resetting the counter to value - 1) and batch-processes
all accumulated sends: returning buffers, releasing Send Queue
credits, and invoking callbacks. Zero-copy sends always request
immediate completion. The first send always triggers one.

**Tradeoffs:**

- *High (64):* Higher throughput, lower CPU per packet. But each
  completion processes all accumulated sends in one burst, causing
  tail latency spikes. More transmit buffers held in-flight.
- *Low (4):* Consistent latency (lower standard deviation), faster
  buffer and credit recovery. But polling after every 4th send
  reduces throughput and increases CPU.

**Sizing:** For throughput workloads, the default (64, also the
maximum) is sufficient. For latency-sensitive workloads (trading,
real-time), use 4 (LATENCY and ULTRA_LATENCY profiles). For
mixed workloads, try 16-32. Monitor latency histograms for jitter.
If [`performance.rings.tx.ring_elements_count`](#performanceringstxring_elements_count) is below `completion_batch_size` × 2, XLIO
automatically raises it to that minimum.

**Default:** `64`

### `performance.rings.tx.max_inline_size`

> **Type:** integer (range: 0 to 884)
>
> **Maps to:** `XLIO_TX_MAX_INLINE`

Maximum packet size (bytes) copied directly into the Work Queue
Entry instead of requiring PCIe DMA from host memory.

**Transmission paths** (preference order): (1) Inline (packet ≤
value): data copied into Work Queue Entry, enables BlueFlame
direct-write to NIC. (2) On-Device Memory (if
[`max_on_device_memory`](#performanceringstxmax_on_device_memory) > 0): data on NIC internal memory, no PCIe
round-trip. (3) Host DMA: NIC reads from host via PCIe. The
18-byte Ethernet header is always inlined. Range: 0-884.

**Tradeoffs:**

- *High (toward 884):* More packets skip DMA, lower per-packet
  latency. But larger Work Queue Entries reduce Send Queue depth
  (fewer in-flight packets) and more CPU from memcpy.
- *Low/0:* More queue depth, less CPU on send path. But more
  packets take the slower DMA path.

**Sizing:** Match to typical send payload size. Default (204)
corresponds to BlueFlame buffer capacity (4 Work Queue Entry
Basic Blocks) and covers most control traffic (TCP
acknowledgments, small UDP). Increase toward 884 only when
latency-critical packets are 204-884 bytes. For applications
sending mostly large packets, the default is sufficient since
those exceed any inline threshold. On-Device Memory
([`max_on_device_memory`](#performanceringstxmax_on_device_memory)) helps packets just above inline size.

**Default:** `204`

### `performance.rings.tx.max_on_device_memory`

> **Type:** integer (range: 0 to 262144)
>
> **Maps to:** `XLIO_RING_DEV_MEM_TX`

Bytes of NIC-internal memory allocated per transmit ring,
eliminating PCIe round-trip latency for packets exceeding
the Work Queue Entry inline size ([`max_inline_size`](#performanceringstxmax_inline_size), default 204).

**Behavior:** Circular buffer per transmit ring. When full,
XLIO falls back to host DMA — no data loss, only higher
latency for overflow packets. Requires BlueFlame; disabled
on virtual machines and when the NIC has no device memory.

**Tradeoffs:**

- *0 (default):* All non-inlined packets use host DMA.
  No NIC memory consumed.
- *Non-zero:* Non-inlined packets bypass PCIe. Lower
  per-packet latency but consumes NIC memory shared across
  all transmit rings on the adapter.

**Sizing:** value × transmit ring count must stay within
262144 (total NIC device memory). Monitor "oob" in the
"Dev Mem Stats:" line of xlio_stats — rising values mean
overflow packets are falling back to host DMA. LATENCY
and ULTRA_LATENCY profiles use 16384 (16 KB). For most
workloads the default (0) is sufficient; enable with
16384 for latency-sensitive workloads where typical
packets exceed the inline size.

**Default:** `0`

### `performance.rings.tx.migration_ratio`

> **Type:** integer (min: -1)
>
> **Maps to:** `XLIO_RING_MIGRATION_RATIO_TX`

Send operations between checks for whether a socket's
transmit ring should migrate to the current thread.
Only effective with per_thread, per_cpuid, or per_core
allocation_logic. Auto-disabled when TCP Segmentation
Offload is enabled.

**Behavior:** Every (value) sends, XLIO compares the
sending thread to the ring owner. On mismatch, the new
thread must stay stable for 20 more sends before
migration. Migration acquires both ring locks, may
reallocate Queue Pairs, and invalidates cached state.

**Tradeoffs:**

- *-1 (default):* Disabled. Socket stays on the
  creating thread's ring permanently. Zero overhead.
- *Positive:* Adapts ring to the active thread. Lower
  values detect sooner (more per-send overhead); higher
  values check less often (slower adaptation).

**Sizing:** Most applications pin sockets to their
creating thread — use -1. Enable (50-500) for
work-stealing or hand-off patterns where a socket
permanently moves threads. Wrong-ring symptoms:
cross-CPU cache misses and lock contention.

**Default:** `-1`

### `performance.rings.tx.ring_elements_count`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_TX_WRE`

**Send Queue depth:** maximum packet descriptors (Work Request
Elements) per transmit ring. Determines how many packets
can be in-flight (posted to the NIC, not yet completed).

**Behavior:** When the Send Queue fills before completions
free space, non-blocking sends silently drop the packet;
blocking sends poll and wait. Automatically capped to the
NIC's maximum Queue Pair work requests, and raised to at
least [`completion_batch_size`](#performanceringstxcompletion_batch_size) × 2.

**Tradeoffs:**

- *Low (256):* Less memory, faster queue drain, more
  predictable latency. But higher risk of Send Queue full
  when sends outpace completions.
- *High (32768, default):* Absorbs send spikes, more
  packets in flight, higher sustained throughput. But more
  memory and longer completion processing cycles.

**Sizing:** For throughput workloads the default (32768) is
sufficient. For latency-sensitive workloads (trading,
real-time), start with 256 (LATENCY and ULTRA_LATENCY
profiles) and increase only if "TX Dropped Send Reqs:" in
xlio_stats -v 3 (full view) is non-zero.

**Default:** `32768`

### `performance.rings.tx.tcp_buffer_batch`

> **Type:** integer (min: 1)
>
> **Maps to:** `XLIO_TX_BUFS_BATCH_TCP`

Transmit buffers fetched at once per TCP connection from the
ring's shared buffer pool when the local cache is empty.

**Behavior:** Each TCP connection caches buffers locally.
When empty, XLIO acquires the ring's pool lock and fetches
this many buffers in one operation. One is used immediately;
the rest stay cached. Zero-copy sends use a separate cache
with the same batch size.

**Tradeoffs:**

- *High (16, default):* Fewer pool lock acquisitions,
  better streaming throughput. But more memory per
  connection; idle connections may hoard buffers (mitigated
  by [`batching_mode`](#performancebuffersbatching_mode) periodic reclaim).
- *Low (1):* Minimal per-connection memory, faster buffer
  return to pool. But a pool lock acquisition on every send.

**Sizing:** For continuous streams, 16 amortizes lock cost
well. For servers with many mostly-idle connections, lower
to 1-4 (worst case: value × buffer size per connection).
LATENCY and ULTRA_LATENCY profiles use 1. Forced to 1
when [`worker_threads`](#performancethreadingworker_threads) > 0 or [`batching_mode`](#performancebuffersbatching_mode) is "disable".

**Default:** `16`

### `performance.rings.tx.udp_buffer_batch`

> **Type:** integer (min: 1)
>
> **Maps to:** `TX_BUFS_BATCH_UDP`

Transmit buffers fetched at once per UDP socket from the
ring's shared buffer pool when the socket's local cache
is empty.

**Behavior:** Each UDP socket caches buffers locally.
When the cache is depleted, XLIO acquires the ring's pool
lock and fetches this many buffers in one operation. One
is used for the current packet; the rest stay cached.
After sending, if the cache is again empty, XLIO
proactively pre-fetches. On socket close, unused cached
buffers return to the pool.

**Tradeoffs:**

- *High (8, default):* Fewer pool lock acquisitions,
  better burst performance. But more memory held per
  socket; idle sockets may hoard buffers (mitigated by
  [`batching_mode`](#performancebuffersbatching_mode) periodic reclaim).
- *Low (1):* Minimal per-socket memory, faster buffer
  return to shared pool. But a pool lock acquisition on
  every send.

**Sizing:** For steady UDP senders, 8 amortizes lock
overhead well. For applications with many mostly-idle
sockets, lower to 1-4 to reduce per-socket memory
(worst case: value × transmit buffer size per socket).
LATENCY, ULTRA_LATENCY, and NVME_BF3 profiles use 1.
Forced to 1 when [`batching_mode`](#performancebuffersbatching_mode) is "disable". For most
UDP workloads the default (8) is sufficient.

**Default:** `8`

### `performance.steering_rules.disable_flowtag`

> **Type:** boolean
>
> **Maps to:** `XLIO_DISABLE_FLOW_TAG`

Controls whether XLIO uses hardware flow tags for
packet-to-socket mapping on receive.

**Behavior:** When false (default), each socket's steering
rule includes a flow tag in the completion entry, enabling
direct array lookup to the socket without header parsing.
When true, every received packet requires Ethernet/IP/
transport header parsing and hash-table lookup to find
the destination socket. Auto-disabled when the network
adapter lacks flow tag support.

**Tradeoffs:**

- *false (default):* Fast receive path (direct array
  lookup per packet). Required for 2-step socket
  migration (fails with ENOTSUP if true).
- *true:* Software classification on every packet (parse
  headers, hash-table lookup). Only useful for debugging
  packet dispatch.

**Interactions:** Cannot coexist with
[`mc_flowtag_acceleration`](#networkmulticastmc_flowtag_acceleration); when both are set,
[`mc_flowtag_acceleration`](#networkmulticastmc_flowtag_acceleration) is auto-disabled with a warning.
Multicast sockets with SO_REUSEADDR or SO_REUSEPORT
lose flow tags unless [`mc_flowtag_acceleration`](#networkmulticastmc_flowtag_acceleration) overrides.
[`performance.steering_rules.tcp.2t_rules`](#performancesteering_rulestcp2t_rules) and [`performance.steering_rules.tcp.3t_rules`](#performancesteering_rulestcp3t_rules) mask flow tags for
affected connections regardless of this setting.

**Sizing:** Keep false for all production deployments.
Enable only for debugging the software classification
path.

**Default:** `false`

### `performance.steering_rules.tcp.2t_rules`

> **Type:** boolean
>
> **Maps to:** `XLIO_TCP_2T_RULES`

Switches TCP hardware steering from per-connection 5-tuple
rules to per-IP 2-tuple rules (protocol + local IP only).

**Behavior:** When false (default), each connection gets
its own steering rule matching protocol, local IP, local
port, remote IP, and remote port. When true, one rule per
local IP covers all connections — software demultiplexes
to sockets via hash lookup.

**Tradeoffs:**

- *false (default):* Per-connection rules with flow-tag
  acceleration. Each connection uses one flow table entry.
- *true:* One rule per local IP, unlimited connections.
  Flow tags are masked (software classification, higher
  per-packet CPU). Requires a unique local IP per XLIO
  ring.

**Sizing:** For TCP clients (outgoing connect()) where
ephemeral ports would exhaust the hardware flow table.
For servers (incoming accept()), prefer [`performance.steering_rules.tcp.3t_rules`](#performancesteering_rulestcp3t_rules) instead.

**Symptom of exhaustion:** "attach_flow" failures in XLIO
error logs. With per-thread ring allocation, each thread
needs its own local IP. For low-to-moderate connection
counts, the default is sufficient.

**Default:** `false`

### `performance.steering_rules.tcp.3t_rules`

> **Type:** boolean
>
> **Maps to:** `XLIO_TCP_3T_RULES`

Controls hardware steering rule granularity for
accepted TCP connections. Only affects incoming
connections (listen()/accept()); for outgoing
(connect()), see 2t_rules.

**Tradeoffs:**

- *false (default):* Each accepted connection gets
  its own 5-tuple steering rule with flow-tag
  acceleration. Each connection uses one flow table
  entry.
- *true:* One 3-tuple rule per listening port
  (protocol + local IP + local port) shared across
  all accepted connections. Faster accept() and
  close() (no per-connection hardware rule
  creation/deletion). But flow tags are masked —
  software demultiplexes via hash lookup (higher
  per-packet CPU).

**Sizing:** For high-connection-count servers where
the hardware flow table fills up (symptom:
"attach_flow" errors in XLIO error logs). NGINX and
NGINX_DPU profiles enable this. For low-to-moderate
connection counts, the default (false) is sufficient.

**Default:** `false`

### `performance.steering_rules.udp.3t_rules`

> **Type:** boolean
>
> **Maps to:** `XLIO_UDP_3T_RULES`

Switches connected-UDP hardware steering from
per-connection 5-tuple rules to per-local-port 3-tuple
rules (protocol + local IP + local port). Only affects
connected UDP sockets (those that called connect());
non-connected sockets always use 3-tuple rules.

**Tradeoffs:**

- *true (default):* All connected sockets on the same
  local IP:port share one hardware rule; remote address
  and port are wildcarded. Software demultiplexes
  packets via hash lookup. Faster connect()/close()
  (no per-connection rule creation/deletion). But
  higher per-packet CPU from software classification.
- *false:* Each connected socket gets a dedicated
  5-tuple rule with flow-tag fast path (hardware
  identifies the socket directly). Each connection
  consumes one flow table entry.

**Sizing:** The default (true) conserves flow table
entries and suits most UDP workloads. Disable only
for latency-critical UDP with few connected sockets
and high per-socket packet rates (trading, real-time
control). Symptom of flow table exhaustion:
"attach_flow" errors in XLIO error logs. For TCP
steering, see [`performance.steering_rules.tcp.3t_rules`](#performancesteering_rulestcp3t_rules) (servers) and [`performance.steering_rules.tcp.2t_rules`](#performancesteering_rulestcp2t_rules)
(clients).

**Default:** `true`

### `performance.steering_rules.udp.only_mc_l2_rules`

> **Type:** boolean
>
> **Maps to:** `XLIO_ETH_MC_L2_ONLY_RULES`

Switches UDP multicast steering from per-(group, port)
rules to per-multicast-MAC rules (destination MAC +
protocol only).

**Behavior:** When false (default), each (multicast IP,
port) gets a dedicated hardware steering rule. When
true, all ports sharing a multicast IP share one rule
keyed on the derived multicast MAC; XLIO filters by
port in software. Rule is created on first join per
multicast IP, removed on last leave.

**Tradeoffs:**

- *false (default):* Hardware dispatches directly to
  the matching flow — lowest latency and CPU. Each
  (multicast IP, port) consumes one flow table entry.
- *true:* One entry per multicast IP, unlimited ports.
  Faster join/leave. But software filtering adds CPU
  on every received packet; unsubscribed ports on the
  same IP also arrive and must be discarded.

**Sizing:** Enable when many ports per multicast group
exhaust the flow table (symptom: "attach_flow" errors
in XLIO logs). Example: 500 ports on 239.1.1.1 need
500 rules when false, 1 when true. For applications
with few multicast subscriptions the default is
sufficient.

**Default:** `false`

### `performance.threading.cpu_affinity`

> **Type:** string
>
> **Maps to:** `XLIO_INTERNAL_THREAD_AFFINITY`

CPU core(s) on which the XLIO internal thread runs.

**Format:** same as taskset — hex bitmask (0x0F) or
comma-delimited list with ranges (0,2,4-7). The
internal thread processes TCP retransmission/keepalive
timers, ARP resolution, fragment reassembly, socket
cleanup, and asynchronous hardware events. It wakes
every [`performance.threading.internal_handler.timer_msec`](#performancethreadinginternal_handlertimer_msec) (default 10 ms) via epoll_wait.

**Tradeoffs:**

- *-1 (default):* No affinity; OS scheduler picks
  cores. Thread may migrate across NUMA nodes, causing less
  deterministic timer processing.
- *Pinned (single core):* Predictable, low-jitter
  timer processing. Best on the same NUMA node as
  application threads but a different physical core.

**Interactions:** If cpuset is set, the thread joins
it first; `cpu_affinity` is applied within that cpuset.
When behavior is "delegate", TCP timers move to
application threads, reducing this setting's importance.

**Sizing:** For most workloads the default (-1) is
sufficient. For latency-sensitive workloads (trading,
real-time), pin to an isolated core on the same NUMA
node as the application (e.g., isolcpus + value "15").
LATENCY and ULTRA_LATENCY profiles use "0"; NVME_BF3
uses "0x01".

**Default:** `-1`

### `performance.threading.cpuset`

> **Type:** string
>
> **Maps to:** `XLIO_INTERNAL_THREAD_CPUSET`

Filesystem path to a Linux cpuset directory for the XLIO
internal thread. Unlike [`cpu_affinity`](#performancethreadingcpu_affinity) (a scheduler hint),
a cpuset is kernel-enforced — the thread is never
scheduled outside the cpuset's allowed CPUs or NUMA
memory nodes.

**Behavior:** At startup the internal thread writes its
thread ID to <path>/tasks. Invalid or unwritable path
aborts XLIO. When both cpuset and [`cpu_affinity`](#performancethreadingcpu_affinity) are set,
the cpuset is joined first; [`cpu_affinity`](#performancethreadingcpu_affinity) applies within
it (must reference CPUs inside the cpuset).

**Tradeoffs:**

- *"" (default):* Thread inherits the process's cpuset
  (root unless restricted by container or cgroup).
  No configuration needed.
- *Non-empty:* Hard CPU and NUMA isolation. Path must
  exist before XLIO starts.

**Sizing:** For most deployments the default is
sufficient — use [`cpu_affinity`](#performancethreadingcpu_affinity) alone for thread pinning.
Use an explicit cpuset only for kernel-guaranteed
isolation in latency-critical production systems.
Containers inherit cgroup constraints automatically.

**Default:** `""`

### `performance.threading.internal_handler.behavior`

> **Type:** integer or string
>
> **Values:** 0/"disable", 1/"delegate"
>
> **Maps to:** `XLIO_TCP_CTL_THREAD`

Controls whether TCP timers (retransmission, keepalive,
delayed acknowledgment, persist, state cleanup) run on
XLIO's internal thread or on each application thread.

**Tradeoffs:**

- *"disable" (0, default):* Internal thread handles all
  TCP timers. Sockets use real locks — safe to share
  across threads. poll(), select(), and epoll all work.
- *"delegate" (1):* Thread-local timers with no-op locks
  (lock-free). Each socket must stay on one thread for
  its lifetime (violation causes silent corruption; no
  runtime check). Incompatible with blocking
  poll()/select() — timers freeze, stalling
  retransmissions. Epoll is safe (wakes periodically).

**Forced** when delegate: ring allocation per_thread
(both directions), progress engine interval disabled.

**Sizing:** Default suits most applications. Use
"delegate" only for busy-polling or epoll event loops
with strict one-thread-per-socket ownership (trading,
single-threaded servers). Benefit: zero per-operation
lock overhead. Misuse symptoms: hung connections
(poll/select); silent corruption (shared sockets).

**Default:** `"disable" (0)`

### `performance.threading.internal_handler.timer_msec`

> **Type:** integer (min: 0)
>
> **Maps to:** `XLIO_TIMER_RESOLUTION_MSEC`

Minimum wakeup interval (milliseconds) for XLIO's internal
thread (TCP timers, neighbor discovery, route updates,
RDMA connection-manager and InfiniBand async events).
Uses epoll_wait with this value as minimum timeout.

**Constraint:** Lower bound for [`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) — values
below this are raised automatically. Timer buckets =
[`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) / timer_msec, so keep [`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) an
integer multiple.

**Tradeoffs:**

- *Low (10, default):* Faster reaction to timer
  expirations (retransmissions, keepalives, link
  failures). But more epoll_wait wakeups and higher CPU
  overhead from the internal thread.
- *High (32+):* Lower CPU utilization and less scheduler
  noise. But slower detection of packet loss and hardware
  events; coarser timer granularity delays retransmissions
  and keepalive probes.

**Sizing:** For most workloads the default (10) is
sufficient. Increase to 32 only for high-connection-count
servers where internal-thread CPU is measurable (NGINX
and NGINX_DPU profiles use 32). Pair with a proportional
[`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) (for example, 32 with [`network.protocols.tcp.timer_msec`](#networkprotocolstcptimer_msec) 256).

**Default:** `10`

### `performance.threading.mutex_over_spinlock`

> **Type:** boolean
>
> **Maps to:** `XLIO_MULTILOCK`

Selects spinlock or mutex for XLIO's ring, socket,
TCP connection, and device locks. On the hot path
XLIO uses non-blocking lock attempts (return immediately
if contended), so the type matters mainly when contention
forces a blocking wait.

**Tradeoffs:**

- *false (default, spinlock):* Lowest uncontended
  latency. But the waiting thread burns 100 percent
  CPU; when threads outnumber cores this starves
  other work.
- *true (mutex):* No CPU waste (thread sleeps). But
  kernel involvement adds latency even uncontended.

**Sizing:** Default is correct for most workloads
with per-thread rings, dedicated cores, or
busy-polling. Switch to true only when threads
outnumber cores and spinning wastes cycles (cloud
virtual machines, containers, CPU-limited cgroups).

**Symptom:** high CPU with low throughput; confirm with
"perf lock report". If mutex latency is unacceptable,
reduce contention via ring allocation (per-thread or
higher ring limits) instead. No effect when behavior
is "delegate" (locks become no-ops).

**Default:** `false`

### `performance.threading.worker_threads`

> **Type:** integer (range: 0 to 512)
>
> **Maps to:** `XLIO_WORKER_THREADS`

Dedicated XLIO threads for network processing. POSIX
API only (not the Ultra API). TCP only — UDP sockets
are unaffected.

**Behavior:**

- *0 (default, run-to-completion):* Application threads
  process networking inline during socket calls. Lowest
  latency, no extra CPU. Requires per-thread socket
  ownership and frequent socket calls.
- *>0 (worker threads):* XLIO spawns N busy-polling
  threads; operations dispatched via lock-free queues.
  Sockets may be shared across application threads. One
  listen socket suffices — XLIO creates one Receive
  Side Scaling child per worker for parallel accept().
  Outgoing connections distributed round-robin. Blocking
  connect() is not supported.

**Forced changes** when >0: [`performance.buffers.tx.buf_size`](#performancebufferstxbuf_size) 256 KB,
[`tcp_buffer_batch`](#performanceringstxtcp_buffer_batch) 1, [`poll_usec`](#performancepollingiomuxpoll_usec) -1,
[`periodic_drain_msec`](#performancecompletion_queueperiodic_drain_msec) 0.

**Sizing:** Each worker consumes one CPU core at 100%
(busy-polling) — set to cores you can dedicate, not
connection count. For applications with per-thread
sockets and frequent socket calls, the default (0) is
sufficient and lower-latency. Use workers for legacy
applications that share sockets across threads or call
socket APIs infrequently. Too few workers: job queue
backs up ("Max" column in xlio_stats view 6). Too
many: CPU cores wasted on idle polling ("Idle" column
near 100%).

**Default:** `0`

---

## PROFILES

### `profiles.spec`

> **Type:** integer or string
>
> **Values:** 0/"none", 1/"ultra_latency", 2/"latency", 3/"nginx", 4/"nginx_dpu", 5/"nvme_bf3"
>
> **Maps to:** `XLIO_SPEC`

Predefined parameter bundle that optimizes XLIO for a
specific workload pattern. Each profile sets dozens of
parameters at once; individual parameters can still be
overridden afterward. Specific values set by each
profile are noted in each parameter's own documentation.

**Profiles:**

- *"none" (0, default):* No optimizations applied.
  XLIO defaults: moderate polling budget (100 ms),
  per-thread rings, TCP Segmentation Offload
  auto-detect, Generic Receive Offload enabled.
  Use for general-purpose workloads or manual tuning.

- *"ultra_latency" (1):* Infinite busy-polling, no
  transmit/receive batching, TCP Segmentation Offload
  and Generic Receive Offload disabled, OS file
  descriptor polling disabled, 128 MB memory limit.
  Lowest latency and jitter but 100 percent CPU
  utilization. Non-offloaded sockets starve because
  OS polling is off. For trading, market data, and
  real-time control on dedicated cores.

- *"latency" (2):* Same as ultra_latency except OS
  polling is kept (select_poll_os_ratio 100) and the
  internal thread still runs (progress_engine_interval
  100 ms). Non-offloaded sockets remain functional.
  Use when ultra_latency causes socket starvation or
  the application mixes offloaded and non-offloaded
  traffic.

- *"nginx" (3):* Per-interface rings, TCP Segmentation
  Offload on, 3-tuple TCP steering, large send buffers
  (2 MB), slow timers (32 ms / 256 ms), epoll-
  optimized. Auto-enabled when
  [`applications.nginx.workers_num`](#applicationsnginxworkers_num) > 0 (must be set).
  Memory scales per worker (3-4 GB each). For HTTP
  proxies, load balancers, and web servers.

- *"nginx_dpu" (4):* Like nginx but with lower memory
  limits (512 MB - 1 GB per worker), no buffer
  batching, and no receive polling on transmit. For
  nginx running inside NVIDIA BlueField DPU.

- *"nvme_bf3" (5):* Large Receive Offload, TCP
  Segmentation Offload, large transmit batches
  (1024 Work Request Elements, signaled every 128),
  8192 strides per receive element, RST on close. For
  NVMe over Fabrics / SPDK on BlueField-3.

| Workload           | Profile           | CPU  | Latency | Thru |
|--------------------|-------------------|------|---------|------|
| Trading / mkt data | ultra_latency (1) | 100% | Lowest  | Low  |
| Real-time control  | ultra_latency (1) | 100% | Lowest  | Low  |
| Mixed latency      | latency (2)       | High | Low     | Med  |
| HTTP proxy / nginx | nginx (3)         | Med  | Higher  | High |
| nginx on BlueField | nginx_dpu (4)     | Med  | Higher  | High |
| NVMe-oF on BF3     | nvme_bf3 (5)      | Med  | Med     | High |
| General purpose    | none (0)          | Med  | Med     | Good |

**Default:** `"none" (0)`

