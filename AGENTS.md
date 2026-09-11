# AGENTS.md - libxlio

Guidance for AI coding agents (and humans) working in this repository. This is the vendor-neutral [AGENTS.md](https://agents.md) entry point; `CLAUDE.md` is a symlink to it. Product overview and general contribution rules live in `README.md` and `docs/`.

libxlio is NVIDIA's Accelerated IO (XLIO) user-space TCP/IP stack - a socket-API accelerator loaded via `LD_PRELOAD` that offloads TCP/UDP onto ConnectX / BlueField NICs (kernel bypass). Because it runs under real applications, subtle protocol bugs surface as application misbehavior, not as failing unit tests - review and test accordingly.

## Build

Requires the NVIDIA DOCA/OFED stack and `dpcp`.

```sh
./autogen.sh
./configure --prefix=<install-dir> --with-dpcp --enable-utls
make -j$(nproc)
```

- `--enable-utls` enables uTLS HW offload. Use profile flags (`--enable-debug`, `--with-asan`, ...) as needed; do not introduce a new build system.
- The library that `LD_PRELOAD` uses after a build is `src/core/.libs/libxlio.so`, not a system-installed `/usr/lib64/libxlio.so`.

## Test

```sh
make tests   # builds the gtest and unit_tests suites
```

- Suites: `tests/unit_tests/unit_tests` and `tests/gtest/gtest`.
- Raw-packet paths need `CAP_NET_RAW`; without it some tests silently fall back and pass without exercising the real path - run with the capability and verify.
- After a fresh checkout the first run can panic with `... -1/tasks` (an ODR issue in `mce_sys_var`); fix with `make clean && make -j`, not with env workarounds.

## Contributing

See `docs/contributing.md` and `docs/coding-style.md`. Commits require a DCO `Signed-off-by` (`git commit -s`) and a header of the form `issue: <number> <summary>` (<= 100 columns). Do not hand-edit `CHANGES` or other generated files.

## Reviewing changes (AI or human)

For any pull-request review, follow **`docs/agent/pr-review/review-guide.md`**. It defines the output/severity contract, the public-repo confidentiality rule (cite internal links, never paste confidential content into a public PR), the hardware-evidence bar for data-path changes, the coverage checklist, and two reference catalogs:

- `docs/agent/pr-review/libvma-backport.md` - the libvma fork map (`src/core` <-> `src/vma`), shared vs XLIO-only areas, and the backport method.
- `docs/agent/pr-review/tcp-deviations.md` - RFC-to-code map, XLIO's accepted deviations, and known Linux-kernel-TCP deviations.

Scrutinize socket-API compatibility, TCP/UDP correctness, retransmission/RTO/timers, `fork`/`exec` and init-order (ODR), buffer/packet and DMA lifetime, offload (LRO/TSO/uTLS), locking/races, and performance. Do not change public socket behavior silently - gate a behavioral change behind a config knob or escalate it.
