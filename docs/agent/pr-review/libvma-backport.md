# libvma backport reference

libxlio was forked from libvma (VMA). A correctness fix in shared code should usually be backported to keep the still-maintained libvma stack correct.

## Lineage & maintenance

- libxlio = initial version on top of **VMA 9.2.2** (`CHANGES`: RM #2405040).
- libvma repo: `github.com/Mellanox/libvma`, **actively maintained** (commits into 2026).

## Path map (critical - do not guess)

libxlio renamed its own `src/vma/` tree to `src/core/` (`CHANGES`: RM #3064947 "Rename /vma directory with /core"). **libvma still uses `src/vma/`.** So:

- libxlio `src/core/<X>`  ->  libvma `src/vma/<X>`
- e.g. libxlio `src/core/lwip/tcp_in.c`  ->  libvma `src/vma/lwip/tcp_in.c`

When porting to libvma, do not assume it mirrors the XLIO rename: libvma still uses `src/vma/lwip/`, not `src/core/lwip/`.

## Shared vs XLIO-only

- **Shared ancestry (backport candidates):** `lwip/` (TCP core), `sock/`, `proto/` (except TLS), `util/`, `event/`, `iomux/`, `netlink/`, `dev/` (non-dpcp parts), `ib/`, `infra/`.
- **XLIO-only (do NOT backport):** `proto/tls*` and uTLS HW offload; anything referencing **dpcp**; DOCA; `config_printer` / `tuning_report`; `xlio_*`-named glue. libvma has no TLS offload and no dpcp.
- Divergence is real: libvma additionally has `lwip/cc_cubic.*` (not present in XLIO); both keep the `TCP_CC_ALGO_MOD` CC abstraction; line numbers differ because the files drifted after the fork.

## Method

1. Map the path (`src/core` -> `src/vma`).
2. **Verify the bug still exists in libvma's copy** - open the target file; it may have diverged. Do not assume.
3. **Manual port, not `git cherry-pick`.** The path rename + drift make a clean cherry-pick fail; apply the minimal change by hand and reference the libxlio issue in the libvma commit message.
4. Confirm any field the patch depends on exists in libvma (e.g. `pcb->nrtx` is present in libvma `src/vma/lwip/tcp.h`).
5. Re-validate on libvma's own CI/tests - do not assume XLIO's hardware evidence transfers.

## Decision

- Correctness fix in shared code -> backport candidate (YES).
- XLIO-only feature (uTLS / dpcp / DOCA) -> not applicable (NO).
- Behavior/perf change gated on XLIO-specific offload -> usually NO / needs judgement.
