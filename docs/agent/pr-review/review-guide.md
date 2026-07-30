# libxlio PR review guide

How to review a pull request to libxlio (`Mellanox/libxlio`, public, branch `vNext`). Applies to an automated reviewer running in CI and to a human or agent reviewing locally. libxlio is `LD_PRELOAD`ed under real socket applications, so subtle protocol bugs surface as application misbehavior, not as failing unit tests.

A capable reviewer already knows TCP and can read code; this guide exists to make reviews **consistent, complete, correctly formatted, and safe in a public repo**, and to supply XLIO-specific facts (the libvma fork map, XLIO's accepted RFC/Linux deviations) that a sandboxed CI runner may not be able to look up.

## Output contract

Every finding on one line: `severity | file:line | what & why | citation`. Severities:

- `must-fix` - correctness / socket-API compatibility / security / protocol bug, or a data-path change missing its required hardware evidence.
- `should-fix` - a real issue, not a merge blocker.
- `question` - needs author intent (may be an intentional deviation).
- `nit` - style / clarity.

End with one verdict line: `merge` / `no-merge` / `needs-evidence`. Cite the RFC section, Linux behavior, or repo rule you invoke - do not assert a standard without a reference.

## Non-negotiables

1. **Public-repo confidentiality.** libxlio is public. When you consult an internal knowledge base, **cite the link only - never paste confidential text, internal host/rig names, ticket IDs, measured numbers, or internal decision records into the PR comment.** Write "contradicts internal design doc `<link>`", not its contents. Never post embargoed or unreleased detail to a public PR.
2. **Evidence bar for data-path changes.** For any change to TCP/UDP behavior, retransmission / RTO / timers, congestion control, offload (LRO/TSO/uTLS), or buffer/packet lifetime: unit and gtest passing is **not** sufficient - require a reproduce-then-fix (RED-GREEN) result on real hardware. If it is absent, that point is `must-fix` and the verdict is `needs-evidence`.
3. **No silent behavior/ABI change.** Flag any change to socket-API semantics or on-wire behavior that is not gated by a config knob or documented.

## Coverage checklist (walk every time)

For each changed hunk: socket-API compatibility; epoll/select/poll; blocking vs non-blocking; TCP/UDP correctness; retransmission / RTO / timers; fork/exec/thread and `LD_PRELOAD` init order (ODR); buffer & packet ownership and DMA-buffer lifetime; checksum/endian; offload (LRO/TSO/Striding-RQ, uTLS); lock ordering / races; error-path cleanup / leaks; performance regressions.

Then the two XLIO-specific dimensions, using the catalogs below:

- **libvma backport** - does the hunk touch code shared with libvma? See `libvma-backport.md`.
- **RFC / Linux-TCP deviation** - does it introduce or rely on a deviation? Is it an *accepted* XLIO deviation (do not flag) or a new/unintended one (flag)? See `tcp-deviations.md`.

## Reference catalogs

- `libvma-backport.md` - fork lineage, the `src/core` <-> `src/vma` path map, shared vs XLIO-only areas, and the manual-port method. A sandboxed runner may not have a libvma checkout - trust this file over guessing the path.
- `tcp-deviations.md` - RFC-to-code map, XLIO's accepted deviations (not bugs), and known Linux-kernel-TCP deviations (app-compat).

## Red flags - stop and correct yourself

- About to paste internal KB text / a host name / a ticket number / a measured number into a public comment -> cite the link instead.
- About to approve a TCP / RTO / CC / offload change because "the code looks right", with no hardware evidence -> the verdict is `needs-evidence`.
- About to state a libvma path from memory -> check `libvma-backport.md`. libvma uses `src/vma/...`, not `src/core/...` (the rename happened in libxlio).
- About to flag a deviation as `must-fix` -> check `tcp-deviations.md`; if it is an accepted XLIO deviation, it is not a bug.
