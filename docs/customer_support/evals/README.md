# XLIO Customer Support Skill Eval Suite

Use these evals whenever `docs/customer_support/SKILL.md`,
`docs/xlio_tuning_report_reference.md`, or
`docs/xlio_config_reference.md` changes.

The goal is not to prove the skill can solve one known ticket. The goal is to
verify that an agent follows the catalog-driven process under pressure:

- match on WARNINGs, not vibes
- recommend one config change or one diagnostic step at a time
- avoid undocumented knobs
- avoid no-op recommendations
- avoid code changes
- escalate when the catalog does not justify a tuning change

## How to Run

For each case in `cases/`, start a fresh agent context and give it this harness:

```text
You are role-playing as the XLIO customer support agent.
Follow docs/customer_support/SKILL.md exactly.

Read before responding:
1. docs/customer_support/SKILL.md
2. docs/customer_support/evals/README.md
3. docs/customer_support/evals/cases/<case>.md
4. docs/xlio_tuning_report_reference.md
5. docs/xlio_config_reference.md

The customer message below already includes any available report. If a report is
present, skip intake and start at Phase 2.

After the customer-facing response, add:
=== AGENT DIAGNOSTIC LOG (for the test, not the customer) ===
1. Docs/sections read
2. WARNINGs matched, with target value > 0 or not
3. Why you recommended or escalated
4. Anti-patterns you avoided or were tempted by
```

## Pass Criteria

Each run passes only if all are true:

- Uses a catalog-backed WARNING rule or escalation trigger.
- Recommends at most one config change or one diagnostic step.
- Does not recommend a config knob absent from `xlio_config_reference.md`.
- Does not recommend setting a knob to its current/default value.
- Does not recommend code changes, rebuilds, patches, or debug instrumentation.
- States the expected indicator in the next report.
- Does not apply a rule whose target WARNING is absent or zero.
- Does not dismiss a present WARNING as benign unless the catalog says so.

## Case Index

### Regression Tests

- `cases/r1-canonical-wqe-exhaustion.md`
- `cases/r2-trap-no-wqe-exhaustion.md`
- `cases/r3-no-warning-escalation.md`

### Catalog Coverage Tests

- `cases/c1-buffer-pool-allocation-failures.md`
- `cases/c2-tcp-segment-pool-exhaustion.md`
- `cases/c3-hardware-rx-drops-plus-rx-buffer-failures.md`
- `cases/c4-non-offloaded-sockets.md`
- `cases/c5-listen-connection-drops.md`
- `cases/c6-low-poll-hit-rate-alone.md`

### Report Quality Tests

- `cases/q1-fallback-detail-report.md`
- `cases/q2-incomplete-or-truncated-report.md`
- `cases/q3-report-generation-error.md`
- `cases/q4-legacy-config-registry-unavailable.md`

### Perturbation Tests

- `cases/p1-same-rule-different-numbers.md`
- `cases/p2-misleading-customer-hypothesis.md`
- `cases/p3-extra-irrelevant-context.md`
- `cases/p4-section-reordering.md`
- `cases/p5-conflicting-prior-attempt.md`

## Minimum Release Gate

Before shipping the skill, run at least:

- R1, R2, R3
- one C* catalog-coverage case
- one Q* report-quality case
- one P* perturbation case

All must pass. If any fail, update `SKILL.md` with the exact rationalization the
agent used, then rerun the failing case.
