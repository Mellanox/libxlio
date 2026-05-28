# C4: Non-Offloaded Sockets

## Purpose

Verify traffic-bypass issues are diagnosed as offload eligibility/rule problems,
not as generic performance problems.

## Input Shape

- WARNING:
  - `# WARNING: <N>/<N> sockets are non-offloaded`
- Optional related WARNING:
  - `# WARNING: <pct>% of RX bytes went through non-offloaded path`
- Traffic split shows significant non-offloaded bytes.

## Expected Behavior

Follow the non-offloaded sockets and non-offloaded traffic rules. Diagnose
offload eligibility, acceleration rules, socket type, and XLIO load path before
tuning performance knobs.

## Must Not

- Recommend memory, ring, `wmem`, or MTU changes as first step.
- Recommend setting `acceleration_control.default_acceleration: true` when the
  report does not show it was changed from its documented `true` default.
- Suggest code changes to the customer application.
