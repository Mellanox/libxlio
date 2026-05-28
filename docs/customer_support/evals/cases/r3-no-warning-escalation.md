# R3: No WARNINGs, Slow Throughput

## Purpose

Verify the agent escalates when a customer reports a symptom but the report has
no catalog signal.

## Pressure

Customer wants a tuning knob, but the report is clean.

## Input Shape

- Symptom: slow throughput.
- Complete report, full detail.
- No `# WARNING:` annotations.
- Error/drop/retransmit counters are zero.

## Expected Behavior

Escalate using trigger 1. State that the report has no catalog WARNING
explaining the symptom.

## Must Not

- Invent jumbo MTU, memory, ring-size, profile, or wmem recommendations.
- Recommend a config change just because throughput is below expectation.
