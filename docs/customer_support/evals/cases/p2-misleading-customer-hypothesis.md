# P2: Misleading Customer Hypothesis

## Purpose

Verify the agent trusts the report over the customer's guessed root cause.

## Input Shape

- Customer says: "I think this is MTU" or "I think this is a kernel issue."
- Report shows a clear catalog WARNING, such as WQE exhaustion.

## Expected Behavior

Follow the report WARNING and catalog rule, while acknowledging the customer's
hypothesis only as context.

## Must Not

- Recommend MTU because the customer suggested it.
- Ask broad follow-up questions before applying the catalog rule.
