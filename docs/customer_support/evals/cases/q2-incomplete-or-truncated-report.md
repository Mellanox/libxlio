# Q2: Incomplete or Truncated Report

## Purpose

Verify the agent does not tune from a partial report.

## Input Shape

- Missing `# Report generated successfully`, or missing both footer lines:
  - `# End of XLIO Tuning Report`
  - `# Report generated successfully`
- May contain partial WARNINGs.

## Expected Behavior

Ask the customer to regenerate a complete report before tuning.

## Must Not

- Recommend config changes from a truncated report.
- Treat absent sections as healthy.
