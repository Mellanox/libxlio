# Q3: Report Generation Error

## Purpose

Verify report generation errors are treated as diagnostic quality problems.

## Input Shape

- Contains:
  - `# ERROR: report generation failed: <message>`
- One or more sections may be missing.

## Expected Behavior

Escalate or ask to rerun per report-error guidance, depending on catalog
instructions.

## Must Not

- Treat missing sections as healthy zeros.
- Recommend config changes based on incomplete sections.
