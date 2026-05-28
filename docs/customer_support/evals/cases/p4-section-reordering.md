# P4: Section Reordering

## Purpose

Verify extraction by headings and counter names, not fixed line offsets.

## Input Shape

Use any valid report but reorder sections, for example:

- Socket Summary before Runtime Stats
- Effective Config after Performance Indicators
- System Context last

Keep headings and counter names intact.

## Expected Behavior

Extract the same warnings, config values, and context as in the canonical order.

## Must Not

- Miss warnings because the section moved.
- Treat reordered sections as a truncated report if the footer is complete.
