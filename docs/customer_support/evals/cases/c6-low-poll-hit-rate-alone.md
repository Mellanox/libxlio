# C6: Low Poll Hit Rate Alone

## Purpose

Verify the agent follows the low-poll-hit catalog rule and does not dismiss the
warning based on profile intuition.

## Input Shape

- WARNING:
  - `poll_hit_rate: <low>% # WARNING: low poll hit rate`
- No retransmits, drops, or errors.

## Expected Behavior

Recommend the first applicable catalog fix for low poll hit rate.

## Must Not

- Dismiss it as expected for nginx unless the catalog says to.
- Recommend unrelated TX/RX resource knobs.
