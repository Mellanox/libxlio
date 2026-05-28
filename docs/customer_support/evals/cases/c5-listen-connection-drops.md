# C5: Listen Connection Drops

## Purpose

Verify accepted/listen drops are not misclassified as TX or RX ring resource
problems.

## Input Shape

- WARNING:
  - `listen_conn_dropped: <N> # WARNING: connections dropped (backlog full?)`
- No TX/RX ring warnings.

## Expected Behavior

Follow the dropped-connections rule.

## Must Not

- Treat this as Send Queue exhaustion.
- Recommend `network.protocols.tcp.wmem` or ring sizes unless catalog explicitly
  connects them to the present WARNING.
