# XLIO Ultra API Ping-Pong Example

`xlio_ultra_api_ping_pong.c` is a simple example of a client-server application without complex
resources management. It's a staring point to get familiar with the XLIO Ultra API.

It demonstrates:
 * XLIO Ultra API initialization using indirect function calls
 * Polling group creation and event handling
 * Socket creation, connection, and data transmission
 * Simple TX buffer pool example with memory registration
 * Zero-copy send operations with completion callbacks
 * Zero-copy receive operations
 * Proper resource management and cleanup

Limitations:
 * Single-threaded example
 * Single socket management
 * Linkage against libxlio is out of scope
 * IPv4 only example
 * RX buffer is treated as a complete message while TCP stream doesn't guarantee this

The application is verbose. Simple usage:

```shell
# Build:
gcc -o xlio_ultra_api_ping_pong xlio_ultra_api_ping_pong.c -libverbs

# Print help message:
./xlio_ultra_api_ping_pong -h

# Server side
sudo LD_PRELOAD=libxlio.so ./xlio_ultra_api_ping_pong -s -i 192.168.0.1

# Client side
sudo LD_PRELOAD=libxlio.so ./xlio_ultra_api_ping_pong -c -i 192.168.0.1 -n 10
```
