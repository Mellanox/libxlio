# Requires root permissions
# Install scapy for root user: pip install scapy 

# To prevent Kernel to reply with RST to incoming traffic:
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <dst_ip> -j DROP

from scapy.all import *

src_ip = ''
dst_ip = ''
src_port = 0
dst_port = 0
option = 0

def send_raw_tcp_packet(flags, sequence):
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=sequence)
    pkt = ip/tcp
    send(pkt)

def send_syn():
    send_raw_tcp_packet('S', 0) # SYN flag

def send_syn_and_fin_packets():
    send_raw_tcp_packet('S', 0) # SYN flag
    send_raw_tcp_packet('F', 1) # FIN flag

def send_syn_and_rst_packets():
    send_raw_tcp_packet('S', 0) # SYN flag
    send_raw_tcp_packet('R', 1) # FIN flag

if (len(sys.argv) > 1):
    src_ip = sys.argv[1]

if (len(sys.argv) > 2):
    dst_ip = sys.argv[2]

if (len(sys.argv) > 3):
    src_port = int(sys.argv[3])

if (len(sys.argv) > 4):
    dst_port = int(sys.argv[4])

if (len(sys.argv) > 5):
    option = int(sys.argv[5])

match option:
    case 1:
        send_syn()
    case 2:
        send_syn_and_fin_packets()
    case 3:
        send_syn_and_rst_packets()
    case _:
        print("Usage: sudo python send_raw_packet.py <src_ip> <dst_ip> <src_port> <dst_port> <option>")
        print("Options:")
        print("1. Send SYN and FIN")
        print("2. Send SYN and RST")

    