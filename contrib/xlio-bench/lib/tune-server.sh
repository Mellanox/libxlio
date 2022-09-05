#!/bin/bash

# bash unofficial strict mode:
set -euo pipefail
IFS=$'\n\t'

# packages required: tuned, cpufrequtils
#
#   apt-get -y install tuned cpufrequtils
#

# Check system limits for both root and current user:
ROOT_LIMITS="$(sudo -i bash -c 'ulimit -n')"
USER_LIMITS="$(ulimit -n)"
if (( ROOT_LIMITS < 1000000 || USER_LIMITS < 1000000 )); then
    echo "Make sure you have proper limits configured for both root and current user $(whoam).
Current number of open files limits: root:$ROOT_LIMITS, $(whoami):$USER_LIMITS
To increase the limits, add following lines to your /etc/security/limits.conf:
*       soft    nofile  unlimited
*       soft    nofile  unlimited
root    hard    nofile  unlimited
root    hard    nofile  unlimited

and a following line to /etc/systemd/system.conf:
DefaultLimitNOFILE=10000000:10000000

and then reboot the system.
"
    exit 1
fi


for CPU in $(grep -E 'processor\s: ' /proc/cpuinfo | awk '{print $3}'); do
    cpufreq-set -g performance -r -c $CPU
done

echo 0 > /proc/sys/kernel/numa_balancing

tuned-adm profile latency-performance

modprobe ip_conntrack

{
sysctl -w net.ipv4.ip_local_port_range="1025 65535"
sysctl -w net.nf_conntrack_max=524288
sysctl -w net.netfilter.nf_conntrack_max=524288
sysctl -w net.ipv4.tcp_max_orphans=524288
sysctl -w net.ipv4.tcp_max_tw_buckets=524288
} > /dev/null # suppressing useless output

for IFACE in $(lshw -class network -short -quiet |grep MT.*Family | awk '{print $2}'); do
    ifconfig $IFACE mtu 1500
    ifconfig $IFACE txqueuelen 16000
done
