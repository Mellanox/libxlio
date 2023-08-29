# Configurion Options

This document describes the configuration options you may use during build procedure.

### --enable-opt-log

This option configures needed logging capacity for target binary.
There are following parameters such as `none`, `medium`, `high`.
Setting `none` include all possible logging levels in the library that can be controlled by `XLIO_TRACELEVEL` environment variable.

### --enable-symbol-visibility

This option manages by symbols visibility of the library.

### --enable-debug

This option manages  debugging information in the executable, such as the names of variables, the names of functions, and line numbers. This allows a debugger to step through code line by line, set breakpoints, and inspect the values of variables. Final binary file size is increased.

### --enable-nginx

This option allows to use the library with popular open source software for web serving, reverse proxying, caching, load balancing, media streaming, and more as NGINX.

### --enable-utls

This option enables uTLS HW offload for supported NVIDIA HW.

### --with-dpcp

This option allows to use DPCP library for programming Infiniband devices.
DPCP (Direct Packet Control Plane) is mandatory to enable advanced HW features for supported NVIDIA HW.
This library should be installed on your system.

Git repository: https://github.com/Mellanox/libdpcp

### --with-ibprof

This option enables socket api profiling information after application exit using libibprof profiling library.
This library should be installed on your system.

Git repository: https://github.com/mellanox-hpc/libibprof

Example:
```
env XLIO_TRACELEVEL=2 LD_PRELOAD=libxlio.so nc -v -n 192.168.3.168 -l 17000
Listening on 192.168.3.168 17000
Connection received on 192.168.3.27 50348
hello

===============================================================================================
libibprof, version 1.1.50
   compiled Aug 29 2023, 17:02:47

Copyright (C) 2013 Mellanox Technologies Ltd.
see http://www.mellanox.com/

date : 01.09.2023 12:14:00
host : bubik01-bf2
user : root
jobid : -1
rank : 23630
pid : 2317390
tid : 2317390
wall time (sec) : 8.97
command line : nc -v -n 192.168.3.168 -l 17000
path : /usr/bin/nc.openbsd
warmup number : 0
Output time unit : milliseconds
===============================================================================================

user                           :      count    total(ms)      avg(ms)      max(ms)      min(ms)
===============================================================================================
ioctl                          :        368     783.5805       2.1293      40.9300       0.0031
getsockname                    :         98       0.1483       0.0015       0.0021       0.0010
socket                         :         99       0.9151       0.0092       0.0720       0.0038
signal                         :          1       0.0021       0.0021       0.0021       0.0021
open                           :       1207      10.1724       0.0084       0.0830       0.0029
shutdown                       :          1       0.0010       0.0010       0.0010       0.0010
listen                         :          1      39.1870      39.1870      39.1870      39.1870
recvmsg                        :        780      17.9052       0.0230       0.1729       0.0000
bind                           :         98       0.3107       0.0032       0.0129       0.0010
write                          :          7       0.3922       0.0560       0.3512       0.0010
close                          :        445       7.8740       0.0177       2.3088       0.0000
xlio_init                      :          1       4.3840       4.3840       4.3840       4.3840
poll                           :          3    4732.3351    1577.4450    2919.4291       0.0179
fcntl                          :          3       0.0052       0.0017       0.0021       0.0010
sendmsg                        :        110       5.1398       0.0467       0.0830       0.0021
setsockopt                     :        204       0.3681       0.0018       0.0122       0.0000
xlio_ctors                     :          1    1039.0520    1039.0520    1039.0520    1039.0520
read                           :        271       4.0867       0.0151       2.9161       0.0010
xlio_exit                      :          1     154.7120     154.7120     154.7120     154.7120
accept4                        :          1    2996.8770    2996.8770    2996.8770    2996.8770
===============================================================================================
total                          :               9797.4484
===============================================================================================
wall time (%)                  :                  0.0011 %
===============================================================================================

```
