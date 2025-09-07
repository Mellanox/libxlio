# XLIO - Accelerated IO SW library

The NVIDIA® Accelerated IO (XLIO) SW library boosts the performance of TCP/IP network applications providing high bandwidth and low CPU usage.
XLIO is a user-space software library which exposes standard POSIX and XLIO Ultra socket APIs with kernel-bypass architecture, enabling a hardware-based direct copy between an application user-space memory and the network interface.

Coupling XLIO with Crypto Enabled NVIDIA ConnectX, NVIDIA BlueField data processing unit (DPU) acceleration capabilities, provides a breakthrough performance of Transport Layer Security (TLS) encryption and decryption.
XLIO is capable of utilizing HW features such as LRO/TSO and Striding-RQ which increase TCP performance, without application code changes for both
POSIX socket and XLIO Ultra APIs.

Please visit our [documentation website](https://docs.nvidia.com/networking/category/xlio) for more details.

<hr>

* [Getting Started](#getting-started)
* [Architecture](#architecture)
* [Supported Transports](#supported-transports)
* [Supported CPU Architectures](#supported-cpu-architectures)
* [Supported NICs](#supported-nics)
* [Licenses](#licenses)
* [Information](#information)
* [Contribution](#contribution)

<hr>

## Getting Started

### Installing XLIO

XLIO is available as part of DOCA Software Stack.
Please visit [DOCA website](https://developer.nvidia.com/networking/doca) for more details.

### Building XLIO

#### Prerequisits

##### DOCA Software stack

XLIO requires NVIDIA DOCA-Host software stack or NVIDIA Bluefiled bundle to be installed on the system.
Please visit [DOCA website](https://developer.nvidia.com/networking/doca) for more details.

##### DPCP

DPCP (Direct Packet Control Plane) is mandatory to run XLIO.
Repository: [libdpcp](https://github.com/Mellanox/libdpcp.git)

```sh
$ ./autogen.sh
$ ./configure --prefix=/where/to/install
$ make -j
$ make install
```

##### Tools

Autoconf, Automake, libtool, unzip, patch, libnl-devel (netlink 3)

#### Compiling XLIO

Run the following commands from within the directory at the top of the tree:

```sh
$ ./autogen.sh
$ ./configure --prefix=/where/to/install --with-dpcp=/where/dpcp/installed --enable-utls
$ make -j
$ make install
```
--enable-utls : Enables uTLS HW offload for supported NVIDIA HW.

#### Compiling XLIO using preinstalled dpcp

```sh
$ ./autogen.sh
$ ./configure --prefix=/where/to/install --with-dpcp --enable-utls
$ make -j
$ make install
```

#### Configure
See more [Options](./docs/configuration.md)

### Usage Examples

#### Sockperf

LD_PRELOAD=libxlio.so sockperf \<params\>

Reposiroty: [Sockperf](https://github.com/Mellanox/sockperf)

#### nginx

LD_PRELOAD=libxlio.so XLIO_NGINX_WORKERS_NUM=\<N\> nginx \<nginx_params\>

N - Number of Nginx workers.

## Architecture

![](docs/arch.png)

## Supported Transports

* IPv4/6
* TCP
* UDP

## Supported CPU Architecturess

* [x86_64](https://en.wikipedia.org/wiki/X86-64)
* [Arm](https://www.arm.com/)

## Supported HW

* Please refer to the [User Manual](https://docs.nvidia.com/networking/software/accelerator-software/index.html#xlio) for supported device list.

## Licenses
See [LICENSE](./LICENSE) file

## Information
See [README](./README) file for XLIO features and parameters.

## Contribution
[Contribution](./docs/contributing.md) guidelines for this project
