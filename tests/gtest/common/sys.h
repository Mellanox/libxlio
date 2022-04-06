/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TESTS_GTEST_COMMON_SYS_H_
#define TESTS_GTEST_COMMON_SYS_H_

/* Minimum and maximum macros */
#define sys_max(a, b) (((a) > (b)) ? (a) : (b))
#define sys_min(a, b) (((a) < (b)) ? (a) : (b))

static INLINE int sys_is_big_endian(void)
{
    return (htonl(1) == 1);
}

static INLINE double sys_gettime(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (double)(tv.tv_sec * 1000000 + tv.tv_usec);
}

static INLINE uint64_t sys_rdtsc(void)
{
    unsigned long long int result = 0;

#if defined(__i386__)
    __asm volatile(".byte 0x0f, 0x31" : "=A"(result) :);

#elif defined(__x86_64__)
    unsigned hi, lo;
    __asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    result = hi;
    result = result << 32;
    result = result | lo;

#elif defined(__powerpc__)
    unsigned long int hi, lo, tmp;
    __asm volatile("0:                 \n\t"
                   "mftbu   %0         \n\t"
                   "mftb    %1         \n\t"
                   "mftbu   %2         \n\t"
                   "cmpw    %2,%0      \n\t"
                   "bne     0b         \n"
                   : "=r"(hi), "=r"(lo), "=r"(tmp));
    result = hi;
    result = result << 32;
    result = result | lo;

#endif

    return (result);
}

void sys_hexdump(const char *tag, void *ptr, int buflen);

pid_t sys_procpid(const char *name);

bool static INLINE sys_check_af(int family)
{
    return (family == AF_INET || family == AF_INET6);
}

static INLINE unsigned short sys_get_port(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
    case AF_INET:
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    case AF_INET6:
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    }
    return 0;
}

static INLINE void sys_set_port(struct sockaddr *addr, const unsigned short port)
{
    switch (addr->sa_family) {
    case AF_INET:
        ((struct sockaddr_in *)addr)->sin_port = htons(port);
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
        break;
    }
}

/**
 * Convert IPv4 address (as 32-bit unsigned integer) to IPv6 address:
 * add 96 bits prefix "::ffff:" to get IPv6 address "::ffff:a.b.c.d".
 */
static INLINE void sys_ipv4_to_ipv6(const struct in_addr *ipv4, struct in6_addr *ipv6)
{
    ipv6->s6_addr32[0] = 0x00000000;
    ipv6->s6_addr32[1] = 0x00000000;
    ipv6->s6_addr32[2] = htonl(0xffff);
    ipv6->s6_addr32[3] = *(uint32_t *)ipv4;
}

static INLINE bool sys_ipv6_addr_equal(const struct in6_addr *a1, const struct in6_addr *a2)
{
    return ((a1->s6_addr32[0] ^ a2->s6_addr32[0]) | (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
            (a1->s6_addr32[2] ^ a2->s6_addr32[2]) | (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;
}

int sys_get_addr(const char *dst, struct sockaddr *addr);

char *sys_addr2dev(const struct sockaddr *addr, char *buf, size_t size);

int sys_dev2addr(const char *dev, struct sockaddr *addr);

bool sys_gateway(struct sockaddr *addr, sa_family_t family);

void sys_str2addr(const char *buf, struct sockaddr *addr, bool port = true);

static INLINE char *sys_addr2str(const struct sockaddr *addr, bool port = true)
{
    static char buf[INET6_ADDRSTRLEN];
    static __thread char addrbuf[sizeof(buf) + 10];
    if (addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf));
    } else {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf));
    }

    if (port) {
        sprintf(addrbuf, "%s[%d]", buf, sys_get_port(addr));
    } else {
        sprintf(addrbuf, "%s", buf);
    }

    return addrbuf;
}

static INLINE int sys_rootuser(void)
{
    return (geteuid() == 0);
}

#endif /* TESTS_GTEST_COMMON_SYS_H_ */
