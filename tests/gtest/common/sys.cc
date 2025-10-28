/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "sys.h"

#include <dirent.h>

void sys_hexdump(const char *tag, void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    char out_buf[256];
    int ret = 0;
    int out_pos = 0;
    int i, j;

    if (tag) {
        log_trace("%s\n", tag);
    }
    if (ptr) {
        return;
    }
    log_trace("dump data at %p\n", ptr);
    for (i = 0; i < buflen; i += 16) {
        out_pos = 0;
        ret = sprintf(out_buf + out_pos, "%06x: ", i);
        if (ret < 0) {
            return;
        }
        out_pos += ret;
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                ret = sprintf(out_buf + out_pos, "%02x ", buf[i + j]);
            } else {
                ret = sprintf(out_buf + out_pos, "   ");
            }
            if (ret < 0) {
                return;
            }
            out_pos += ret;
        }
        ret = sprintf(out_buf + out_pos, " ");
        if (ret < 0) {
            return;
        }
        out_pos += ret;
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                ret = sprintf(out_buf + out_pos, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
                if (ret < 0) {
                    return;
                }
                out_pos += ret;
            }
        }
        ret = sprintf(out_buf + out_pos, "\n");
        if (ret < 0) {
            return;
        }
        log_trace("%s", out_buf);
    }
}

int sys_get_addr(const char *dst, struct sockaddr *addr)
{
    int rc = 0;
    struct addrinfo *res;

    rc = getaddrinfo(dst, NULL, NULL, &res);
    if (rc) {
        log_error("getaddrinfo failed - invalid hostname or IP address\n");
        return rc;
    }

    if (!sys_check_af(res->ai_family)) {
        rc = -1;
        goto out;
    }

    addr->sa_family = res->ai_family;
    memcpy(addr, res->ai_addr, res->ai_addrlen);

out:
    freeaddrinfo(res);
    return rc;
}

bool sys_cmp_addr(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    if (addr1->sa_family == addr2->sa_family) {
        switch (addr1->sa_family) {
        case AF_INET:
            return (((struct sockaddr_in *)addr1)->sin_addr.s_addr ==
                    ((struct sockaddr_in *)addr2)->sin_addr.s_addr);
        case AF_INET6:
            return (sys_ipv6_addr_equal(&((const struct sockaddr_in6 *)addr1)->sin6_addr,
                                        &((const struct sockaddr_in6 *)addr2)->sin6_addr));
        }
    }
    return false;
}

char *sys_addr2dev(const struct sockaddr *addr, char *buf, size_t size)
{
    struct ifaddrs *interfaces;
    struct ifaddrs *ifa;

    if (buf && size && !getifaddrs(&interfaces)) {
        buf[0] = '\0';
        for (ifa = interfaces; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr) {
                if (sys_check_af(ifa->ifa_addr->sa_family)) {
                    if (sys_cmp_addr(ifa->ifa_addr, addr)) {
                        if (ifa->ifa_name) {
                            size_t n = sys_min(strlen(ifa->ifa_name), size - 1);
                            memcpy(buf, ifa->ifa_name, n);
                            buf[n] = '\0';
                            return buf;
                        }
                    }
                }
            }
        }
        freeifaddrs(interfaces);
    }

    return NULL;
}

// SIOCGIFADDR supports only IPv4.
int sys_dev2addr(const char *dev, struct sockaddr *addr)
{
    int rc = 0;
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        rc = -1;
        goto out;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = 0;
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);

    rc = ioctl(fd, SIOCGIFADDR, &ifr);
    if (rc >= 0 && addr) {
        memcpy(addr, &ifr.ifr_addr, sizeof(*addr));
    }

    close(fd);

out:
    return rc;
}

// Converts address to sockaddr structure. On an error, addr->sa_family is AF_UNSPEC.
void sys_str2addr(const char *buf, struct sockaddr *addr, bool port)
{
    char src[128];
    char *p;
    void *dst;
    int af;
    int rc;

    addr->sa_family = AF_UNSPEC;

    if (!buf) {
        return;
    }
    if (strlen(buf) >= sizeof(src)) {
        log_trace("Address '%s' is too long\n", buf);
    }

    snprintf(src, sizeof(src), "%s", buf);

    p = strchr(src, '[');
    if (p) {
        // Separate IP address from port.
        *p = '\0';
        ++p;
    }

    if (!strchr(src, ':')) {
        dst = &((struct sockaddr_in *)addr)->sin_addr;
        af = AF_INET;
    } else {
        struct sockaddr_in6 *addr6 = reinterpret_cast<struct sockaddr_in6 *>(addr);
        dst = &(addr6->sin6_addr);
        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;
        af = AF_INET6;
    }

    rc = inet_pton(af, src, dst);
    if (rc != 1) {
        log_trace("Failed to convert '%s' to IP (af=%d rc=%d errno=%d)\n", buf, af, rc, errno);
        return;
    }
    addr->sa_family = af;

    if (port) {
        if (p) {
            unsigned int port_value;
            // Opening '[' is removed above.
            if (sscanf(p, "%u]", &port_value) == 1 && port_value <= 65535) {
                sys_set_port(addr, port_value);
            }
        }
    }
}

pid_t sys_procpid(const char *name)
{
    DIR *dir;
    struct dirent *ent;
    char buf[512];
    long pid;
    char pname[100] = {0};
    char state;
    FILE *fp = NULL;

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        long lpid = atol(ent->d_name);
        if (lpid < 0) {
            continue;
        }
        snprintf(buf, sizeof(buf), "/proc/%ld/stat", lpid);
        fp = fopen(buf, "r");

        if (fp) {
            if ((fscanf(fp, "%ld (%[^)]) %c", &pid, pname, &state)) != 3) {
                printf("fscanf failed \n");
                fclose(fp);
                closedir(dir);
                return -1;
            }
            if (!strcmp(pname, name)) {
                fclose(fp);
                closedir(dir);
                return (pid_t)lpid;
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return -1;
}
