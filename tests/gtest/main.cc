/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <getopt.h>

#include "googletest/include/gtest/gtest.h"

#include "common/tap.h"
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"

static int _set_config(int argc, char **argv);
static int _def_config(void);
static void _usage(void);

struct gtest_configure_t gtest_conf;

int main(int argc, char **argv)
{
    // coverity[fun_call_w_exception]: uncaught exceptions cause nonzero exit anyway, so don't warn.
    ::testing::InitGoogleTest(&argc, argv);

    char *str = getenv("GTEST_TAP");
    /* Append TAP Listener */
    if (str) {
        if (0 < strtol(str, NULL, 0)) {
            testing::TestEventListeners &listeners = testing::UnitTest::GetInstance()->listeners();
            if (1 == strtol(str, NULL, 0)) {
                delete listeners.Release(listeners.default_result_printer());
            }
            listeners.Append(new tap::TapListener());
        }
    }

    _def_config();
    _set_config(argc, argv);

    return RUN_ALL_TESTS();
}

static int _def_config(void)
{
    int rc = 0;

    memset(&gtest_conf, 0, sizeof(gtest_conf));
    gtest_conf.log_level = 4;
    gtest_conf.random_seed = time(NULL) % 32768;

    sys_str2addr("0.0.0.0[0]", (struct sockaddr *)&gtest_conf.client_addr, true);
    sys_str2addr("0.0.0.0[0]", (struct sockaddr *)&gtest_conf.server_addr, true);
    sys_str2addr("192.0.2.1[8888]", (struct sockaddr *)&gtest_conf.remote_addr, true);
    sys_str2addr("127.0.0.1[8888]", (struct sockaddr *)&gtest_conf.remote_routable_addr, true);

    gtest_conf.port = 55555;

    return rc;
}

static void set_def_remote_address(bool user_defined_routable, bool user_defined_remote)
{
    if (gtest_conf.server_addr.addr.sa_family == AF_INET6) {
        if (!user_defined_remote) {
            // Replace IPv4 non-routable default with IPv6 non-routable address
            sys_str2addr("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff[8888]",
                         (struct sockaddr *)&gtest_conf.remote_addr, true);
        } else {
            // User provided -r, just ensure port is set
            gtest_conf.remote_addr.addr6.sin6_port = htons(8888);
        }
        if (!user_defined_routable) {
            // User didn't provide -g, use IPv6 localhost as default
            sys_str2addr("::1[8888]", (struct sockaddr *)&gtest_conf.remote_routable_addr, true);
        } else {
            // User provided -g, just ensure port is set
            gtest_conf.remote_routable_addr.addr6.sin6_port = htons(8888);
        }
    } else if (gtest_conf.server_addr.addr.sa_family == AF_INET) {
        gtest_conf.remote_addr.addr4.sin_port = htons(8888);
        gtest_conf.remote_routable_addr.addr4.sin_port = htons(8888);
    }
}

static int _set_config(int argc, char **argv)
{
    int rc = 0;
    static struct option long_options[] = {
        {"addr", required_argument, 0, 'a'},
        {"if", required_argument, 0, 'i'},
        {"remote-non-routable", required_argument, 0, 'r'},
        {"remote-routable", required_argument, 0, 'g'},
        {"port", required_argument, 0, 'p'},
        {"random", required_argument, 0, 's'},
        {"debug", required_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
    };
    int op;
    int option_index;
    bool user_defined_remote = false;
    bool user_defined_routable = false;

    while ((op = getopt_long(argc, argv, "a:i:r:g:p:d:h", long_options, &option_index)) != -1) {
        switch (op) {
        case 'a': {
            char *token1 = NULL;
            char *token2 = NULL;
            const char s[2] = ",";

            if (optarg) {
                if (optarg[0] != ',') {
                    token1 = strtok(optarg, s);
                    token2 = strtok(NULL, s);
                } else {
                    token1 = NULL;
                    token2 = strtok(optarg, s);
                }
            }

            if (token1) {
                rc = sys_get_addr(token1, &gtest_conf.client_addr.addr);
                if (rc < 0) {
                    rc = -EINVAL;
                    log_fatal("Failed to resolve ip address %s\n", token1);
                }
            }
            if (token2) {
                rc = sys_get_addr(token2, &gtest_conf.server_addr.addr);
                if (rc < 0) {
                    rc = -EINVAL;
                    log_fatal("Failed to resolve ip address %s\n", token2);
                }
            }
        } break;
        case 'i': {
            char *token1 = NULL;
            char *token2 = NULL;
            const char s[2] = ",";
            if (optarg) {
                if (optarg[0] != ',') {
                    token1 = strtok(optarg, s);
                    token2 = strtok(NULL, s);
                } else {
                    token1 = NULL;
                    token2 = strtok(optarg, s);
                }
            }

            if (token1) {
                rc = sys_dev2addr(token1, (struct sockaddr *)&gtest_conf.client_addr);
                if (rc < 0) {
                    rc = -EINVAL;
                    log_fatal("Failed to resolve ip address %s\n", token1);
                }
            }
            if (token2) {
                rc = sys_dev2addr(token2, (struct sockaddr *)&gtest_conf.server_addr);
                if (rc < 0) {
                    rc = -EINVAL;
                    log_fatal("Failed to resolve ip address %s\n", token2);
                }
            }
        } break;
        case 'r': {
            rc = sys_get_addr(optarg, (struct sockaddr *)&gtest_conf.remote_addr);
            if (rc < 0) {
                rc = -EINVAL;
                log_fatal("Failed to resolve ip address %s\n", optarg);
            } else {
                user_defined_remote = true;
            }
        } break;
        case 'g': {
            rc = sys_get_addr(optarg, (struct sockaddr *)&gtest_conf.remote_routable_addr);
            if (rc < 0) {
                rc = -EINVAL;
                log_fatal("Failed to resolve ip address %s\n", optarg);
            } else {
                user_defined_routable = true;
            }
        } break;
        case 'p':
            errno = 0;
            gtest_conf.port = strtol(optarg, NULL, 0);
            if (0 != errno) {
                rc = -EINVAL;
                log_error("Invalid option value <%s>\n", optarg);
            }
            break;
        case 's':
            errno = 0;
            gtest_conf.random_seed = strtol(optarg, NULL, 0);
            if (0 != errno) {
                rc = -EINVAL;
                log_error("Invalid option value <%s>\n", optarg);
            }
            break;
        case 'd':
            errno = 0;
            gtest_conf.log_level = strtol(optarg, NULL, 0);
            if (0 != errno) {
                rc = -EINVAL;
                log_error("Invalid option value <%s>\n", optarg);
            }
            break;
        case 'h':
            _usage();
            break;
        default:
            rc = -EINVAL;
            log_error("Unknown option <%c>\n", op);
            break;
        }
    }

    if (0 != rc) {
        _usage();
    } else {
        srand(gtest_conf.random_seed);
        sys_set_port((struct sockaddr *)&gtest_conf.server_addr, gtest_conf.port);

        set_def_remote_address(user_defined_routable, user_defined_remote);

        log_info("CONFIGURATION:\n");
        log_info("log level: %d\n", gtest_conf.log_level);
        log_info("seed: %d\n", gtest_conf.random_seed);
        log_info("client ip: %s\n", sys_addr2str((struct sockaddr *)&gtest_conf.client_addr));
        log_info("server ip: %s\n", sys_addr2str((struct sockaddr *)&gtest_conf.server_addr));
        log_info("remote ip: %s\n", sys_addr2str((struct sockaddr *)&gtest_conf.remote_addr));
        log_info("remote routable ip: %s\n",
                 sys_addr2str((struct sockaddr *)&gtest_conf.remote_routable_addr));
        log_info("port: %d\n", gtest_conf.port);
    }

    return rc;
}

static void _usage(void)
{
    printf("Usage: gtest [options]\n"
           "\t--addr,-a <ip,ip>                IP address client,server\n"
           "\t--if,-i <ip,ip>                  Interface client,server\n"
           "\t--remote-non-routable,-r <ip>    IP address not reachable\n"
           "\t--remote-routable,-g <ip>        IP address reachable\n"
           "\t--port,-p <num>                  Listen/connect to port <num> (default %d).\n"
           "\t--random,-s <count>              Seed (default %d).\n"
           "\t--debug,-d <level>               Output verbose level (default: %d).\n"
           "\t--help,-h                        Print help and exit\n",

           gtest_conf.port, gtest_conf.random_seed, gtest_conf.log_level);
    exit(0);
}
