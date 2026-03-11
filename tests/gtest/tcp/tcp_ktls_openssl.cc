/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"
#include "common/utils.h"

#if defined(DEFINED_UTLS)

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include "tcp_base.h"

#include "config.h"

class tcp_ktls_openssl : public tcp_base {
protected:
    void SetUp() override
    {
        tcp_base::SetUp();
        errno = 0;
    }

    /* Create a minimal self-signed cert and key, write to temp files, load into ctx. */
    static int ssl_ctx_use_self_signed(SSL_CTX *ctx)
    {
        log_trace("ssl_ctx_use_self_signed(): Called\n");
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!kctx) {
            log_trace("ssl_ctx_use_self_signed(): EVP_PKEY_CTX_new_id() failed\n");
            return -1;
        }

        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
            EVP_PKEY_keygen(kctx, &pkey) <= 0 || !pkey) {
            EVP_PKEY_CTX_free(kctx);
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
            log_trace(
                "ssl_ctx_use_self_signed(): EVP_PKEY_keygen_init() or a friend of it failed\n");
            return -1;
        }
        EVP_PKEY_CTX_free(kctx);

        X509 *cert = X509_new();
        if (!cert) {
            log_trace("ssl_ctx_use_self_signed(): X509_new() failed\n");
            EVP_PKEY_free(pkey);
            return -1;
        }

        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 86400L * 365);

        X509_NAME *name = X509_get_subject_name(cert);
        if (!name ||
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("localhost"), -1, -1,
                                       0) != 1) {
            X509_free(cert);
            EVP_PKEY_free(pkey);
            log_trace("ssl_ctx_use_self_signed(): X509_NAME_add_entry_by_txt() failed\n");
            return -1;
        }
        X509_set_issuer_name(cert, name);
        X509_set_pubkey(cert, pkey);

        if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
            X509_free(cert);
            EVP_PKEY_free(pkey);
            log_trace("ssl_ctx_use_self_signed(): X509_sign() failed\n");
            return -1;
        }

        char key_file[] = "/tmp/xlio_ktls_key_XXXXXX";
        char cert_file[] = "/tmp/xlio_ktls_cert_XXXXXX";
        int key_fd = mkstemp(key_file);
        int cert_fd = mkstemp(cert_file);
        log_trace("ssl_ctx_use_self_signed(): after_open key_fd=%d cert_fd=%d\n", key_fd, cert_fd);
        if (key_fd < 0 || cert_fd < 0) {
            if (key_fd >= 0) {
                unlink(key_file);
                close(key_fd);
            }
            if (cert_fd >= 0) {
                unlink(cert_file);
                close(cert_fd);
            }
            X509_free(cert);
            EVP_PKEY_free(pkey);
            log_trace("ssl_ctx_use_self_signed(): mkstemp(%s) or mkstemp(%s) failed\n", key_file,
                      cert_file);
            return -1;
        }

        FILE *key_fp = fdopen(key_fd, "w");
        FILE *cert_fp = fdopen(cert_fd, "w");
        if (!key_fp || !cert_fp) {
            if (key_fp) {
                fclose(key_fp);
            } else if (key_fd >= 0) {
                close(key_fd);
            }
            if (cert_fp) {
                fclose(cert_fp);
            } else if (cert_fd >= 0) {
                close(cert_fd);
            }
            unlink(key_file);
            unlink(cert_file);
            X509_free(cert);
            EVP_PKEY_free(pkey);
            log_trace("ssl_ctx_use_self_signed(): fdopen(%s) or fdopen(%s) failed\n", key_file,
                      cert_file);
            return -1;
        }

        int ret = -1;
        if (PEM_write_PrivateKey(key_fp, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1 &&
            PEM_write_X509(cert_fp, cert) == 1) {
            fflush(key_fp);
            fflush(cert_fp);
            fclose(key_fp);
            fclose(cert_fp);
            if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
                log_trace("ssl_ctx_use_self_signed(): SSL_CTX_use_certificate_file() failed.");
                ERR_print_errors_fp(stderr);
            } else if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
                log_trace("ssl_ctx_use_self_signed(): SSL_CTX_use_PrivateKey_file() failed.");
                ERR_print_errors_fp(stderr);
            } else if (SSL_CTX_check_private_key(ctx) != 1) {
                log_trace("ssl_ctx_use_self_signed(): SSL_CTX_check_private_key() failed.");
                ERR_print_errors_fp(stderr);
            } else {
                ret = 0;
            }
        } else {
            fclose(key_fp);
            fclose(cert_fp);
            log_trace(
                "ssl_ctx_use_self_signed(): PEM_write_PrivateKey() or PEM_write_X509() failed\n");
        }

        unlink(key_file);
        unlink(cert_file);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        log_trace("ssl_ctx_use_self_signed(): Returning %d\n", ret);
        return ret;
    }

    /* --- Server helpers (run in parent) --- */

    SSL_CTX *create_server_ctx()
    {
        log_trace("create_server_ctx(): enter\n");
        SSL_library_init();
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            log_trace("create_server_ctx(): SSL_CTX_new failed\n");
            return nullptr;
        }
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        if (ssl_ctx_use_self_signed(ctx) != 0) {
            log_trace("create_server_ctx(): ssl_ctx_use_self_signed failed\n");
            SSL_CTX_free(ctx);
            return nullptr;
        }
        log_trace("create_server_ctx(): ok\n");
        return ctx;
    }

    int server_listen()
    {
        log_trace("server_listen(): enter\n");
        int l_fd = sock_create();
        if (l_fd < 0) {
            log_trace("server_listen(): sock_create failed\n");
            return -1;
        }
        if (bind(l_fd, reinterpret_cast<struct sockaddr *>(&server_addr), sizeof(server_addr)) !=
            0) {
            log_trace("server_listen(): bind failed errno=%d\n", errno);
            close(l_fd);
            return -1;
        }
        if (listen(l_fd, 5) != 0) {
            log_trace("server_listen(): listen failed errno=%d\n", errno);
            close(l_fd);
            return -1;
        }
        log_trace("server_listen(): returning l_fd=%d\n", l_fd);
        return l_fd;
    }

    SSL *server_accept_ssl(int l_fd, SSL_CTX *ctx)
    {
        log_trace("server_accept_ssl(): enter l_fd=%d\n", l_fd);
        struct sockaddr_storage peer_addr;
        socklen_t socklen = sizeof(peer_addr);
        int fd = accept(l_fd, reinterpret_cast<struct sockaddr *>(&peer_addr), &socklen);
        if (fd < 0) {
            log_trace("server_accept_ssl(): accept failed errno=%d\n", errno);
            return nullptr;
        }
        log_trace("server_accept_ssl(): accepted fd=%d\n", fd);
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            log_trace("server_accept_ssl(): SSL_new failed\n");
            close(fd);
            return nullptr;
        }
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) <= 0) {
            log_trace("server_accept_ssl(): SSL_accept failed: %s\n",
                      ERR_error_string(ERR_get_error(), nullptr));
            SSL_free(ssl);
            close(fd);
            return nullptr;
        }
        log_trace("server_accept_ssl(): returning ssl->fd=%d\n", fd);
        return ssl;
    }

    int server_exchange(SSL *ssl, void *recv_buf, size_t recv_len, const void *send_buf,
                        size_t send_len)
    {
        int fd = SSL_get_fd(ssl);
        log_trace("server_exchange(ssl->fd=%d): enter recv_len=%zu send_len=%zu\n", fd, recv_len,
                  send_len);
        size_t total_read = SSL_read(ssl, recv_buf, recv_len);
        log_trace("server_exchange(ssl->fd=%d): total_read=%zu\n", fd, total_read);
        if (total_read != recv_len) {
            log_trace("server_exchange(ssl->fd=%d): SSL_read failed\n", fd);
            return -1;
        }
        size_t total_written = SSL_write(ssl, send_buf, send_len);
        log_trace("server_exchange(ssl->fd=%d): total_written=%zu\n", fd, total_written);
        if (total_written != send_len) {
            log_trace("server_exchange(ssl->fd=%d): SSL_write failed\n", fd);
            return -1;
        }
        log_trace("server_exchange(ssl->fd=%d): ok\n", fd);
        return 0;
    }

    void server_close_connection(SSL *ssl)
    {
        int fd = SSL_get_fd(ssl);
        log_trace("server_close_connection(fd=%d): called\n", fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        if (fd >= 0) {
            close(fd);
        }
    }

    /* --- Client helpers (run in child) --- */

    SSL_CTX *create_client_ctx()
    {
        log_trace("create_client_ctx(): enter\n");
        SSL_library_init();
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            log_trace("create_client_ctx(): SSL_CTX_new failed\n");
            return nullptr;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        log_trace("create_client_ctx(): ok\n");
        return ctx;
    }

    SSL *client_connect_ssl(SSL_CTX *ctx, bool request_ktls)
    {
        log_trace("client_connect_ssl(): enter\n");
        int fd = sock_create();
        if (fd < 0) {
            log_trace("client_connect_ssl(): sock_create failed\n");
            return nullptr;
        }
        if (bind(fd, reinterpret_cast<struct sockaddr *>(&client_addr), sizeof(client_addr)) != 0) {
            log_trace("client_connect_ssl(): fd=%d, bind failed errno=%d\n", fd, errno);
            close(fd);
            return nullptr;
        }
        if (connect(fd, reinterpret_cast<struct sockaddr *>(&server_addr), sizeof(server_addr)) !=
            0) {
            log_trace("client_connect_ssl(): fd=%d, connect failed errno=%d\n", fd, errno);
            close(fd);
            return nullptr;
        }
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            log_trace("client_connect_ssl(): fd=%d, SSL_new failed\n", fd);
            close(fd);
            return nullptr;
        }
        SSL_set_fd(ssl, fd);
        if (request_ktls) {
            SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);
        }
        if (SSL_connect(ssl) <= 0) {
            log_trace("client_connect_ssl(): fd=%d, SSL_connect failed: %s\n", fd,
                      ERR_error_string(ERR_get_error(), nullptr));
            SSL_free(ssl);
            close(fd);
            return nullptr;
        }
        log_trace("client_connect_ssl(): ok fd=%d\n", fd);
        return ssl;
    }

    int client_exchange(SSL *ssl, const void *send_buf, size_t send_len, void *recv_buf,
                        size_t recv_len)
    {
        int fd = SSL_get_fd(ssl);
        log_trace("client_exchange(ssl->fd=%d): enter send_len=%zu recv_len=%zu\n", fd, send_len,
                  recv_len);
        size_t total_written = SSL_write(ssl, send_buf, send_len);
        log_trace("client_exchange(ssl->fd=%d): total_written=%zu\n", fd, total_written);
        if (total_written != send_len) {
            log_trace("client_exchange(ssl->fd=%d): SSL_write failed\n", fd);
            return -1;
        }
        size_t total_read = SSL_read(ssl, recv_buf, recv_len);
        log_trace("client_exchange(ssl->fd=%d): total_read=%zu\n", fd, total_read);
        if (total_read != recv_len) {
            log_trace("client_exchange(ssl->fd=%d): SSL_read failed\n", fd);
            return -1;
        }
        log_trace("client_exchange(ssl->fd=%d): ok\n", fd);
        return 0;
    }

    void client_close_connection(SSL *ssl)
    {
        int fd = SSL_get_fd(ssl);
        log_trace("client_close_connection(fd=%d): called\n", fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        if (fd >= 0) {
            close(fd);
        }
    }

    bool is_ktls_tx_active(SSL *ssl)
    {
        log_trace("is_ktls_tx_active(ssl->fd=%d): called\n", SSL_get_fd(ssl));
        int tx = BIO_get_ktls_send(SSL_get_wbio(ssl));
        bool ret = (tx == 1);
        log_trace("is_ktls_tx_active(ssl->fd=%d): Returning %d\n", SSL_get_fd(ssl), ret);
        return ret;
    }
};

/**
 * @test tcp_ktls_openssl.ktls_tx_one_connection_ktls
 * @brief
 *    Use OpenSSL to establish a TLS connection with KTLS (TX HW acceleration)
 *    and exchange data in both directions.
 */
TEST_F(tcp_ktls_openssl, ktls_tx_one_connection)
{
    const char client_msg[] = "client_hello_ktls";
    const char server_msg[] = "server_hello_ktls";

    for (bool request_ktls : {true, false}) {
        log_trace("\n");
        log_trace("=== ktls_tx_one_connection(): request_ktls=%d\n", request_ktls);
        log_trace("=============================================\n");
        int pid = fork();

        if (0 == pid) { /* child = client */
            barrier_fork(pid);

            SSL_CTX *ctx = create_client_ctx();
            ASSERT_TRUE(ctx != nullptr);

            SSL *ssl = client_connect_ssl(ctx, request_ktls);
            ASSERT_TRUE(ssl != nullptr)
                << "SSL_connect failed: " << ERR_error_string(ERR_get_error(), nullptr);

            bool ktls_tx_active = is_ktls_tx_active(ssl);
            ASSERT_EQ(request_ktls, ktls_tx_active);

            char buf[sizeof(server_msg)];
            int rc = client_exchange(ssl, client_msg, sizeof(client_msg), buf, sizeof(buf));
            ASSERT_EQ(0, rc);
            EXPECT_EQ(0, memcmp(buf, server_msg, sizeof(server_msg)));

            client_close_connection(ssl);
            SSL_CTX_free(ctx);

            exit(testing::Test::HasFailure());
        } else { /* parent = server */
            SSL_CTX *ctx = create_server_ctx();
            if (!ctx) {
                GTEST_SKIP() << "Could not create self-signed cert for server (OpenSSL or env)";
            }

            int l_fd = server_listen();
            ASSERT_GE(l_fd, 0) << "errno=" << errno << " " << strerror(errno);

            barrier_fork(pid);

            SSL *ssl = server_accept_ssl(l_fd, ctx);
            ASSERT_TRUE(ssl != nullptr)
                << "SSL_accept failed: " << ERR_error_string(ERR_get_error(), nullptr);

            char buf[sizeof(client_msg)];
            int rc = server_exchange(ssl, buf, sizeof(buf), server_msg, sizeof(server_msg));
            ASSERT_EQ(0, rc);
            EXPECT_EQ(0, memcmp(buf, client_msg, sizeof(client_msg)));

            server_close_connection(ssl);
            close(l_fd);
            SSL_CTX_free(ctx);

            ASSERT_EQ(0, wait_fork(pid));
        }
    }
}

/**
 * @test tcp_ktls_openssl.ktls_tx_ten_connections_first_five_ktls
 * @brief
 *    Establish 10 concurrent TLS connections, request KTLS on all,
 *    expect KTLS TX to be active only on the first 5 (e.g. resource limit).
 *    Do this 3 times to ensure that counter is decremented on close properly.
 *
 *    NOTE: This test should be run with XLIO_UTLS_MAX_SESSIONS set to 5.
 *          In the future, this test should either re-init XLIO with the proper env so that we
 *          do not depend on an outside runner to set the env, OR the test should launch a new
 *          executable containint its functionality, with a propely configured env.
 *          Right now we are just a POC so this requirement is good enough.
 */
TEST_F(tcp_ktls_openssl, ktls_tx_ten_connections_first_five_ktls)
{
    static const int k_ktls_ten_connections = 10;
    static const int k_ktls_expected_active = 5;
    static const int k_loops = 3;

    // If XLIO_UTLS_MAX_SESSIONS is not set to 5 in the env or inline config, skip test */
    if ((std::string(getenv("XLIO_UTLS_MAX_SESSIONS") ?: "") !=
         std::to_string(k_ktls_expected_active)) &&
        (std::string(getenv("XLIO_INLINE_CONFIG") ?: "")
             .find("hardware_features.tcp.tls_offload.max_sessions=" +
                   std::to_string(k_ktls_expected_active)) == std::string::npos)) {
        log_info("XLIO_UTLS_MAX_SESSIONS is not set to %d in the env or inline config, skipping "
                 "test\n",
                 k_ktls_expected_active);
        GTEST_SKIP();
    }

    const char client_msg[] = "client_hello_ktls";
    const char server_msg[] = "server_hello_ktls";

    int port = m_port;
    std::string server_addr_str =
        sys_addr2str(reinterpret_cast<struct sockaddr *>(&server_addr), false);
    std::string client_addr_str =
        sys_addr2str(reinterpret_cast<struct sockaddr *>(&client_addr), false);

    log_trace("client: port = %d\n", port);
    log_trace("client: server_addr = %s\n", server_addr_str.c_str());
    log_trace("client: client_addr = %s\n", client_addr_str.c_str());

    int pid = fork();

    if (0 == pid) { /* child = client */
        barrier_fork(pid);
        log_trace("client: pid = %d\n", getpid());

        SSL_CTX *ctx = create_client_ctx();
        ASSERT_TRUE(ctx != nullptr);

        SSL *connections[k_ktls_ten_connections];
        for (int loop = 0; loop < k_loops; ++loop) {
            log_trace("client: Beginning loop %d\n", loop);

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                connections[i] = client_connect_ssl(ctx, true); /* request KTLS on all */
                ASSERT_TRUE(connections[i] != nullptr)
                    << "loop " << loop << ", connection " << i << " failed";
            }

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                bool ktls_active = is_ktls_tx_active(connections[i]);
                bool expect_ktls = (i < k_ktls_expected_active);
                EXPECT_EQ(expect_ktls, ktls_active)
                    << "loop " << loop << ", connection " << i << ": expected KTLS=" << expect_ktls
                    << " got " << ktls_active;
            }

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                char buf[sizeof(server_msg)];
                int rc = client_exchange(connections[i], client_msg, sizeof(client_msg), buf,
                                         sizeof(buf));
                ASSERT_EQ(0, rc) << "loop " << loop << ", connection " << i;
                EXPECT_EQ(0, memcmp(buf, server_msg, sizeof(server_msg)));
            }

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                client_close_connection(connections[i]);
            }

            if (!utils::wait_for_connections_to_close(
                    sys_addr2str(reinterpret_cast<struct sockaddr *>(&server_addr), false), m_port,
                    10)) {
                log_error("client: wait_for_connections_to_close failed\n");
                exit(testing::Test::HasFailure());
            }
        }
        SSL_CTX_free(ctx);

        exit(testing::Test::HasFailure());
    } else { /* parent = server */
        log_trace("server: pid = %d\n", getpid());

        SSL_CTX *ctx = create_server_ctx();
        if (!ctx) {
            GTEST_SKIP() << "Could not create self-signed cert for server (OpenSSL or env)";
        }

        int l_fd = server_listen();
        ASSERT_GE(l_fd, 0) << "errno=" << errno << " " << strerror(errno);

        barrier_fork(pid);

        SSL *connections[k_ktls_ten_connections];
        for (int loop = 0; loop < k_loops; ++loop) {
            log_trace("server: Beginning loop %d\n", loop);

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                connections[i] = server_accept_ssl(l_fd, ctx);
                ASSERT_TRUE(connections[i] != nullptr)
                    << "loop " << loop << ", accept " << i << " failed";
            }

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                char buf[sizeof(client_msg)];
                int rc = server_exchange(connections[i], buf, sizeof(buf), server_msg,
                                         sizeof(server_msg));
                ASSERT_EQ(0, rc) << "loop " << loop << ", connection " << i;
                EXPECT_EQ(0, memcmp(buf, client_msg, sizeof(client_msg)));
            }

            for (int i = 0; i < k_ktls_ten_connections; i++) {
                server_close_connection(connections[i]);
            }
        }
        close(l_fd);
        SSL_CTX_free(ctx);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

#else /* DEFINED_UTLS */

#include "tcp_base.h"

class tcp_ktls_openssl : public tcp_base {};

TEST_F(tcp_ktls_openssl, skip_no_utls)
{
    GTEST_SKIP() << "UTLS/KTLS are not enabled (build without DEFINED_UTLS or SSL_OP_ENABLE_KTLS)";
}

#endif /* DEFINED_UTLS */
