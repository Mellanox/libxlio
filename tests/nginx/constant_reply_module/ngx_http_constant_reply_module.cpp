/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
}

#include <unordered_map>

#define REPLY_CONTENT_TYPE "text/plain"

static char *ngx_http_constant_reply(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_constant_reply_handler(ngx_http_request_t *r);

// Module config
static ngx_command_t ngx_http_constant_reply_commands[] = {
    {
        ngx_string("constant_reply"),      // Config name
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, // Conf locations and args
        ngx_http_constant_reply, // Initialization method
        0,
        0,
        nullptr
    },
    ngx_null_command
};

// HTTP Module context
static ngx_http_module_t ngx_http_constant_reply_module_ctx = {
    NULL, // Pre config
    NULL, // Post config
    NULL, // Main config create
    NULL, // Main config init
    NULL, // Server conf create
    NULL, // Server conf merge
    NULL, // Location config create
    NULL  // Location config merge
};

// Nginx Module definition
ngx_module_t ngx_http_constant_reply_module = {
    NGX_MODULE_V1,
    &ngx_http_constant_reply_module_ctx, // Context
    ngx_http_constant_reply_commands, // Commands
    NGX_HTTP_MODULE, // Type HTTP
    NULL, // Master init
    NULL, // Module init
    NULL, // Process init
    NULL, // Thread init
    NULL, // Thread exit
    NULL, // Process exit
    NULL, // Master exit
    NGX_MODULE_V1_PADDING
};

struct reply_buffer
{
    reply_buffer(u_char *out_b, u_char *out_b_end):
        out_buffer(out_b),
        out_buffer_end(out_b_end) {}
    u_char *out_buffer = 0;
    u_char *out_buffer_end = 0;
};

static std::unordered_map<off_t, reply_buffer> g_constant_reply_buffers;
static long long g_max_off_t = (1ULL << ((sizeof(off_t) * 8) - 1)) - 1;

// Module initialization method.
// Called by Nginx.
// This module replaces the default core module HTTP reply handler.
// @param cf Nginx config
// @param cmd Commands
// @param conf Generic config.
static char *ngx_http_constant_reply(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    reinterpret_cast<ngx_http_core_loc_conf_t *>(
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module))->handler =
            ngx_http_constant_reply_handler;

    return NGX_CONF_OK;
}

// Main Handler
// This handler is called when Nginx generates reply content.
// @param r HTTP request.
// @return HTTP output chain RC.
static ngx_int_t ngx_http_constant_reply_handler(ngx_http_request_t *r)
{
    long long buf_size_val = 5;

    // The 'Expect' header is used to request the desired reply buffer.
    if (r->headers_in.expect) {
        const char * tempc = reinterpret_cast<char *>(r->headers_in.expect->value.data);
        char* end = 0;
        buf_size_val = strtoll(tempc, &end, 10);
        if (end <= tempc || buf_size_val < 0) {
            buf_size_val = 1;
        }

        if (buf_size_val > g_max_off_t) {
            buf_size_val = g_max_off_t;
        }
    }

    off_t buffer_size = static_cast<off_t>(buf_size_val);
    auto itr = g_constant_reply_buffers.find(buffer_size);
    if (itr == g_constant_reply_buffers.end()) {
        // Allocate global buffer accordng the content-type header.
        u_char *buffptr = (u_char *)malloc((size_t)buffer_size);
        if (!buffptr) {
            buffptr = (u_char *)malloc(1);
            buffer_size = 1;
        }

        itr = g_constant_reply_buffers.emplace(
            std::piecewise_construct,
            std::make_tuple(buffer_size),
            std::make_tuple(buffptr, buffptr + buffer_size)).first;

        memset(buffptr, '1', buffer_size);
    }

    // Allocate new Nginx buffer descriptor to send reply content.
    // The buffer is returned to the pool by Nginx.
    ngx_buf_t *buf_desc = reinterpret_cast<ngx_buf_t *>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));

    // Nginx buffer chain for output.
    ngx_chain_t out{buf_desc, nullptr};

    buf_desc->last_buf = 1; // Chain of one buffer
    buf_desc->memory = 1; // Buffer memory is constant and copy is not needed.
    buf_desc->pos = itr->second.out_buffer; // Buffer begin
    buf_desc->last = itr->second.out_buffer_end; // Buffer end (excluded)

    // HTTP reply status
    r->headers_out.status = NGX_HTTP_OK;

    // HTTP reply content-type
    r->headers_out.content_type.len = sizeof(REPLY_CONTENT_TYPE) - 1;
    r->headers_out.content_type.data = (u_char *)REPLY_CONTENT_TYPE;

    // HTTP reply content-length
    r->headers_out.content_length_n = itr->first;

    // Send reply headers
    ngx_http_send_header(r);

    // Send reply content
    return ngx_http_output_filter(r, &out);
}

