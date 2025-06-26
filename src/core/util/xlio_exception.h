/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include <exception>
#include <string.h>
#include <string>

/**
 * @class xlio_error
 *
 * base class for xlio exceptions classes.
 * Note: xlio code should NOT catch xlio_error; xlio code should only catch
 * exceptions of derived classes
 */
class xlio_error : public std::exception {
    char formatted_message[512];

public:
    const std::string message;
    const std::string function;
    const std::string filename;
    const int lineno;
    const int errnum;

    /**
     * Create an object that contains const members for all the given arguments,
     * plus a formatted message that will be available thru the 'what()' method of
     * base class.
     *
     * The formatted_message will look like this:
     * 		"xlio_error <create internal epoll> (errno=24 Too many open files)
     * in sock/sockinfo.cpp:61" catcher can print it to log like this:
     * fdcoll_loginfo("recovering from %s", e.what());
     */
    xlio_error(const char *_message, const char *_function, const char *_filename, int _lineno,
               int _errnum) throw()
        : message(_message)
        , function(_function)
        , filename(_filename)
        , lineno(_lineno)
        , errnum(_errnum)
    {
        snprintf(formatted_message, sizeof(formatted_message),
                 "xlio_error <%s> (errno=%d %s) in %s:%d\n", message.c_str(), errnum,
                 strerror(errnum), filename.c_str(), lineno);
        formatted_message[sizeof(formatted_message) - 1] = '\0';
    }

    virtual ~xlio_error() throw() {};

    virtual const char *what() const throw() { return formatted_message; }
};

/**
 * @class xlio_exception
 * NOTE: ALL exceptions that can be caught by XLIO should be derived of this
 * class
 */
class xlio_exception : public xlio_error {
public:
    xlio_exception(const char *_message, const char *_function, const char *_filename, int _lineno,
                   int _errnum) throw()
        : xlio_error(_message, _function, _filename, _lineno, _errnum)
    {
    }

    xlio_exception(const std::string &_message, const char *_function, const char *_filename,
                   int _lineno, int _errnum) throw()
        : xlio_exception(_message.c_str(), _function, _filename, _lineno, _errnum)
    {
    }
};

#define create_xlio_exception_class(clsname, basecls)                                              \
    class clsname : public basecls {                                                               \
    public:                                                                                        \
        clsname(const char *_message, const char *_function, const char *_filename, int _lineno,   \
                int _errnum) throw()                                                               \
            : basecls(_message, _function, _filename, _lineno, _errnum)                            \
        {                                                                                          \
        }                                                                                          \
    }

create_xlio_exception_class(xlio_unsupported_api, xlio_error);

#define throw_xlio_exception(msg)                                                                  \
    throw xlio_exception(msg, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
// uses for throwing  something that is derived from xlio_error and has similar
// CTOR; msg will automatically be class name
#define xlio_throw_object(_class)                                                                  \
    throw _class(#_class, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
#define xlio_throw_object_with_msg(_class, _msg)                                                   \
    throw _class(_msg, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
