# Module description

This modules allows to return constant reply content without reading files or accessing system resources.
The module checks the 'Expect' header of the request. This header must contain a number of bytes to reply with.
This number does not include HTTP reply headers.
Example, Expect: 100000
The module allocates the required contiguous buffer once for a requested size and fills it with '1' chars.
The module keeps the allocated buffers forever allowing the application to request different sizes for performance testing.
The module is enabled per location basis in Nginx configuration.

# Setup

## Configure and compile Nginx with the module

auto/configure ... --add-module=/path/to/constant-reply-module-dir/
make -j

## Configure Nginx location to use the module

http {
    ...
    server {
        ...
        location /constant_reply {
            constant_reply;
        }
    }
}

## Send request to the module

curl -H'Expect: 4096' http://host:port/constant_reply
