# Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

conf = configuration_data()
conf.set10('ENABLE_RDRAND', true)

conf.set10('ENABLE_THREADING', true)

check_headers = [
  'dlfcn.h',
  'endian.h',
  'fcntl.h',
  'float.h',
  'inttypes.h',
  'limits.h',
  'locale.h',
  'memory.h',
  'stdarg.h',
  'stdint.h',
  'stdlib.h',
  'strings.h',
  'string.h',
  'syslog.h',
  'sys/cdefs.h',
  'sys/param.h',
  'sys/stat.h',
  'sys/types.h',
  'sys/resource.h',
  'unistd.h',
  'xlocale.h',
]

foreach header : check_headers
  if c_compiler.has_header(header)
    conf.set10('HAVE_' + header.underscorify().to_upper(), true)
  endif
endforeach

stdc = ['stdlib.h', 'stdarg.h', 'string.h', 'float.h']
have_stdc = true
foreach header : stdc
  if not conf.has('HAVE_' + header.underscorify().to_upper())
    have_stdc = false
  endif
endforeach
conf.set10('STDC_HEADERS', have_stdc)

float_symbols = ['_isnan', '_finite']
math_symbols = ['INFINITY', 'isinf', 'isnan', 'nan']

foreach symbol : float_symbols
  if c_compiler.has_header_symbol('float.h', symbol)
    conf.set10('HAVE_DECL_' + symbol.to_upper(), true)
  endif
endforeach

foreach symbol : math_symbols
  if c_compiler.has_header_symbol('math.h', symbol)
    conf.set10('HAVE_DECL_' + symbol.to_upper(), true)
  endif
endforeach

check_function = [
  'snprintf',
  'vasprintf',
  'vsnprintf',
  'vprintf',
  'open',
  'realloc',
  'setlocale',
  'uselocale',
  'strcasecmp',
  'strncasecmp',
  'strdup',
  'strerror',
  'vsyslog',
]

foreach function : check_function
  if c_compiler.has_function(function)
    conf.set10('HAVE_' + function.to_upper(), true)
  endif
endforeach
conf.set10('HAVE_DOPRNT', c_compiler.has_function('_doprnt'))

if c_compiler.get_id() == 'msvc'
  if c_compiler.has_function('strtoll')
    conf.set10('HAVE_STRTOLL', true)
    conf.set('json_c_strtoll', 'strtoll')
  elif c_compiler.has_function('_strtoi64')
    conf.set10('HAVE_STRTOLL', true)
    conf.set('json_c_strtoll', '_strtoi64')
  endif
endif

check_types = ['int', 'int64_t', 'long', 'long long', 'size_t', 'ssize_t']
foreach type : check_types
  size = c_compiler.sizeof(type, prefix: '#include <stdint.h>')
  # W/A, since in windows the size of ssize_t can't be detected
  if is_compiler_msvc and type == 'ssize_t' and size == -1
    size = c_compiler.sizeof('size_t', prefix: '#include <stdint.h>')
  endif
  conf.set('SIZEOF_' + type.underscorify().to_upper(), size)
endforeach

if not is_compiler_msvc
  if c_compiler.compiles('int main() { int i, x = 0; i = __sync_add_and_fetch(&x,1); return x; }')
    conf.set10('HAVE_ATOMIC_BUILTINS', true)
  endif
endif

if c_compiler.compiles('__thread int x = 0; int main() { return 0; }')
  conf.set10('HAVE___THREAD', true)
endif

if conf.has('HAVE___THREAD')
  conf.set('SPEC___THREAD', '__thread')
elif c_compiler.get_id() == 'msvc'
  conf.set('SPEC___THREAD', '__declspec(thread)')
endif

conf.set_quoted('VERSION', meson.project_version())

config_h = configure_file(
  configuration: conf,
  output: 'config.h',
)

