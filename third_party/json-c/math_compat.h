#ifndef __math_compat_h
#define __math_compat_h

/**
 * @file
 * @brief Do not use, json-c internal, may be changed or removed at any time.
 */

/* Define isnan, isinf, infinity and nan on Windows/MSVC */

#ifndef HAVE_DECL_ISNAN
# ifdef HAVE_DECL__ISNAN
#include <float.h>
#define isnan(x) _isnan(x)
# endif
#endif

#ifndef HAVE_DECL_ISINF
# ifdef HAVE_DECL__FINITE
#include <float.h>
#define isinf(x) (!_finite(x))
# endif
#endif

/* Add these defines to config.h to indicate they are declared */
#define HAVE_DECL_INFINITY 1
#define HAVE_DECL_NAN 1

/* Only define INFINITY if it's not already defined */
#if !defined(INFINITY) && !defined(HAVE_DECL_INFINITY)
#include <float.h>
#define INFINITY (DBL_MAX + DBL_MAX)
#endif

/* Only define NAN if it's not already defined */
#if !defined(NAN) && !defined(HAVE_DECL_NAN)
#define NAN (INFINITY - INFINITY)
#endif

#endif
