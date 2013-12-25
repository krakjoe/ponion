/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2013 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Joe Watkins <joe.watkins@live.co.uk>                        |
   +----------------------------------------------------------------------+
*/
#ifndef PONION_H
#define PONION_H

#ifdef PHP_WIN32
# define PONION_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PONION_API __attribute__ ((visibility("default")))
#else
# define PONION_API
#endif

#include "php.h"
#include "php_globals.h"
#include "php_variables.h"
#include "php_getopt.h"
#include "zend_builtin_functions.h"
#include "zend_extensions.h"
#include "zend_modules.h"
#include "zend_globals.h"
#include "zend_ini_scanner.h"
#include "zend_stream.h"
#include "SAPI.h"

#if defined(_WIN32) && !defined(__MINGW32__)
# include <windows.h>
# include "config.w32.h"
# undef  strcasecmp
# undef  strncasecmp
# define strcasecmp _stricmp 
# define strncasecmp _strnicmp 
#else
# include "php_config.h"
#endif

#ifndef O_BINARY
#	define O_BINARY 0
#endif
#include "php_main.h"

#ifdef ZTS
# include "TSRM.h"
#endif

#ifdef ZTS
# define PONION_G(v) TSRMG(ponion_globals_id, zend_ponion_globals *, v)
#else
# define PONION_G(v) (ponion_globals.v)
#endif

/* {{{ strings */
#define PONION_NAME "ponion"
#define PONION_AUTHORS "Joe Watkins"
#define PONION_URL "http://github.com/krakjoe/ponion"
#define PONION_ISSUES "http://github.com/krakjoe/ponion/issues"
#define PONION_VERSION "0.0.1"
/* }}} */

ZEND_BEGIN_MODULE_GLOBALS(ponion)
	zend_bool g;
ZEND_END_MODULE_GLOBALS(ponion)

#endif
