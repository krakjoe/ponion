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
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <sys/stat.h>

#include <onion/onion.h>
#include <onion/handlers/exportlocal.h>
#include <onion/request.h>
#include <onion/types.h>
#include <onion/types_internal.h>
#include <onion/log.h>

#ifndef PONION_UTILS_H
#define PONION_UTILS_H
/* {{{ */
typedef struct _ponion_string_t {
	size_t len;
	char *str;
} ponion_string_t; /* }}} */

/* {{{ */
typedef struct _ponion_context_t {
	onion_request *req;
	onion_response *res;
} ponion_context_t; /* }}} */

char *ponion_path_tostring(const char *path TSRMLS_DC);
char *ponion_method_tostring(onion_request_flags flags TSRMLS_DC);
void  ponion_dict_tostring(void *context, const char *key, const char *value, int flags);
#endif
