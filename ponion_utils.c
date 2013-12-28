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

#include <zend.h>
#include <TSRM.h>

#include "ponion_utils.h"

char *ponion_path_tostring(const char *path TSRMLS_DC) { /* {{{ */
	char *translated = NULL;
	
	if (path && *path) {
		size_t path_len = strlen(path);
		
		if (path_len > 0L) {
			const char *end = &path[path_len - 1];
			
			{
				char *php = strstr(path, ".php");
				if (php) {
					/* ensure this is a php script */
					if (php + (strlen(php)-1) == end) {
						translated = strdup((char*)path);
					}
				}
			}
		}
	} else {
		/* auto index */
		struct stat sb;
		
		if (stat("index.php", &sb) == SUCCESS) {
			translated = strdup("index.php");
		}
	}
	
	/* don't allow insecure, silly paths */
	if (translated && 
		(strstr(translated, "..") != NULL)) {
		translated = NULL;
	}
	
	return translated;
} /* }}} */

char *ponion_method_tostring(onion_request_flags flags TSRMLS_DC) { /* {{{ */

	switch (flags & OR_METHODS) {
		case OR_GET:
			return "GET";
		case OR_POST:
			return "POST";
		case OR_HEAD:
			return "HEAD";
		case OR_OPTIONS:
			return "OPTIONS";
		case OR_PROPFIND:
			return "PROPFIND";
		case OR_PUT:
			return "PUT";
		case OR_DELETE:
			return "DELETE";
		case OR_MOVE:
			return "MOVE";
		case OR_MKCOL:
			return "MKCOL";
		case OR_PROPPATCH:
			return "PROPPATCH";
		case OR_PATCH:
			return "PATCH";	
		
		default:
			return NULL;
	}
} /* }}} */

void ponion_dict_tostring(void *context, const char *key, const char *value, int flags) { /* {{{ */
	ponion_string_t *string = (ponion_string_t*) context;
	size_t lengths[3] = {
		strlen(key), 
		strlen(value),
		lengths[0]+lengths[1]};
	
	if (!string->len) {
		string->str = malloc(lengths[2]+2);
		sprintf(
			string->str, "%s=%s\0", key, value);
	} else {
		string->str = realloc(
			string->str, string->len + lengths[2]+4);
		sprintf(
			&string->str[string->len], "&%s=%s\0", key, value);
	}
	
	string->len = strlen(string->str);
} /* }}} */

