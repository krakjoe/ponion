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
#include <ponion.h>
#include <ponion_utils.h>
#include <ponion_sapi.h>

static zend_class_entry *OnionQuery_ce = NULL,
                        *OnionPost_ce = NULL,
                        *OnionHeaders_ce = NULL,
                        *OnionFiles_ce = NULL;
static zend_object_handlers onion_handlers,
                            *zend_handlers = NULL;

int php_sapi_ponion_ub_write(const char *message, unsigned int length TSRMLS_DC) /* {{{ */
{
	ponion_context_t *context = (ponion_context_t*) SG(server_context);
	if (context) {
		if (onion_response_write(context->res, message, length))
			return SUCCESS;	
	}
	
	return FAILURE;
} /* }}} */

#if PHP_VERSION_ID >= 50700
void php_sapi_ponion_flush(void *context TSRMLS_DC)  /* {{{ */
{
#else
void php_sapi_ponion_flush(void *context)  /* {{{ */
{
#endif

	ponion_context_t *ctx = (ponion_context_t*) context;
	if (ctx) {
		onion_response_flush(ctx->res);	
	}
} /* }}} */

int php_sapi_ponion_deactivate(TSRMLS_D) /* {{{ */
{
	fflush(stdout);
	if(SG(request_info).argv0) {
		free(SG(request_info).argv0);
		SG(request_info).argv0 = NULL;
	}
	return SUCCESS;
}
/* }}} */

int php_ponion_module_startup(sapi_module_struct *module) /* {{{ */
{
	if (php_module_startup(module, &ponion_sapi_zend_module, 1) == FAILURE) {
		return FAILURE;
	}
	
	return SUCCESS;
} /* }}} */

char* php_sapi_ponion_read_cookies(TSRMLS_D) /* {{{ */
{
	return NULL;
} /* }}} */

int php_sapi_ponion_read_post(char *buffer, uint length TSRMLS_DC) /* {{{ */
{
	return 0;
} /* }}} */

int php_sapi_ponion_header_handler(sapi_header_struct *h, sapi_header_op_enum op, sapi_headers_struct *s TSRMLS_DC) /* {{{ */
{
	return 0;
}
/* }}} */

int php_sapi_ponion_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC) /* {{{ */
{
	ponion_context_t *context = (ponion_context_t*) SG(server_context);
	
	onion_response_set_code(
		context->res, sapi_headers->http_response_code);
	
	{
		zend_llist_element *position;
		sapi_header_struct *header = zend_llist_get_first_ex(&sapi_headers->headers, &position),
						   *end = zend_llist_get_last(&sapi_headers->headers);
		
		if (header) {
			do {
				const char *sep = strstr(header->header, ":");
				
				if (sep) {
					sep++;
					while (isspace(*sep)) {
						sep++;
					}
				}
				
				onion_response_set_header(
					context->res, 
					header->header, sep ? sep + 1 : NULL);
				
				if (header == end) {
					break;
				}
			} while((header = zend_llist_get_next_ex(&sapi_headers->headers, &position)));
		}
	}
	return SAPI_HEADER_SENT_SUCCESSFULLY;
}
/* }}} */

void php_sapi_ponion_send_header(sapi_header_struct *sapi_header, void *server_context TSRMLS_DC) /* {{{ */
{
	
}
/* }}} */

void php_sapi_ponion_register_vars(zval *track_vars_array TSRMLS_DC) /* {{{ */
{
	unsigned int len;
	char   docroot[MAXPATHLEN], 
		   *path = NULL, *query = NULL;
	
	ponion_context_t *context = SG(server_context);
	
	php_import_environment_variables(track_vars_array TSRMLS_CC);
	
	path = (char*) onion_request_get_fullpath(context->req);
	len = strlen(path);
	
	if (sapi_module.input_filter(PARSE_SERVER, "PHP_SELF", &path, len, &len TSRMLS_CC)) {
		php_register_variable("PHP_SELF", path, track_vars_array TSRMLS_CC);
	}
	
	if (sapi_module.input_filter(PARSE_SERVER, "SCRIPT_NAME", &path, len, &len TSRMLS_CC)) {
		php_register_variable("SCRIPT_NAME", path, track_vars_array TSRMLS_CC);
	}
	
	if (sapi_module.input_filter(PARSE_SERVER, "SCRIPT_FILENAME", &path, len, &len TSRMLS_CC)) {
		php_register_variable("SCRIPT_FILENAME", path, track_vars_array TSRMLS_CC);
	}
	
	if (sapi_module.input_filter(PARSE_SERVER, "PATH_TRANSLATED", &path, len, &len TSRMLS_CC)) {
		php_register_variable("PATH_TRANSLATED", path, track_vars_array TSRMLS_CC);
	}

	VCWD_GETCWD(docroot, MAXPATHLEN);
	if ((len = strlen(docroot))) {
		char *document_root = estrndup(docroot, len);
		
		if (sapi_module.input_filter(PARSE_SERVER, "DOCUMENT_ROOT",
					(char**) &document_root, len, &len TSRMLS_CC)) {
			php_register_variable("DOCUMENT_ROOT", document_root, track_vars_array TSRMLS_CC);
		}
	}

	/* really ? */
	php_register_variable("GATEWAY_INTERFACE", "CGI/1.1", track_vars_array TSRMLS_CC);
}
/* }}} */

void php_sapi_ponion_log_message(char *message TSRMLS_DC) /* {{{ */
{
	fprintf(stderr, "%s\n", message);
} /* }}} */

/* {{{ sapi_module_struct ponion_sapi_module
*/
sapi_module_struct ponion_sapi_module = {
	"ponion",                       /* name */
	"ponion",                       /* pretty name */

	php_ponion_module_startup,      /* startup */
	php_module_shutdown_wrapper,    /* shutdown */

	NULL,                           /* activate */
	php_sapi_ponion_deactivate,     /* deactivate */

	php_sapi_ponion_ub_write,       /* unbuffered write */
	php_sapi_ponion_flush,          /* flush */
	NULL,                           /* get uid */
	NULL,                           /* getenv */

	php_error,                      /* error handler */

	php_sapi_ponion_header_handler, /* header handler */
	php_sapi_ponion_send_headers,   /* send headers handler */
	NULL,    						/* send header handler */

	php_sapi_ponion_read_post,      /* read POST data */
	php_sapi_ponion_read_cookies,   /* read Cookies */

	php_sapi_ponion_register_vars,  /* register server variables */
	php_sapi_ponion_log_message,    /* Log message */
	NULL,                           /* Get request time */
	NULL,                           /* Child terminate */
	STANDARD_SAPI_MODULE_PROPERTIES
}; /* }}} */

/* {{{ */
#include <classes/query.h>
#include <classes/post.h> 
#include <classes/headers.h> /* }}} */

static PHP_MINIT_FUNCTION(ponion) { /* {{{ */
	zend_class_entry qe, pe, he;
	
	INIT_CLASS_ENTRY(qe, "OnionQuery", onion_query_methods);
	OnionQuery_ce = zend_register_internal_class(&qe TSRMLS_CC);
	zend_class_implements(OnionQuery_ce TSRMLS_CC, 1, spl_ce_ArrayAccess);
	
	INIT_CLASS_ENTRY(pe, "OnionPost", onion_post_methods);
	OnionPost_ce = zend_register_internal_class(&pe TSRMLS_CC);
	zend_class_implements(OnionPost_ce TSRMLS_CC, 1, spl_ce_ArrayAccess);
	
	INIT_CLASS_ENTRY(he, "OnionHeaders", onion_headers_methods);
	OnionHeaders_ce = zend_register_internal_class(&he TSRMLS_CC);
	zend_class_implements(OnionHeaders_ce TSRMLS_CC, 1, spl_ce_ArrayAccess);
	
	return SUCCESS;
} /* }}} */

/* {{{ */
zend_module_entry ponion_sapi_zend_module = {
	STANDARD_MODULE_HEADER,
	PONION_NAME,
	NULL,
	PHP_MINIT(ponion), // minit
	NULL,
	NULL, // rinit
	NULL,
	NULL,
	PONION_VERSION,
	STANDARD_MODULE_PROPERTIES
}; /* }}} */
