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
ZEND_BEGIN_ARG_INFO_EX(OnionHeaders_offsetGet, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(OnionHeaders_offsetSet, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(OnionHeaders_offsetExists, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(OnionHeaders_offsetUnset, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

static PHP_METHOD(OnionHeaders, offsetGet) {
	char *key;
	zend_uint key_len;
	ponion_context_t *context = (ponion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	{
		const char *value = onion_request_get_header(context->req, key);
		
		if (value)
			RETURN_STRING(value, 1);
	}
}

static PHP_METHOD(OnionHeaders, offsetSet) {
	char *key;
	zend_uint key_len;
	ponion_context_t *context = (ponion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	zend_error(E_WARNING, "OnionHeaders objects are read only");
}

static PHP_METHOD(OnionHeaders, offsetExists) {
	char *key;
	zend_uint key_len;
	ponion_context_t *context = (ponion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	{
		const char *value = onion_request_get_header(context->req, key);
		
		if (value) {
			RETURN_BOOL(1);
		} else RETURN_BOOL(0);
	}
}

static PHP_METHOD(OnionHeaders, offsetUnset) {
	char *key;
	zend_uint key_len;
	ponion_context_t *context = (ponion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	zend_error(E_WARNING, "OnionHeaders objects are read only");
}

zend_function_entry onion_headers_methods[] = {
	PHP_ME(OnionHeaders, offsetGet, OnionHeaders_offsetGet, ZEND_ACC_PUBLIC)
	PHP_ME(OnionHeaders, offsetSet, OnionHeaders_offsetSet, ZEND_ACC_PUBLIC)
	PHP_ME(OnionHeaders, offsetExists, OnionHeaders_offsetExists, ZEND_ACC_PUBLIC)
	PHP_ME(OnionHeaders, offsetUnset, OnionHeaders_offsetUnset, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
