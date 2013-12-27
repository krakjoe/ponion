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
ZEND_BEGIN_ARG_INFO_EX(OnionPost_offsetGet, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(OnionPost_offsetSet, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(OnionPost_offsetExists, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(OnionPost_offsetUnset, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

static PHP_METHOD(OnionPost, offsetGet) {
	char *key;
	zend_uint key_len;
	onion_context_t *context = (onion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	{
		const char *value = onion_request_get_post(context->req, key);
		
		if (value)
			RETURN_STRING(value, 1);
	}
}

static PHP_METHOD(OnionPost, offsetSet) {
	char *key;
	zend_uint key_len;
	onion_context_t *context = (onion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	zend_error(E_WARNING, "OnionPost objects are read only");
}

static PHP_METHOD(OnionPost, offsetExists) {
	char *key;
	zend_uint key_len;
	onion_context_t *context = (onion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	{
		const char *value = onion_request_get_post(context->req, key);
		
		if (value) {
			RETURN_BOOL(1);
		} else RETURN_BOOL(0);
	}
}

static PHP_METHOD(OnionPost, offsetUnset) {
	char *key;
	zend_uint key_len;
	onion_context_t *context = (onion_context_t*) SG(server_context);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}
	
	zend_error(E_WARNING, "OnionPost objects are read only");
}

zend_function_entry onion_post_methods[] = {
	PHP_ME(OnionPost, offsetGet, OnionPost_offsetGet, ZEND_ACC_PUBLIC)
	PHP_ME(OnionPost, offsetSet, OnionPost_offsetSet, ZEND_ACC_PUBLIC)
	PHP_ME(OnionPost, offsetExists, OnionPost_offsetExists, ZEND_ACC_PUBLIC)
	PHP_ME(OnionPost, offsetUnset, OnionPost_offsetUnset, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
