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
#ifndef PONION_SAPI_H
#define PONION_SAPI_H
int php_ponion_module_startup(sapi_module_struct *module);
int php_sapi_ponion_deactivate(TSRMLS_D);
char* php_sapi_ponion_read_cookies(TSRMLS_D);
int php_sapi_ponion_read_post(char *buffer, uint length TSRMLS_DC);
int php_sapi_ponion_header_handler(sapi_header_struct *h, sapi_header_op_enum op, sapi_headers_struct *s TSRMLS_DC);
int php_sapi_ponion_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC);
void php_sapi_ponion_send_header(sapi_header_struct *sapi_header, void *server_context TSRMLS_DC);
void php_sapi_ponion_register_vars(zval *track_vars_array TSRMLS_DC);
void php_sapi_ponion_log_message(char *message TSRMLS_DC);
int php_sapi_ponion_ub_write(const char *message, unsigned int length TSRMLS_DC);
#if PHP_VERSION_ID >= 50700
void php_sapi_ponion_flush(void *context TSRMLS_DC);
#else
void php_sapi_ponion_flush(void *context);
#endif

extern sapi_module_struct ponion_sapi_module;
extern zend_module_entry  ponion_sapi_zend_module;
#endif
