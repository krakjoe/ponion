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

ZEND_DECLARE_MODULE_GLOBALS(ponion);

/* {{{ */
static onion *o = NULL; /* }}} */

static inline int ponion_request_init(onion_request *req, onion_response *res TSRMLS_DC) { /* {{{ */

	const char *path = onion_request_get_path(req);
	      char *path_translated = NULL;
	const char *buffer = NULL;
	onion_request_flags flags;
	
	path_translated = ponion_path_tostring(path TSRMLS_CC);
	if (!path_translated || !*path_translated) {
		return FAILURE;
	}
	
	flags = onion_request_get_flags(req);

	SG(request_info).request_method = ponion_method_tostring(flags TSRMLS_CC);

	if (SG(request_info).request_method) {
		SG(sapi_headers).http_response_code = 200;
		SG(request_info).request_uri = estrdup(path);
		SG(request_info).path_translated = estrdup(path_translated);
		free(path_translated);
		
		SG(request_info).auth_user = NULL;
		SG(request_info).auth_password = NULL;
		SG(request_info).auth_digest = NULL;	

		{
			ponion_string_t buffer = {0, NULL};
			onion_dict_preorder(
				onion_request_get_query_dict(req),
				ponion_dict_tostring,
				&buffer);
			if (buffer.len) {
				SG(request_info).query_string = estrndup(
					buffer.str, buffer.len);
				free(buffer.str);
			} else SG(request_info).query_string = NULL;
		}
		
		buffer = onion_request_get_header(req, "content-type");
		if (buffer) {
			SG(request_info).content_type = estrdup(buffer);
		} else {
			SG(request_info).content_type = NULL;
		}
	
		buffer = onion_request_get_header(req, "content-length");
		if (buffer) {
			SG(request_info).content_length = strtol(buffer, 0, 10);
		} else {
			SG(request_info).content_length = 0;
		}
		
	} else {
		SG(sapi_headers).http_response_code = 500;
		free(path_translated);
	}
	
	if (SG(sapi_headers).http_response_code != 200) {
		onion_response_set_code(res, SG(sapi_headers).http_response_code);
		onion_response_write0(res,"Error Occured");
		return FAILURE;
	}
	
	{
		SG(server_context) = (ponion_context_t*) emalloc(
			sizeof(ponion_context_t));
		
		((ponion_context_t*)SG(server_context))->req = req;
		((ponion_context_t*)SG(server_context))->res = res;
	}
	
	return SUCCESS;
} /* }}} */

static inline int ponion_request_handler(void *p, onion_request *req, onion_response *res){ /* {{{ */
	TSRMLS_FETCH();
	int status = 200;
	
	if (ponion_request_init(req, res TSRMLS_CC) == SUCCESS) {
		php_request_startup(TSRMLS_C);
		{
			int retval = SUCCESS;
			zend_file_handle file_handle;
		
			file_handle.filename = SG(request_info).path_translated;
			file_handle.free_filename = 0;
			file_handle.type = ZEND_HANDLE_FILENAME;
			file_handle.opened_path = NULL;

			/* open the script here so we can 404 if it fails */
			if (file_handle.filename)
				retval = php_fopen_primary_script(&file_handle TSRMLS_CC);

			if (!file_handle.filename || retval == FAILURE) {
				SG(sapi_headers).http_response_code = 404;
				onion_response_set_code(
					res, SG(sapi_headers).http_response_code);
				onion_response_write0(res, "Not Found");
			} else {
				php_execute_script(&file_handle TSRMLS_CC);
			}

			if (SG(request_info).cookie_data) {
				efree(SG(request_info).cookie_data);
			}
			if (SG(request_info).path_translated)
				efree(SG(request_info).path_translated);
		}

		php_request_shutdown(TSRMLS_C);
		
		switch (SG(sapi_headers).http_response_code) {
			case 500:
				return OCS_INTERNAL_ERROR;
			
			default:
				return OCS_PROCESSED;
		}
	}

	return OCS_NOT_PROCESSED;
} /* }}} */

static inline int ponion_error_handler(void *p, onion_request *req, onion_response *res) { /* {{{ */
	onion_response_write0(res,"Error world");
	return OCS_PROCESSED;
} /* }}} */

/* {{{ SAPI foo */
#include <ponion_sapi.h> /* }}} */

const opt_struct OPTIONS[] = { /* {{{ */
	{'h', 0, "show this help menu"},
	{'n', 0, "do not load any php.ini file"},
	{'c', 1, "load a specific php.ini file, -c/my/php.ini"},
	{'d', 1, "define ini entry on command line, -dmemory_limit=4G"},
	{'z', 1, "load zend_extension, -z/path/to/zendext.so"},
	{'p', 1, "sets the listening port to accept connections, -p12000"},
	{'a', 1, "set the interface address to bind too, -a127.0.0.1"},
	{'t', 1, "set the socket timeout in milliseconds, -t5000"},
	{'D', 1, "set the document root (chdir), -D."},
	{'T', 1, "set the maximum number of threads, -T16"},
	{'K', 1, "set the SSL key, -K/path/to/cert.key"},
	{'C', 1, "set the SSL certification, -C/path/to/cert.pem"},
	{'U', 1, "set the username to use, -Uweb"},
	{'G', 1, "set the group to use, -Gweb"},
	{'-', 0, NULL}
}; /* }}} */

const char ponion_ini_hardcoded[] =
"html_errors=On\n"
"register_argc_argv=Off\n"
"implicit_flush=Off\n"
"display_errors=Off\n"
"log_errors=On\n"
"max_execution_time=0\n"
"max_input_time=-1\n"
"error_log=\n\0";

/* overwriteable ini defaults must be set in ponion_ini_defaults() */
#define INI_DEFAULT(name, value) \
        Z_SET_REFCOUNT(tmp, 0); \
        Z_UNSET_ISREF(tmp); \
        ZVAL_STRINGL(&tmp, zend_strndup(value, sizeof(value)-1), sizeof(value)-1, 0); \
        zend_hash_update(configuration_hash, name, sizeof(name), &tmp, sizeof(zval), NULL);

static inline void ponion_ini_defaults(HashTable *configuration_hash) /* {{{ */
{
	zval tmp;
	INI_DEFAULT("report_zend_debug", "0");
} /* }}} */

static inline void ponion_shutdown_server(int _){ /* {{{ */
	zend_bailout();
} /* }}} */

static inline void ponion_help(TSRMLS_D) { /* {{{ */
	const opt_struct *opt = OPTIONS;
	
	printf(
		"%s (%s) (built: %s %s)\n", 
		PONION_NAME, PONION_VERSION,
		__DATE__, __TIME__);
	
	for (;;) {
		switch (opt->opt_char) {
			case '-':
				goto done;
				
			default:
				printf(
					"\t-%c\t\t%s\n", 
					opt->opt_char, 
					opt->opt_name);
				
		}
		opt++;
	}
done:
	return;
} /* }}} */

int main(int argc, char **argv) { /* {{{ */
	sapi_module_struct *ponion = &ponion_sapi_module;
	char *ini_entries;
	int   ini_entries_len;
	char **zend_extensions = NULL;
	zend_ulong zend_extensions_len = 0L;
	zend_bool ini_ignore;
	char *ini_override;
	char *php_optarg;
	int php_optind,
		opt,
		timeout,
		threads;
	char *port,
	     *address,
	     *docroot,
	     *cert,
	     *key,
	     *user,
	     *grp;
	void ***tsrm_ls;

#ifdef PHP_WIN32
	_fmode = _O_BINARY;                 /* sets default for file streams to binary */
	setmode(_fileno(stdin), O_BINARY);  /* make the stdio mode be binary */
	setmode(_fileno(stdout), O_BINARY); /* make the stdio mode be binary */
	setmode(_fileno(stderr), O_BINARY); /* make the stdio mode be binary */
#endif

	tsrm_startup(1, 1, 0, NULL);

	tsrm_ls = ts_resource(0);

ponion_enter:
	ini_entries = NULL;
	ini_entries_len = 0;
	ini_ignore = 0;
	ini_override = NULL;
	zend_extensions = NULL;
	zend_extensions_len = 0L;
	php_optarg = NULL;
	php_optind = 1;
	opt = 0;
	port = NULL;
	timeout = 5000;
	address = NULL;
	threads = 16;
	docroot = NULL;
	cert = NULL;
	key = NULL;
	user = NULL;
	grp = NULL;
	
	while ((opt = php_getopt(argc, argv, OPTIONS, &php_optarg, &php_optind, 0, 2)) != -1) {
		switch (opt) {
			case 'h':
				ponion_help(TSRMLS_C);
				goto quit;	

			case 'n':
				ini_ignore = 1;
				break;
			case 'c':
				if (ini_override) {
					free(ini_override);
				}
				ini_override = strdup(php_optarg);
				break;
			case 'd': {
				int len = strlen(php_optarg);
				char *val;

				if ((val = strchr(php_optarg, '='))) {
				  val++;
				  if (!isalnum(*val) && *val != '"' && *val != '\'' && *val != '\0') {
					  ini_entries = realloc(ini_entries, ini_entries_len + len + sizeof("\"\"\n\0"));
					  memcpy(ini_entries + ini_entries_len, php_optarg, (val - php_optarg));
					  ini_entries_len += (val - php_optarg);
					  memcpy(ini_entries + ini_entries_len, "\"", 1);
					  ini_entries_len++;
					  memcpy(ini_entries + ini_entries_len, val, len - (val - php_optarg));
					  ini_entries_len += len - (val - php_optarg);
					  memcpy(ini_entries + ini_entries_len, "\"\n\0", sizeof("\"\n\0"));
					  ini_entries_len += sizeof("\n\0\"") - 2;
				  } else {
					  ini_entries = realloc(ini_entries, ini_entries_len + len + sizeof("\n\0"));
					  memcpy(ini_entries + ini_entries_len, php_optarg, len);
					  memcpy(ini_entries + ini_entries_len + len, "\n\0", sizeof("\n\0"));
					  ini_entries_len += len + sizeof("\n\0") - 2;
				  }
				} else {
				  ini_entries = realloc(ini_entries, ini_entries_len + len + sizeof("=1\n\0"));
				  memcpy(ini_entries + ini_entries_len, php_optarg, len);
				  memcpy(ini_entries + ini_entries_len + len, "=1\n\0", sizeof("=1\n\0"));
				  ini_entries_len += len + sizeof("=1\n\0") - 2;
				}
			} break;
			
			case 'z':
				zend_extensions_len++;
				if (zend_extensions) {
					zend_extensions = realloc(zend_extensions, sizeof(char*) * zend_extensions_len);
				} else zend_extensions = malloc(sizeof(char*) * zend_extensions_len);
				zend_extensions[zend_extensions_len-1] = strdup(php_optarg);
			break;
			
			case 'p':
				if (port) {
					free(port);
				}
				port = strdup(php_optarg);
			break;
			
			case 't':
				timeout = atoi(php_optarg);
			break;
			
			case 'a':
				if (address) {
					free(address);
				}
				address = strdup(php_optarg);
			break;
			
			case 'D':
				if (docroot) {
					free(docroot);
				}
				docroot = strdup(php_optarg);
			break;
			
			case 'T':
				threads = atoi(php_optarg);
			break;
			
			case 'K':
				if (key) {
					free(key);
				}
				key = strdup(php_optarg);
			break;
			
			case 'C':
				if (cert) {
					free(cert);
				}
				cert = strdup(php_optarg);
			break;
			
			case 'U':
				if (user) {
					free(user);
				}
				user = strdup(php_optarg);
			break;
			
			case 'G':
				if (grp) {
					free(grp);
				}
				grp = strdup(php_optarg);
			break;
		}
	}
	
	if (!port)
		port = strdup("12000");
	if (timeout < -1)
		timeout = 5000;
	if (!address)
		address = strdup("127.0.0.1");
	if (docroot) {
		if (chdir(docroot) != SUCCESS) {
			ONION_ERROR("could not change into %s", docroot);
			free(docroot);
			goto quit;
		}
		free(docroot);
	}
	
	if (cert || key) {
		if (!cert) {
			ONION_ERROR("the SSL certificate is not set for %s", key);	
			free(key);
			goto quit;
		} else if (!key) {
			ONION_ERROR("the SSL key is not set for %s", cert);	
			free(cert);
			goto quit;
		}
	}
	
	ponion->ini_defaults = ponion_ini_defaults;
	ponion->phpinfo_as_text = 0;
	ponion->php_ini_ignore_cwd = 1;

	sapi_startup(ponion);

	ponion->executable_location = argv[0];
	ponion->phpinfo_as_text = 0;
	ponion->php_ini_ignore = ini_ignore;
	ponion->php_ini_path_override = ini_override;

	if (ini_entries) {
		ini_entries = realloc(ini_entries, ini_entries_len + sizeof(ponion_ini_hardcoded));
		memmove(ini_entries + sizeof(ponion_ini_hardcoded) - 2, ini_entries, ini_entries_len + 1);
		memcpy(ini_entries, ponion_ini_hardcoded, sizeof(ponion_ini_hardcoded) - 2);
	} else {
		ini_entries = malloc(sizeof(ponion_ini_hardcoded));
		memcpy(ini_entries, ponion_ini_hardcoded, sizeof(ponion_ini_hardcoded));
	}
	ini_entries_len += sizeof(ponion_ini_hardcoded) - 2;
	
	if (zend_extensions_len) {
		zend_ulong zend_extension = 0L;
		
		while (zend_extension < zend_extensions_len) {
			const char *ze = zend_extensions[zend_extension];
			size_t ze_len = strlen(ze);
			
			ini_entries = realloc(
				ini_entries, ini_entries_len + (ze_len + (sizeof("zend_extension=\n"))));
			memcpy(&ini_entries[ini_entries_len], "zend_extension=", (sizeof("zend_extension=\n")-1));
			ini_entries_len += (sizeof("zend_extension=")-1);
			memcpy(&ini_entries[ini_entries_len], ze, ze_len);
			ini_entries_len += ze_len;
			memcpy(&ini_entries[ini_entries_len], "\n", (sizeof("\n") - 1));

			free(zend_extensions[zend_extension]);
			zend_extension++;
		}
		
		free(zend_extensions);
	}

	ponion->ini_entries = ini_entries;
	
	if (ponion->startup(ponion) == SUCCESS) {
#ifdef SIGPIPE
		signal(SIGPIPE, SIG_IGN);
#endif
		
#ifdef ZEND_SIGNALS
		zend_try {
			zend_signal_activate(TSRMLS_C);

#ifdef SIGINT
			zend_signal(SIGINT, ponion_shutdown_server TSRMLS_CC);
#endif
#ifdef SIGTERM
			zend_signal(SIGTERM, ponion_shutdown_server TSRMLS_CC);
#endif
		} zend_end_try();
#else
#ifdef SIGINT
		signal(SIGINT, ponion_shutdown_server);
#endif
#ifdef SIGTERM
		signal(SIGTERM, ponion_shutdown_server);
#endif
#endif

		ONION_INFO("Starting ponion on %s:%s, %d Threads", address, port, threads);
		o=onion_new(O_POLL|O_POOL|O_THREADED);
		
		onion_set_max_threads(o, threads);
		
		onion_set_timeout(o, timeout);
		
		onion_set_port(o, port);
		free(port);
		
		onion_set_hostname(o, address);
		free(address);
		
		if (user ) {
			struct group *g = NULL;
			struct passwd *pwd = getpwnam(user);
			
			if (pwd) {
				g = (!grp) ?
						getgrgid(pwd->pw_gid) : 
						getgrnam(grp);
				if (g &&
					g->gr_gid != getgid()) {
					ONION_INFO("Setting group for process \"%s\"", g->gr_name);
					setgid(g->gr_gid);
				}
				
				if (getuid() != pwd->pw_uid) {
					ONION_INFO("Setting username for process \"%s\"", user);
					setuid(pwd->pw_uid);
				}
			} else {
				ONION_WARNING("Couldn't find username \"%s\"", user);
			}
			
			free(user);
			if (grp)
				free(grp);
		}
		
		if (cert && key) {
			ONION_INFO("Setting SSL certificate/key \"%s/%s\"", cert, key);
			onion_set_certificate(
				o, O_SSL_CERTIFICATE_KEY, cert, key, O_SSL_NONE);
			free(cert);
			free(key);	
		}
		
		{
			onion_handler *handlers[3] = {
				onion_handler_new(ponion_error_handler, o, NULL),
				onion_handler_new(ponion_request_handler, o, NULL),
				onion_handler_export_local_new(".")
			};
			
			onion_set_internal_error_handler(o, handlers[0]);
			onion_handler_add(
				handlers[1], handlers[2]);
			onion_set_root_handler(o, handlers[1]);
		}
		
		zend_first_try {
			ONION_INFO("Listening for connections ...");
			onion_listen(o);
		} zend_catch {
			ONION_WARNING("Shutting down server ...");
			
			if (o) {
				onion_listen_stop(o);
			}
			
			if (ponion_sapi_module.ini_entries) {
				free(ponion_sapi_module.ini_entries);
			}

			if (ponion_sapi_module.php_ini_path_override) {
				free(ponion_sapi_module.php_ini_path_override);
			}

#ifdef ZEND_SIGNALS
			zend_try {
				zend_signal_deactivate(TSRMLS_C);
			} zend_end_try();
#endif

			sapi_shutdown();
			
		} zend_end_try();
	}

quit:
	tsrm_shutdown();

	return 0;
} /* }}} */

