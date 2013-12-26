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
#include <onion/onion.h>
#include <onion/handlers/exportlocal.h>
#include <onion/request.h>
#include <onion/types.h>
#include <onion/types_internal.h>
#include <onion/log.h>
#include <signal.h>
#include <netdb.h>

ZEND_DECLARE_MODULE_GLOBALS(ponion);

static onion *o=NULL;

typedef struct _onion_context_t {
	onion_request *req;
	onion_response *res;
} onion_context_t;

static inline int ponion_ub_write(const char *message, unsigned int length TSRMLS_DC) /* {{{ */
{
	onion_context_t *context = (onion_context_t*) SG(server_context);
	if (context) {
		if (onion_response_write(context->res, message, length))
			return SUCCESS;	
	}
	
	return FAILURE;
} /* }}} */

#if PHP_VERSION_ID >= 50700
static inline void ponion_flush(void *context TSRMLS_DC)  /* {{{ */
{
#else
static inline void ponion_flush(void *context)  /* {{{ */
{
#endif

	onion_context_t *ctx = (onion_context_t*) context;
	if (ctx) {
		onion_response_flush(ctx->res);	
	}
} /* }}} */

char *ponion_translate_path(const char *path TSRMLS_DC) { /* {{{ */
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
			translated = "index.php";
		}
	}
	
	/* don't allow insecure, silly paths */
	if (translated && 
		(strstr(translated, "..") != NULL)) {
		translated = NULL;
	}
	
	return translated;
} /* }}} */

static inline char *ponion_init_method(onion_request_flags flags TSRMLS_DC) { /* {{{ */

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

int ponion_init_request(onion_request *req, onion_response *res TSRMLS_DC) { /* {{{ */

	const char *path = onion_request_get_path(req), 
	           *path_translated = NULL;
	const char *buffer = NULL;
	onion_request_flags flags;
	
	path_translated = ponion_translate_path(path TSRMLS_CC);
	if (!path_translated) {
		return FAILURE;
	}
	
	flags = onion_request_get_flags(req);
	
	SG(request_info).request_method = ponion_init_method(flags TSRMLS_CC);
	SG(request_info).query_string = NULL;
	SG(request_info).auth_user = NULL;
	SG(request_info).auth_password = NULL;
	SG(request_info).auth_digest = NULL;	

	if (SG(request_info).request_method && 
		path_translated && *path_translated) {
		SG(sapi_headers).http_response_code = 200;
		SG(request_info).request_uri = estrdup(path);
		SG(request_info).path_translated = estrdup(path_translated);

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
		SG(request_info).path_translated = NULL;
		SG(sapi_headers).http_response_code = 500;
	}

	if (SG(sapi_headers).http_response_code != 200) {
		onion_response_set_code(res, SG(sapi_headers).http_response_code);
		onion_response_write0(
			res,"Error Occured");
		return FAILURE;
	}
	
	{
		SG(server_context) = (onion_context_t*) emalloc(
			sizeof(onion_context_t));
		
		((onion_context_t*)SG(server_context))->req = req;
		((onion_context_t*)SG(server_context))->res = res;
	}
	
	return SUCCESS;
} /* }}} */

int onion_request_handler(void *p, onion_request *req, onion_response *res){ /* {{{ */
	TSRMLS_FETCH();
	int status = 200;
	
	if (ponion_init_request(req, res TSRMLS_CC) == SUCCESS) {
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

int onion_error_handler(void *p, onion_request *req, onion_response *res) { /* {{{ */
	onion_response_write0(res,"Error world");
	return OCS_PROCESSED;
} /* }}} */

/* {{{ */
static zend_module_entry ponion_sapi_zend_module = {
	STANDARD_MODULE_HEADER,
	PONION_NAME,
	NULL,
	NULL, // minit
	NULL,
	NULL, // rinit
	NULL,
	NULL,
	PONION_VERSION,
	STANDARD_MODULE_PROPERTIES
}; /* }}} */

static int php_sapi_ponion_deactivate(TSRMLS_D) /* {{{ */
{
	fflush(stdout);
	if(SG(request_info).argv0) {
		free(SG(request_info).argv0);
		SG(request_info).argv0 = NULL;
	}
	return SUCCESS;
}
/* }}} */

static inline int php_ponion_module_startup(sapi_module_struct *module) /* {{{ */
{
	if (php_module_startup(module, &ponion_sapi_zend_module, 1) == FAILURE) {
		return FAILURE;
	}
	
	return SUCCESS;
} /* }}} */

static char* php_sapi_ponion_read_cookies(TSRMLS_D) /* {{{ */
{
	return NULL;
} /* }}} */

static int php_sapi_ponion_header_handler(sapi_header_struct *h, sapi_header_op_enum op, sapi_headers_struct *s TSRMLS_DC) /* {{{ */
{
	return 0;
}
/* }}} */

static int php_sapi_ponion_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC) /* {{{ */
{
	onion_context_t *context = (onion_context_t*) SG(server_context);
	
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

static void php_sapi_ponion_send_header(sapi_header_struct *sapi_header, void *server_context TSRMLS_DC) /* {{{ */
{
	
}
/* }}} */

static void php_sapi_ponion_register_vars(zval *track_vars_array TSRMLS_DC) /* {{{ */
{
	unsigned int len;
	char   docroot[MAXPATHLEN], 
		   *path = NULL, *query = NULL;
	
	onion_context_t *context = SG(server_context);
	
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

static void php_sapi_ponion_log_message(char *message TSRMLS_DC) /* {{{ */
{
	fprintf(stderr, "%s\n", message);
} /* }}} */

/* {{{ sapi_module_struct ponion_sapi_module
*/
static sapi_module_struct ponion_sapi_module = {
	"ponion",                       /* name */
	"ponion",                       /* pretty name */

	php_ponion_module_startup, /* startup */
	php_module_shutdown_wrapper,    /* shutdown */

	NULL,                           /* activate */
	php_sapi_ponion_deactivate,     /* deactivate */

	ponion_ub_write,       			/* unbuffered write */
	ponion_flush,          			/* flush */
	NULL,                           /* get uid */
	NULL,                           /* getenv */

	php_error,                      /* error handler */

	php_sapi_ponion_header_handler, /* header handler */
	php_sapi_ponion_send_headers,   /* send headers handler */
	NULL,    /* send header handler */

	NULL,                           /* read POST data */
	php_sapi_ponion_read_cookies,   /* read Cookies */

	php_sapi_ponion_register_vars,  /* register server variables */
	php_sapi_ponion_log_message,    /* Log message */
	NULL,                           /* Get request time */
	NULL,                           /* Child terminate */
	STANDARD_SAPI_MODULE_PROPERTIES
};
/* }}} */

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

void ponion_ini_defaults(HashTable *configuration_hash) /* {{{ */
{
	zval tmp;
	INI_DEFAULT("report_zend_debug", "0");
} /* }}} */

#ifdef ZEND_SIGNALS
static void shutdown_server(int _){
#else
static void shutdown_server(int _){
#endif
	TSRMLS_FETCH();
	
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
	
	if (o) 
		onion_listen_stop(o);

	tsrm_shutdown();
}

static inline void ponion_help(TSRMLS_D) {
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
}

int main(int argc, char **argv){
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
	     *key;
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
			zend_signal(SIGINT, shutdown_server TSRMLS_CC);
#endif
#ifdef SIGTERM
			zend_signal(SIGTERM, shutdown_server TSRMLS_CC);
#endif
		} zend_end_try();
#else
#ifdef SIGINT
		signal(SIGINT, shutdown_server);
#endif
#ifdef SIGTERM
		signal(SIGTERM, shutdown_server);
#endif
#endif

		o=onion_new(O_POLL|O_POOL|O_THREADED);
		
		if (cert && key) {
			onion_set_certificate(
				o, O_SSL_CERTIFICATE_KEY, cert, key, O_SSL_NONE);
			free(cert);
			free(key);	
		}
		
		onion_set_max_threads(o, threads);
		
		onion_set_timeout(o, timeout);
		
		onion_set_port(o, port);
		free(port);
		
		onion_set_hostname(o, address);
		free(address);
		
		{
			onion_handler *ponion_error_handler = onion_handler_new(onion_error_handler, o, NULL);
			
			if (ponion_error_handler) {
				onion_set_internal_error_handler(o, ponion_error_handler);
			}
		}
		
		{
			onion_handler *ponion_handler = onion_handler_new(onion_request_handler, o, NULL);
			
			if (ponion_handler) {
				onion_handler_add(
					ponion_handler, onion_handler_export_local_new("."));
				
				onion_set_root_handler(o, ponion_handler);
			}
		}
		
		onion_listen(o);
	}

quit:
	tsrm_shutdown();

	return 0;
}
