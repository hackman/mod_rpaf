#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"

#define RPATH_DEBUG
#define RPATH_VERSION "mod_rpath/0.1"
#define HEADER_NAME "X-Forwarded-For"
#define REMOTE_ADDR "REMOTE_ADDR"

#ifdef APACHE_RELEASE
#include "http_conf_globals.h"
#else
#define APACHE2
//#include "http_request.h"
//#include "http_connection.h"
//#include "apr_strings.h"
#endif

#ifdef APACHE2
module AP_MODULE_DECLARE_DATA rpath_module;
#else
module rpath_module;
#endif

#ifdef APACHE2
static int rpath_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
	ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, s, RPATH_VERSION " loaded.");
	return OK;
#else
static void rpath_init(server_rec *s, pool *p) {
	ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, s, RPATH_VERSION " loaded.");
#endif
}


static int rpath_handler(request_rec *r) {
	const char *ip = NULL;
	int time = 0;
#ifdef APACHE2
	ip = apr_table_get(r->headers_in, HEADER_NAME);
#else
	ip = ap_table_get(r->headers_in, HEADER_NAME);
#endif

#ifdef RPATH_DEBUG
	if (ip == NULL) 
		ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, r, "[mod_rpath] " HEADER_NAME " not found");
#endif // RPATH_DEBUG

	if (ip != NULL) {
#ifdef RPATH_DEBUG 
#ifdef APACHE2
		ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, r, "[mod_rpath] " HEADER_NAME " found(%s)", ip);
#else
		ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, r, "[mod_rpath] " HEADER_NAME " found(%s)", ip);
#endif // APACHE2
#endif // RPATH_DEBUG

	
// rewrite the headers
		ap_table_unset(r->headers_in, HEADER_NAME);
		ap_table_setn(r->headers_in, REMOTE_ADDR, ip);
	}
	return OK;
};

#ifdef APACHE2
static void register_hooks(apr_pool_t *p) {
	static const char * const aszPre[]  = { "mod_mime.c", "mod_env.c", "mod_setenvif.c", NULL };
	static const char * const aszPost[] = { "mod_hive.c", "mod_cgi.c", "mod_php.c", "mod_suphp.c", "mod_python.c", "mod_perl.c", NULL };
	ap_hook_post_config(rpath_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_header_parser(rpath_handler, aszPre, aszPost, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA rpath_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* per-directory config creator */
	NULL,				/* dir config merger */
	NULL,				/* server config creator */
	NULL,				/* server config merger */
	NULL,				/* command table */
	register_hooks,		/* set up other request processing hooks */
};
#else
module MODULE_VAR_EXPORT rpath_module = {
	STANDARD_MODULE_STUFF,
	rpath_init,		/* module initializer                  */
	NULL,			/* create per-dir    config structures */
	NULL,			/* merge  per-dir    config structures */
	NULL,			/* create per-server config structures */
	NULL,			/* merge  per-server config structures */
	NULL,			/* table of config file commands       */
	NULL,			/* [#8] MIME-typed-dispatched handlers */
	NULL,			/* [#1] URI to filename translation    */
	NULL,			/* [#4] validate user id from request  */
	NULL,			/* [#5] check if the user is ok _here_ */
	NULL,			/* [#3] check access by host address   */
	NULL,			/* [#6] determine MIME type            */
	rpath_handler,	/* [#7] pre-run fixups                 */
	NULL,			/* [#9] log a transaction              */
	NULL,			/* [#2] header parser                  */
	NULL,			/* child_init                          */
	NULL,			/* child_exit                          */
	NULL			/* [#0] post read-request              */
};
#endif
