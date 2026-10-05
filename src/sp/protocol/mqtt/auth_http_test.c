#include "nng/protocol/mqtt/mqtt_parser.h"
#include <nuts.h>

static void conf_auth_http_init(conf_auth_http **conf)
{
	*conf = nng_zalloc(sizeof(conf_auth_http));
	if (*conf == NULL) {
		return;
	}

	// Explicitly initialize key fields to avoid using uninitialized
	// cache_ttl/acl_cache_mtx in nmq_auth_http_sub_pub during tests.
	(*conf)->enable          = true;
	(*conf)->timeout         = 0;
	(*conf)->connect_timeout = 0;
	(*conf)->pool_size       = 0;
	(*conf)->cache_ttl       = 0;     // Ensure ACL cache branch is skipped
	(*conf)->acl_cache_map   = NULL;
	(*conf)->acl_cache_mtx   = NULL;  // No mutex allocated when cache_ttl is 0

	(*conf)->auth_req.enable       = false;
	(*conf)->auth_req.url          = NULL;
	(*conf)->auth_req.method       = NULL;
	(*conf)->auth_req.header_count = 0;
	(*conf)->auth_req.headers      = NULL;
	(*conf)->auth_req.param_count  = 0;
	(*conf)->auth_req.params       = NULL;

	(*conf)->super_req.enable       = false;
	(*conf)->super_req.url          = NULL;
	(*conf)->super_req.method       = NULL;
	(*conf)->super_req.header_count = 0;
	(*conf)->super_req.headers      = NULL;
	(*conf)->super_req.param_count  = 0;
	(*conf)->super_req.params       = NULL;

	(*conf)->acl_req.enable       = false;
	(*conf)->acl_req.url          = NULL;
	(*conf)->acl_req.method       = NULL;
	(*conf)->acl_req.header_count = 0;
	(*conf)->acl_req.headers      = NULL;
	(*conf)->acl_req.param_count  = 0;
	(*conf)->acl_req.params       = NULL;

	return;
}

static void conn_param_init(conn_param **conn_param)
{
	conn_param_alloc(conn_param);
	if (conn_param == NULL) {
		return;
	}

	conn_param_set_clientid(*conn_param, "clientid");
	conn_param_set_username(*conn_param, "username");
	conn_param_set_password(*conn_param, "password");

	return;
}

void test_auth_http_connect(void)
{
	conf_auth_http *conf = NULL;
	conf_auth_http_init(&conf);
	NUTS_TRUE(conf != NULL);
	char *url = "http://127.0.0.1:8064/mqtt/auth";
	conf->auth_req.url = nng_alloc(strlen(url) + 1);
	nng_mtx_alloc(&conf->auth_req.mtx);
	strncpy(conf->auth_req.url, url, strlen(url));
	conf->auth_req.url[strlen(url)] = '\0';

	conn_param *conn_param = NULL;
	conn_param_init(&conn_param);
	NUTS_TRUE(conn_param != NULL);

	int rc = nmq_auth_http_connect(conn_param, conf);
	/* No HTTP response: the backend could not decide, which is not a denial. */
	NUTS_TRUE(rc == NMQ_SERVER_UNAVAILABLE);

	nng_mtx_free(conf->auth_req.mtx);
	nng_free(conf->auth_req.url, strlen(conf->auth_req.url) + 1);
	nng_free(conf, sizeof(conf_auth_http));
	conn_param_free(conn_param);

	return;
}

void test_auth_http_sub_pub(void)
{
	conf_auth_http *conf = NULL;
	conf_auth_http_init(&conf);
	NUTS_TRUE(conf != NULL);
	char *url = "http://10.1.0.1:8964/mqtt/acl";
	conf->super_req.enable = false;
	conf->acl_req.enable = true;
	conf->enable = true;
	conf->acl_req.url = nng_alloc(strlen(url) + 1);
	strncpy(conf->acl_req.url, url, strlen(url));
	conf->acl_req.url[strlen(url)] = '\0';
	conf->super_req.url = NULL;
	conf->connect_timeout = 1;
	conf->timeout = 1;

	conn_param *conn_param = NULL;
	conn_param_init(&conn_param);
	NUTS_TRUE(conn_param != NULL);
	nng_mtx_alloc(&conf->acl_req.mtx);
	NUTS_TRUE(conf->acl_req.mtx != NULL);
	nng_mtx_alloc(&conf->super_req.mtx);
	NUTS_TRUE(conf->super_req.mtx != NULL);
	nng_mtx_alloc(&conf->acl_cache_mtx);
	NUTS_TRUE(conf->acl_cache_mtx != NULL);

	nng_id_map_alloc(&conf->acl_cache_map, 0, 0xffff, false);

	topic_queue *tq = topic_queue_init("topic1", strlen("topic1"));

	/* handle pub */
	int rc = nmq_auth_http_sub_pub(conn_param, false, tq, conf);
	/* send_request will be failed */
	printf("rc %d\n", rc);
	NUTS_TRUE(rc == NOT_AUTHORIZED);

	topic_queue *tq2 = topic_queue_init("topic2", strlen("topic2"));
	tq->next = tq2;
	rc = nmq_auth_http_sub_pub(conn_param, true, tq, conf);
	/* send_request will be failed */
	printf("rc %d\n", rc);
	NUTS_TRUE(rc == NOT_AUTHORIZED);

	topic_queue_release(tq);
	nng_mtx_free(conf->acl_req.mtx);
	nng_mtx_free(conf->super_req.mtx);
	nng_mtx_free(conf->acl_cache_mtx);
	nng_id_map_free(conf->acl_cache_map);
	nng_free(conf->acl_req.url, strlen(conf->acl_req.url) + 1);
	nng_free(conf, sizeof(conf_auth_http));
	conn_param_free(conn_param);

	return;
}

#ifdef NNG_SUPP_TLS

static void
reply_ok(nng_aio *aio)
{
	nng_http_res *res;
	int           rv;

	if ((rv = nng_http_res_alloc(&res)) != 0) {
		nng_aio_finish(aio, rv);
		return;
	}
	nng_http_res_set_status(res, NNG_HTTP_STATUS_OK);
	nng_aio_set_output(aio, 0, res);
	nng_aio_finish(aio, 0);
}

/* An HTTPS backend on localhost that grants every request it answers. The
 * nuts server certificate is self-signed for CN=localhost, so it doubles as
 * the trust anchor a caller configures. */
static void
https_backend_start(nng_http_server **srvp, uint16_t port)
{
	nng_http_handler *handler;
	nng_tls_config   *cfg;
	nng_url          *url;
	char              addr[64];

	snprintf(addr, sizeof(addr), "https://localhost:%u", port);
	NUTS_PASS(nng_url_parse(&url, addr));
	NUTS_PASS(nng_http_server_hold(srvp, url));
	NUTS_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    cfg, nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_http_server_set_tls(*srvp, cfg));
	nng_tls_config_free(cfg);
	NUTS_PASS(nng_http_handler_alloc(&handler, "/mqtt/auth", reply_ok));
	NUTS_PASS(nng_http_server_add_handler(*srvp, handler));
	NUTS_PASS(nng_http_server_start(*srvp));
	nng_url_free(url);
}

static void
auth_http_connect_over_tls(const char *ca, int expect)
{
	conf_auth_http  *conf = NULL;
	conn_param      *cp   = NULL;
	nng_http_server *srv  = NULL;
	uint16_t         port = nuts_next_port();
	char             url[64];

	conf_auth_http_init(&conf);
	NUTS_TRUE(conf != NULL);
	conf->connect_timeout = 5;
	conf->timeout         = 5;
	snprintf(url, sizeof(url), "https://localhost:%u/mqtt/auth", port);
	conf->auth_req.url    = nng_strdup(url);
	conf->auth_req.tls.ca = nng_strdup(ca);
	nng_mtx_alloc(&conf->auth_req.mtx);

	conn_param_init(&cp);
	NUTS_TRUE(cp != NULL);

	https_backend_start(&srv, port);
	NUTS_TRUE(nmq_auth_http_connect(cp, conf) == expect);

	nng_http_server_stop(srv);
	nng_http_server_release(srv);
	nng_mtx_free(conf->auth_req.mtx);
	nng_strfree(conf->auth_req.url);
	nng_strfree(conf->auth_req.tls.ca);
	nng_free(conf, sizeof(conf_auth_http));
	conn_param_free(cp);
}

/* Production reaches the backend over https, so the plain-socket client has to
 * speak it; cacertfile is the trust anchor the config parser loaded. */
void test_auth_http_connect_tls(void)
{
	auth_http_connect_over_tls(nuts_server_crt, SUCCESS);
}

/* The request carries the broker's credentials, so a certificate that does not
 * chain to the configured anchor has to stop it -- and that is the backend
 * failing to answer, not the client failing to authenticate. */
void test_auth_http_connect_tls_untrusted(void)
{
	auth_http_connect_over_tls(nuts_client_crt, NMQ_SERVER_UNAVAILABLE);
}

#endif // NNG_SUPP_TLS

NUTS_TESTS = {
	{ "auth_http_connect", test_auth_http_connect },
	{ "auth_http_sub_pub", test_auth_http_sub_pub },
#ifdef NNG_SUPP_TLS
	{ "auth_http_connect_tls", test_auth_http_connect_tls },
	{ "auth_http_connect_tls_untrusted",
	    test_auth_http_connect_tls_untrusted },
#endif
	{ NULL, NULL },
};
