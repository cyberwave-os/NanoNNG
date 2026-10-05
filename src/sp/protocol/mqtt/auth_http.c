#include "nng/nng.h"
#include "core/nng_impl.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "supplemental/http/http_api.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if defined(NNG_PLATFORM_POSIX)
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#if defined(NNG_TLS_ENGINE_MBEDTLS)
#include "mbedtls/version.h" // Must be first in order to pick up version
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
// For MBEDTLS_ERR_NET_*; mbedTLS renamed this header for 2.4.0.
#if MBEDTLS_VERSION_MAJOR > 2 || MBEDTLS_VERSION_MINOR >= 4
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
#endif
#endif

struct auth_http_params {
	const char *access; // (1 - subscribe, 2 - publish)
	const char *username;
	const char *clientid;
	const char *ipaddress;
	const char *protocol;
	const char *password;
	const char *sockport;
	const char *common;
	const char *subject;
	const char *mountpoint;
	const char *topic;
};

typedef struct auth_http_params auth_http_params;

static char *
url_encode(const char *str)
{
	if (str == NULL) {
		return NULL;
	}
	const char *hex = "0123456789ABCDEF";
	size_t len = strlen(str);
	// turn every char to "%XX" + '\0'
	char *encoded = calloc(len * 3 + 1, sizeof(char));
	if (encoded == NULL) {
		return NULL;
	}
	char *p = encoded;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)str[i];
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			*p++ = c;
		} else {
			*p++ = '%';
			*p++ = hex[c >> 4];
			*p++ = hex[c & 15];
		}
	}
	*p = '\0';
	return encoded;
}

static void
set_data(
    nng_http_req *req, conf_auth_http_req *req_conf, auth_http_params *params)
{
	char *req_data     = NULL;
	char *content_type = "application/x-www-form-urlencoded";

	if (req_conf->header_count == 0) {
		log_error("No headers found in request configuration");
		return;
	}

	for (size_t i = 0; i < req_conf->header_count; i++) {
		if (nni_strcasecmp(req_conf->headers[i]->key, "Content-Type") ==
		    0) {
			content_type = req_conf->headers[i]->value;
			continue;
		}
		nng_http_req_add_header(req, req_conf->headers[i]->key,
		    req_conf->headers[i]->value);
	}

	if (nni_strcasecmp(content_type, "application/json") == 0 &&
	    nni_strcasecmp(req_conf->method, "get") == 0) {
		content_type = "application/x-www-form-urlencoded";
	}

	if (nni_strcasecmp(content_type, "application/json") == 0) {
		cJSON *obj = cJSON_CreateObject();
		for (size_t i = 0; i < req_conf->param_count; i++) {
			switch (req_conf->params[i]->type) {
			case ACCESS:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name, params->access);
				break;
			case USERNAME:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->username);
				break;
			case CLIENTID:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->clientid);
				break;
			case IPADDRESS:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->ipaddress);
				break;
			case PROTOCOL:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->protocol);
				break;
			case PASSWORD:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->password);
				break;
			case SOCKPORT:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->sockport);
				break;
			case COMMON_NAME:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name, params->common);
				break;
			case SUBJECT:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name,
				    params->subject);
				break;
			case TOPIC:
				cJSON_AddStringToObject(obj,
				    req_conf->params[i]->name, params->topic);
				break;
			default:
				break;
			}
		}
		req_data = cJSON_PrintUnformatted(obj);
		cJSON_Delete(obj);
	} else {
		for (size_t i = 0; i < req_conf->param_count; i++) {
			const char *val = NULL;

			switch (req_conf->params[i]->type) {
			case ACCESS:
				val = params->access;
				break;
			case USERNAME:
				val = params->username;
				break;
			case CLIENTID:
				val = params->clientid;
				break;
			case IPADDRESS:
				val = params->ipaddress;
				break;
			case PROTOCOL:
				val = params->protocol;
				break;
			case PASSWORD:
				val = params->password;
				break;
			case SOCKPORT:
				val = params->sockport;
				break;
			case COMMON_NAME:
				val = params->common;
				break;
			case SUBJECT:
				val = params->subject;
				break;
			case TOPIC:
				val = params->topic;
				break;
			default:
				break;
			}

			if (val) {
				char *encoded_val = url_encode(val);
				if (encoded_val) {
					str_append(&req_data, req_conf->params[i]->name);
					str_append(&req_data, "=");
					str_append(&req_data, encoded_val);
					str_append(&req_data, "&");
					free(encoded_val);
				}
			}
		}

		if (req_data != NULL &&
		    req_data[strlen(req_data) - 1] == '&') {
			req_data[strlen(req_data) - 1] = '\0';
		}
	}

	nng_http_req_add_header(req, "Content-Type", content_type);
	nng_http_req_set_method(req, req_conf->method);

	if (nni_strcasecmp(req_conf->method, "post") == 0 ||
	    nni_strcasecmp(req_conf->method, "put") == 0) {
		if (req_data && req_data[0] != '\0') {
			nng_http_req_copy_data(
			    req, req_data, strlen(req_data));
		}
	} else if (req_data && req_data[0] != '\0') {
		const char *base_uri = nng_http_req_get_uri(req);
		size_t      uri_len  = strlen(base_uri) + strlen(req_data) + 2;
		char *      uri      = nng_alloc(uri_len);
		snprintf(uri, uri_len, "%s?%s", base_uri, req_data);
		nng_http_req_set_uri(req, uri);
		nng_free(uri, uri_len);
	}

	if (req_data) {
		free(req_data);
	}
}

#if defined(NNG_PLATFORM_POSIX)
// Auth and ACL checks run on nng task-queue threads (server_cb and the
// protocol's pipe callbacks). Waiting there for an nng aio deadlocks under
// load: the aio's own completion also needs a task-queue thread, so once every
// thread is blocked in an auth call no reply can be processed and each call
// runs into its timeout while the backend is healthy. Plain blocking sockets
// need no other thread, so concurrent checks neither starve nor serialise.

static uint64_t
http_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t) ts.tv_sec * 1000) + ((uint64_t) ts.tv_nsec / 1000000);
}

static int
http_wait_fd(int fd, short events, uint64_t deadline)
{
	for (;;) {
		uint64_t now = http_now_ms();
		if (now >= deadline) {
			return (NNG_ETIMEDOUT);
		}
		struct pollfd pfd = { .fd = fd, .events = events };
		int           n   = poll(&pfd, 1, (int) (deadline - now));
		if (n > 0) {
			return (0);
		}
		if (n == 0) {
			return (NNG_ETIMEDOUT);
		}
		if (errno != EINTR) {
			return (NNG_ECLOSED);
		}
	}
}

static int
http_connect(const char *host, const char *port, uint64_t deadline, int *fdp)
{
	struct addrinfo  hints = { 0 };
	struct addrinfo *res   = NULL;
	int              rv;

	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(host, port, &hints, &res)) != 0) {
		log_error("Resolve %s failed: %s", host, gai_strerror(rv));
		return (NNG_EADDRINVAL);
	}
	rv = NNG_ECONNREFUSED;
	for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
		int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
		(void) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#ifdef SO_NOSIGPIPE
		int one = 1;
		(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			rv = 0;
		} else if (errno == EINPROGRESS) {
			if ((rv = http_wait_fd(fd, POLLOUT, deadline)) == 0) {
				int       err = 0;
				socklen_t len = sizeof(err);
				if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 ||
				    err != 0) {
					rv = NNG_ECONNREFUSED;
				}
			}
		} else {
			rv = NNG_ECONNREFUSED;
		}
		if (rv == 0) {
			*fdp = fd;
			break;
		}
		close(fd);
		if (rv == NNG_ETIMEDOUT) {
			break;
		}
	}
	freeaddrinfo(res);
	return (rv);
}

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// A connection to the backend: the socket, plus the TLS session when the
// callback URL is https. TLS runs over the same non-blocking socket and the
// same poll() deadlines, so it keeps the no-extra-thread property above.
typedef struct {
	int fd;
#if defined(NNG_TLS_ENGINE_MBEDTLS)
	bool                     tls;
	mbedtls_ssl_context      ssl;
	mbedtls_ssl_config       cfg;
	mbedtls_x509_crt         ca;
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context drbg;
#endif
} http_io;

#if defined(NNG_TLS_ENGINE_MBEDTLS)

// mbedTLS BIO callbacks. The socket is non-blocking, so "would block" becomes
// WANT_READ/WANT_WRITE and the caller waits on the request deadline. These
// mirror mbedtls_net_send/mbedtls_net_recv, including returning 0 at EOF.
static int
http_tls_send(void *ctx, const unsigned char *buf, size_t len)
{
	ssize_t n = send(*(int *) ctx, buf, len, MSG_NOSIGNAL);
	if (n >= 0) {
		return ((int) n);
	}
	if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
		return (MBEDTLS_ERR_SSL_WANT_WRITE);
	}
	return (MBEDTLS_ERR_NET_SEND_FAILED);
}

static int
http_tls_recv(void *ctx, unsigned char *buf, size_t len)
{
	ssize_t n = recv(*(int *) ctx, buf, len, 0);
	if (n >= 0) {
		return ((int) n);
	}
	if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
		return (MBEDTLS_ERR_SSL_WANT_READ);
	}
	return (MBEDTLS_ERR_NET_RECV_FAILED);
}

// Waits for whichever direction mbedTLS asked for. Returns NNG_EPROTO for any
// result that is not a wait, so the caller can report the original error.
static int
http_tls_wait(http_io *io, int want, uint64_t deadline)
{
	if (want == MBEDTLS_ERR_SSL_WANT_READ) {
		return (http_wait_fd(io->fd, POLLIN, deadline));
	}
	if (want == MBEDTLS_ERR_SSL_WANT_WRITE) {
		return (http_wait_fd(io->fd, POLLOUT, deadline));
	}
	return (NNG_EPROTO);
}

// An explicit `ssl { cacertfile = ... }` on the request pins the trust anchor;
// the config parser has already read that file into tls.ca. Otherwise the
// platform CA bundle is used, so a backend behind a public certificate needs
// no broker configuration at all.
static int
http_tls_trust(mbedtls_x509_crt *ca, conf_auth_http_req *conf_req)
{
	const char *file;
	const char *dir;
	int         rv;

	if (conf_req->tls.ca != NULL) {
		rv = mbedtls_x509_crt_parse(ca,
		    (const unsigned char *) conf_req->tls.ca,
		    strlen(conf_req->tls.ca) + 1);
		if (rv != 0) {
			log_error("Parse cacertfile %s failed: -0x%04x",
			    conf_req->tls.cafile ? conf_req->tls.cafile : "",
			    -rv);
			return (NNG_EINVAL);
		}
		return (0);
	}
	if ((file = getenv("SSL_CERT_FILE")) == NULL) {
		file = "/etc/ssl/certs/ca-certificates.crt";
	}
	if (mbedtls_x509_crt_parse_file(ca, file) == 0) {
		return (0);
	}
	if ((dir = getenv("SSL_CERT_DIR")) == NULL) {
		dir = "/etc/ssl/certs";
	}
	if ((rv = mbedtls_x509_crt_parse_path(ca, dir)) < 0) {
		log_error("No CA certificates in %s or %s: set the auth "
		          "request's ssl.cacertfile",
		    file, dir);
		return (NNG_ENOENT);
	}
	return (0);
}

static void
http_tls_log_error(http_io *io, const char *host, int rv)
{
	char info[256];

	if (rv == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
		uint32_t flags = mbedtls_ssl_get_verify_result(&io->ssl);
		if (mbedtls_x509_crt_verify_info(
		        info, sizeof(info), "", flags) > 0) {
			char *eol = strchr(info, '\n');
			if (eol != NULL) {
				*eol = '\0';
			}
			log_error("TLS certificate of %s rejected: %s", host,
			    info);
			return;
		}
	}
	mbedtls_strerror(rv, info, sizeof(info));
	log_error("TLS handshake with %s failed: %s", host, info);
}

// Seeds, configures and completes the handshake. The server certificate is
// always verified against the trust anchors and the hostname: these callbacks
// carry client credentials, so an unverified peer is not an option.
static int
http_tls_start(http_io *io, const char *host, conf_auth_http_req *conf_req,
    uint64_t deadline)
{
	static const char personal[] = "nanomq-auth-http";
	int               rv;

	mbedtls_ssl_init(&io->ssl);
	mbedtls_ssl_config_init(&io->cfg);
	mbedtls_x509_crt_init(&io->ca);
	mbedtls_entropy_init(&io->entropy);
	mbedtls_ctr_drbg_init(&io->drbg);
	io->tls = true; // every context above is now owned by http_io_fini

	if ((rv = mbedtls_ctr_drbg_seed(&io->drbg, mbedtls_entropy_func,
	         &io->entropy, (const unsigned char *) personal,
	         sizeof(personal) - 1)) != 0) {
		log_error("Seed TLS random generator failed: -0x%04x", -rv);
		return (NNG_ECRYPTO);
	}
	if ((rv = http_tls_trust(&io->ca, conf_req)) != 0) {
		return (rv);
	}
	if ((rv = mbedtls_ssl_config_defaults(&io->cfg, MBEDTLS_SSL_IS_CLIENT,
	         MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) !=
	    0) {
		log_error("Configure TLS client failed: -0x%04x", -rv);
		return (NNG_ECRYPTO);
	}
	mbedtls_ssl_conf_authmode(&io->cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&io->cfg, &io->ca, NULL);
	mbedtls_ssl_conf_rng(&io->cfg, mbedtls_ctr_drbg_random, &io->drbg);
	if ((rv = mbedtls_ssl_setup(&io->ssl, &io->cfg)) != 0) {
		log_error("Set up TLS session failed: -0x%04x", -rv);
		return (NNG_ECRYPTO);
	}
	// Also sends SNI, which a shared front end needs to pick a certificate.
	if ((rv = mbedtls_ssl_set_hostname(&io->ssl, host)) != 0) {
		log_error("Set TLS hostname failed: -0x%04x", -rv);
		return (NNG_ECRYPTO);
	}
	mbedtls_ssl_set_bio(
	    &io->ssl, &io->fd, http_tls_send, http_tls_recv, NULL);

	for (;;) {
		int wrv;
		if ((rv = mbedtls_ssl_handshake(&io->ssl)) == 0) {
			return (0);
		}
		if ((wrv = http_tls_wait(io, rv, deadline)) == NNG_EPROTO) {
			http_tls_log_error(io, host, rv);
			return (rv == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
			        ? NNG_EPEERAUTH
			        : NNG_ECLOSED);
		}
		if (wrv != 0) {
			log_error("TLS handshake with %s: %s", host,
			    nng_strerror(wrv));
			return (wrv);
		}
	}
}
#endif // NNG_TLS_ENGINE_MBEDTLS

static void
http_io_fini(http_io *io)
{
#if defined(NNG_TLS_ENGINE_MBEDTLS)
	if (io->tls) {
		(void) mbedtls_ssl_close_notify(&io->ssl); // best effort
		mbedtls_ssl_free(&io->ssl);
		mbedtls_ssl_config_free(&io->cfg);
		mbedtls_x509_crt_free(&io->ca);
		mbedtls_ctr_drbg_free(&io->drbg);
		mbedtls_entropy_free(&io->entropy);
		io->tls = false;
	}
#endif
	if (io->fd >= 0) {
		close(io->fd);
		io->fd = -1;
	}
}

static int
http_io_write(http_io *io, const char *buf, size_t len, uint64_t deadline)
{
	while (len > 0) {
		ssize_t n;
#if defined(NNG_TLS_ENGINE_MBEDTLS)
		if (io->tls) {
			int rv, wrv;
			rv = mbedtls_ssl_write(
			    &io->ssl, (const unsigned char *) buf, len);
			if (rv > 0) {
				buf += rv;
				len -= (size_t) rv;
				continue;
			}
			if ((wrv = http_tls_wait(io, rv, deadline)) != 0) {
				return (wrv == NNG_EPROTO ? NNG_ECLOSED : wrv);
			}
			continue;
		}
#endif
		n = send(io->fd, buf, len, MSG_NOSIGNAL);
		if (n > 0) {
			buf += n;
			len -= (size_t) n;
		} else if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			int rv;
			if ((rv = http_wait_fd(io->fd, POLLOUT, deadline)) != 0) {
				return (rv);
			}
		} else {
			return (NNG_ECLOSED);
		}
	}
	return (0);
}

// Reads at least one byte. NNG_ECLOSED reports the peer closing the stream.
static int
http_io_read(
    http_io *io, char *buf, size_t len, uint64_t deadline, size_t *gotp)
{
	for (;;) {
		ssize_t n;
#if defined(NNG_TLS_ENGINE_MBEDTLS)
		if (io->tls) {
			int rv, wrv;
			rv = mbedtls_ssl_read(
			    &io->ssl, (unsigned char *) buf, len);
			if (rv > 0) {
				*gotp = (size_t) rv;
				return (0);
			}
			if ((wrv = http_tls_wait(io, rv, deadline)) != 0) {
				return (wrv == NNG_EPROTO ? NNG_ECLOSED : wrv);
			}
			continue;
		}
#endif
		n = recv(io->fd, buf, len, 0);
		if (n > 0) {
			*gotp = (size_t) n;
			return (0);
		}
		if (n == 0) {
			return (NNG_ECLOSED);
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			int rv;
			if ((rv = http_wait_fd(io->fd, POLLIN, deadline)) != 0) {
				return (rv);
			}
			continue;
		}
		return (NNG_ECLOSED);
	}
}

// Reads the status line ("HTTP/1.1 200 OK") into line and returns its code.
static int
http_read_status(
    http_io *io, uint64_t deadline, char *line, size_t size, int *statusp)
{
	size_t got = 0;
	char  *eol = NULL;

	while ((eol = memchr(line, '\n', got)) == NULL) {
		size_t n;
		int    rv;
		if (got == size - 1) {
			return (NNG_EPROTO);
		}
		if ((rv = http_io_read(
		         io, line + got, size - 1 - got, deadline, &n)) != 0) {
			return (rv);
		}
		got += n;
	}
	*eol = '\0';
	if (eol > line && eol[-1] == '\r') {
		eol[-1] = '\0';
	}
	// "HTTP/1.x NNN ..."
	if (strncmp(line, "HTTP/1.", 7) != 0 || strlen(line) < 12 ||
	    line[8] != ' ' || !isdigit((unsigned char) line[9]) ||
	    !isdigit((unsigned char) line[10]) ||
	    !isdigit((unsigned char) line[11])) {
		return (NNG_EPROTO);
	}
	*statusp = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
	return (0);
}

// Returns the HTTP status, or 0 when no complete response arrived.
static int
send_request(conf_auth_http *conf, conf_auth_http_req *conf_req,
    auth_http_params *params)
{
	nng_url      *url    = NULL;
	nng_http_req *req    = NULL;
	http_io       io     = { .fd = -1 };
	int           status = 0;
#if defined(NNG_TLS_ENGINE_MBEDTLS)
	bool          secure = false;
#endif
	int           rv;
	void         *head;
	size_t        head_len;
	void         *body;
	size_t        body_len;
	char          line[256];

	if (((rv = nng_url_parse(&url, conf_req->url)) != 0) ||
	    ((rv = nng_http_req_alloc(&req, url)) != 0)) {
		log_error("Prepare request failed: %s", nng_strerror(rv));
		goto out;
	}
	if (strcmp(url->u_scheme, "https") == 0) {
#if defined(NNG_TLS_ENGINE_MBEDTLS)
		secure = true;
#else
		log_error("Auth URL scheme https needs a TLS-enabled build");
		goto out;
#endif
	} else if (strcmp(url->u_scheme, "http") != 0) {
		log_error("Unsupported auth URL scheme: %s", url->u_scheme);
		goto out;
	}
	set_data(req, conf_req, params);
	nng_http_req_set_header(req, "Connection", "close");
	if ((rv = nni_http_req_get_buf((nni_http_req *) req, &head, &head_len)) !=
	    0) {
		log_error("Prepare request failed: %s", nng_strerror(rv));
		goto out;
	}
	nni_http_req_get_data((nni_http_req *) req, &body, &body_len);

	rv = http_connect(url->u_hostname, url->u_port,
	    http_now_ms() + conf->connect_timeout * 1000, &io.fd);
	if (rv != 0) {
		log_error("Connect failed: %s", nng_strerror(rv));
		goto out;
	}

#if defined(NNG_TLS_ENGINE_MBEDTLS)
	// The handshake is part of establishing the connection, so it gets its
	// own connect_timeout: a peer that accepts the socket but never
	// finishes TLS must not hold a worker thread for the request timeout.
	if (secure &&
	    (rv = http_tls_start(&io, url->u_hostname, conf_req,
	         http_now_ms() + conf->connect_timeout * 1000)) != 0) {
		goto out;
	}
#endif
	uint64_t deadline = http_now_ms() + conf->timeout * 1000;
	if (((rv = http_io_write(&io, head, head_len, deadline)) != 0) ||
	    ((rv = http_io_write(&io, body, body_len, deadline)) != 0)) {
		log_error("Write req failed: %s", nng_strerror(rv));
		goto out;
	}
	if ((rv = http_read_status(&io, deadline, line, sizeof(line), &status)) !=
	    0) {
		log_error("Read response: %s", nng_strerror(rv));
		status = 0;
		goto out;
	}
	if (status != NNG_HTTP_STATUS_OK) {
		log_error("HTTP Server Responded: %s", line);
	}

out:
	http_io_fini(&io);
	if (req) {
		nng_http_req_free(req);
	}
	if (url) {
		nng_url_free(url);
	}
	return status;
}
#else
static int
send_request(conf_auth_http *conf, conf_auth_http_req *conf_req,
    auth_http_params *params)
{
	nng_http_client *client = NULL;
	nng_http_conn *  conn   = NULL;
	nng_url *        url    = NULL;
	nng_aio *        aio    = NULL;
	nng_http_req *   req    = NULL;
	nng_http_res *   res    = NULL;
	int              status = 0;
	int              rv;

	nng_mtx_lock(conf_req->mtx);
	if (((rv = nng_url_parse(&url, conf_req->url)) != 0) ||
	    ((rv = nng_http_client_alloc(&client, url)) != 0) ||
	    ((rv = nng_http_req_alloc(&req, url)) != 0) ||
	    ((rv = nng_http_res_alloc(&res)) != 0) ||
	    ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0)) {
		goto out;
	}

	// Start connection process...
	nng_aio_set_timeout(aio, conf->connect_timeout * 1000);
	nng_http_client_connect(client, aio);

	// Wait for it to finish.
	// TODO It could cause some problems.
	nng_aio_wait(aio);
	if ((rv = nng_aio_result(aio)) != 0) {
		log_error("Connect failed: %s\n", nng_strerror(rv));
		goto out;
	}

	// Get the connection, at the 0th output.
	conn = nng_aio_get_output(aio, 0);
	// Request is already set up with URL, and for GET via HTTP/1.1.
	// The Host: header is already set up too.
	set_data(req, conf_req, params);
	// Send the request, and wait for that to finish.
	nng_aio_set_timeout(aio, conf->timeout * 1000);
	nng_http_conn_write_req(conn, req, aio);
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		log_error("Write req failed: %s", nng_strerror(rv));
		goto out;
	}

	// Read a response.
	nng_aio_set_timeout(aio, conf->timeout * 1000);
	nng_http_conn_read_res(conn, res, aio);
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		log_error("Read response: %s", nng_strerror(rv));
		goto out;
	}

	if ((status = nng_http_res_get_status(res)) != NNG_HTTP_STATUS_OK) {
		log_error("HTTP Server Responded: %d %s",
		    nng_http_res_get_status(res),
		    nng_http_res_get_reason(res));
		goto out;
	}

out:
	if (url) {
		nng_url_free(url);
	}
	if (req) {
		nng_http_req_free(req);
	}
	if (res) {
		nng_http_res_free(res);
	}
	if (conn) {
		nng_http_conn_close(conn);
	}
	if (client) {
		nng_http_client_free(client);
	}
	if (aio) {
		nng_aio_free(aio);
	}
	nng_mtx_unlock(conf_req->mtx);
	return status;
}

#endif // NNG_PLATFORM_POSIX

/**
 * HTTP 200 accepts the connection. A completed response with any other status
 * below 500 is a denial (NOT_AUTHORIZED). No response at all (connect, write
 * or read failure, timeout) or a 5xx means the backend could not decide, so the
 * client gets NMQ_SERVER_UNAVAILABLE and may retry. This mirrors the split
 * mosquitto-go-auth makes between a rejected user and a backend error.
 * Both close the connection after a failure CONNACK.
 * */
int
nmq_auth_http_connect(conn_param *cparam, conf_auth_http *conf)
{
	if (cparam == NULL) {
		log_error("nmq_auth_http_connect: cparam is NULL");
		return NOT_AUTHORIZED;
	}

	if (conf->enable == false || conf->auth_req.url == NULL) {
		log_info("HTTP Authentication is not enabled!");
		return SUCCESS;
	}

	auth_http_params auth_params = {
		.clientid  = (const char *) conn_param_get_clientid(cparam),
		.username  = (const char *) conn_param_get_username(cparam),
		.password  = (const char *) conn_param_get_password(cparam),
		.ipaddress = (const char *) conn_param_get_ip_addr_v4(cparam),
		.protocol = cparam->pro_name.body,
		.sockport = cparam->server_port,
		.common   = cparam->tls_peer_cn,
		.subject  = cparam->tls_subject,
	};

	int status = send_request(conf, &conf->auth_req, &auth_params);

	if (status == NNG_HTTP_STATUS_OK) {
		return SUCCESS;
	}
	if (status == 0 || status >= NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR) {
		return NMQ_SERVER_UNAVAILABLE;
	}
	return NOT_AUTHORIZED;
}

char *parse_topics(topic_queue *head)
{
	if (head == NULL) {
	    return NULL;
	}
	size_t total_length = 0;
	topic_queue *current = head;
	while (current != NULL) {
		if (current->topic == NULL || strlen(current->topic) == 0) {
			log_error("topic is empty");
			return NULL;
		}
		size_t tlen = strlen(current->topic);
		if (tlen > SIZE_MAX - total_length - 1) {
			log_error("topic list too long");
			return NULL;
		}
		total_length += tlen + 1; // for ','
		current = current->next;
	}
	char *result = (char *)nni_alloc(total_length + 1);
	if (result == NULL) {
		log_error("malloc failed");
		return NULL;
	}
	current = head;
	result[0] = '\0';
	while (current != NULL) {
	    strcat(result, current->topic);
	    strcat(result, ",");
	    current = current->next;
	}
	if (strlen(result) > 0) {
	    result[strlen(result) - 1] = '\0';
	}
	return result;
}

int
nmq_auth_http_sub_pub(
    conn_param *cparam, bool is_sub, topic_queue *topics, conf_auth_http *conf)
{
	if (conf->enable == false ||
	    (conf->super_req.url == NULL && conf->acl_req.url == NULL)) {
		return SUCCESS;
	}

	char *topic_str = parse_topics(topics);
	if (topic_str == NULL) {
		log_warn("Parsing topic failed for ACL");
		return NOT_AUTHORIZED;
	}

	auth_http_params auth_params = {
		.clientid  = (const char *) conn_param_get_clientid(cparam),
		.username  = (const char *) conn_param_get_username(cparam),
		.password  = (const char *) conn_param_get_password(cparam),
		.access    = is_sub ? "1" : "2",
		.topic     = topic_str,
		.ipaddress = conn_param_get_ip_addr_v4(cparam),
		// TODO incompleted fields
		// .mountpoint = ,
		.protocol = cparam->pro_name.body,
		.sockport = cparam->server_port,
		.common   = cparam->tls_peer_cn,
		.subject  = cparam->tls_subject,
	};
	int status = NNG_HTTP_STATUS_OK;

	// The key of ACL Cache Map is hash(clientid,username,password,access,topic,ip)
	// The ACL Cache Map will be reset after every interval.
	char *auth_params_clientid = "null";
	if (auth_params.clientid)
		auth_params_clientid = (char*) auth_params.clientid;
	char *auth_params_username = "null";
	if (auth_params.username)
		auth_params_username = (char*) auth_params.username;
	char *auth_params_password = "null";
	if (auth_params.password)
		auth_params_password = (char*) auth_params.password;
	char *auth_params_ipaddress = "null";
	if (auth_params.ipaddress)
		auth_params_ipaddress = (char*) auth_params.ipaddress;

	char acl_cache_k_str[1024];
	snprintf(acl_cache_k_str, 1024, "ACLK%s,%s,%s,%s,%s,%s",
		auth_params_clientid, auth_params_username, auth_params_password,
		auth_params.access, topic_str, auth_params_ipaddress);
	acl_cache_k_str[1023] = '\0'; // Avoid StackOverFlow
	uint32_t acl_cache_k = nanomq_siphash_32(acl_cache_k_str,
		strlen(acl_cache_k_str), NULL);

	if (conf->super_req.url) {
		if (conf->cache_ttl > 0 && conf->acl_cache_map != NULL) {
			nng_mtx_lock(conf->acl_cache_mtx);
			void *acl_cache_v = nng_id_get(
					conf->acl_cache_map, (uint64_t)acl_cache_k);
			nng_mtx_unlock(conf->acl_cache_mtx);
			if (acl_cache_v != NULL) {
				nni_free(topic_str, strlen(topic_str) + 1);
				return SUCCESS; // cache hit
			}
		}

		status = send_request(conf, &conf->super_req, &auth_params);
		if (status == NNG_HTTP_STATUS_OK) {
			if (conf->cache_ttl > 0 && conf->acl_cache_map != NULL) {
				log_debug("acl passed, add cache %ld, %s",
						acl_cache_k, acl_cache_k_str);
				nng_mtx_lock(conf->acl_cache_mtx);
				nng_id_set(conf->acl_cache_map,
						(uint64_t)acl_cache_k, (void*)conf);
				nng_mtx_unlock(conf->acl_cache_mtx);
			}
			nni_free(topic_str, strlen(topic_str) + 1);
			return SUCCESS;
		}
	}

	if (conf->acl_req.url) {
		if (conf->cache_ttl > 0 && conf->acl_cache_map != NULL) {
			nng_mtx_lock(conf->acl_cache_mtx);
			void *acl_cache_v = nng_id_get(
					conf->acl_cache_map, (uint64_t)acl_cache_k);
			nng_mtx_unlock(conf->acl_cache_mtx);
			if (acl_cache_v != NULL) {
				nni_free(topic_str, strlen(topic_str) + 1);
				return SUCCESS; // cache hit
			}
		}

		status = conf->acl_req.url == NULL
		    ? NNG_HTTP_STATUS_OK
		    : send_request(conf, &conf->acl_req, &auth_params);
		if (status == NNG_HTTP_STATUS_OK) {
			if (conf->cache_ttl > 0 && conf->acl_cache_map != NULL) {
				log_debug("acl passed, add cache %ld, %s",
						acl_cache_k, acl_cache_k_str);
				nng_mtx_lock(conf->acl_cache_mtx);
				nng_id_set(conf->acl_cache_map,
						(uint64_t)acl_cache_k, (void*)conf);
				nng_mtx_unlock(conf->acl_cache_mtx);
			}
		}
	}
	nni_free(topic_str, strlen(topic_str) + 1);

	return status == NNG_HTTP_STATUS_OK ? SUCCESS : NOT_AUTHORIZED;
}
