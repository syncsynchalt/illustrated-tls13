// from https://wiki.openssl.org/index.php/Simple_TLS_Server
// licensed via Openssl License https://www.openssl.org/source/license.html
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>

void die(const char *str)
{
	fprintf(stderr, "%s: %s\n", str, strerror(errno));
	exit(1);
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx)
		die("Unable to create SSL context");
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	return ctx;
}

void keylog_callback(const SSL *ssl, const char *line)
{
	printf("%s\n", line);
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_keylog_callback(ctx, keylog_callback);
}

void configure_connection(SSL *ssl)
{
	SSL_set_tlsext_host_name(ssl, "example.ulfheim.net");
	SSL_set_connect_state(ssl);
	if (SSL_do_handshake(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to do handshake");
	}
}

size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr)
{
	struct addrinfo *res = 0;
	if (getaddrinfo(host, port, 0, &res) != 0)
		die("Unable to transform address");
	size_t len = res->ai_addrlen;
	memcpy(addr, res->ai_addr, len);
	freeaddrinfo(res);
	return len;
}

int main(int argc, char **argv)
{
	// set up ssl
	init_openssl();
	SSL_CTX *ctx = create_context();
	configure_context(ctx);

	int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		die("Unable to create socket");

	// create connection to localhost:8400
	struct sockaddr_storage addr;
	size_t len = resolve_hostname("127.0.0.1", "8400", &addr);
	if (connect(sock, (struct sockaddr *)&addr, len) < 0) {
		die("Unable to connect to 127.0.0.1:8400");
	}

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	configure_connection(ssl);

	char wbuf[] = "ping";
	if (SSL_write(ssl, wbuf, strlen(wbuf)) <= 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to write to server");
	}
	printf("Wrote [%s]\n", wbuf);

	char rbuf[128];
	int ret = SSL_read(ssl, rbuf, sizeof(rbuf)-1);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to read from server");
	}
	rbuf[ret] = '\0';
	printf("Read [%s]\n", rbuf);

	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}
