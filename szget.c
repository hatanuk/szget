#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h> 
#include <arpa/inet.h> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#define HTTPS_PORT "443"
#define HTTP_PORT "80"

// Program currently supports HTTP or HTTPS requests. No FTP, sorry.
#define HTTPS 1
#define HTTP 2

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef int (*read_func_t)(void *src, void *buf, size_t buf_size, size_t *bytes_read);

int parse_url(const char *url, int *prot, char *path, size_t psize, char *hostname, size_t hsize) {
    const char *start_p;
    const char *end_p;

    if (strncmp(url, "https://", 8) == 0) {
        start_p = url + 8;
        *prot = HTTPS;
    } else if (strncmp(url, "http://", 7) == 0) {
        start_p = url + 7;
        *prot = HTTP;
    } else if (strstr(url, "://") == NULL) {
        // No schema given — default to HTTP
        fprintf(stdout, "no schema found. defaulting to HTTP\n");
        start_p = url;
        *prot = HTTP;
    } else {
        fprintf(stderr, "unsupported schema found.\nplease include either https:// or http:// at the start of the url\n");
        return -1;
    }

    end_p = strchr(start_p, '/');

    // extract path & hostname
    if (end_p == NULL) {
        // no path, use / as default
        strcpy(path, "/");

        strncpy(hostname, start_p, hsize - 1);
        hostname[hsize - 1] = '\0';
    } else {
        strncpy(path, end_p, psize - 1);
        path[psize - 1] = '\0';

        size_t diff = end_p - start_p;
        strncpy(hostname, start_p, MIN(diff, hsize - 1));
        hostname[MIN(diff, hsize - 1)] = '\0';
    }

    return 0;

}

int parse_args(int argc, char *argv[], const char **outfile, const char **url) {

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                *outfile = argv[++i];  // use next argument as filename
            } else {
                fprintf(stderr, "Error: -o requires a filename\n");
                return -1;
            }
        } else {
            *url = argv[i];
        }
    }

    if (!*url) {
        fprintf(stderr, "Usage: %s [-o outputfile] <url>\n", argv[0]);
        return -1;
    }
    return 0;
}

int ssl_reader(void *src, void *buf, size_t buf_size, size_t *bytes_read) {
    SSL *ssl = (SSL *)src;
    int err;
    int ret = SSL_read_ex(ssl, buf, buf_size, bytes_read);

    if (ret <= 0) {
        if ((err = SSL_get_error(ssl, ret)) != SSL_ERROR_ZERO_RETURN) {
            unsigned long e = ERR_get_error();
            fprintf(stderr, "ssl reader: %s\n", ERR_error_string(e, NULL));
            return -1;
        } else {
            return 0;
        }
    }
    return 1;
}

int socket_reader(void *src, void *buf, size_t buf_size, size_t *bytes_read) {
    int *sockfd = (int *)src;
    *bytes_read = 0;

    ssize_t ret = recv(*sockfd, buf, buf_size, 0);
    if (ret == -1) {
        fprintf(stderr, "socket reader: %s\n", strerror(errno));
    } 
    if (ret > 0) {
        *bytes_read = (size_t)ret;
        return 1;
    }
    return (int)ret;
}


int write_res_to_file(void *src, read_func_t reader, const char * filename) {

    char buf[4096];
    char header_buf[8192];
    size_t header_bytes = 0;
    int header_done = 0;
    size_t bytes = 0;

    int ret;

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "res: failed to open file");
        return -1;
    }

    while ((ret = reader(src, buf, sizeof(buf), &bytes))) {
        if (ret == -1) {
            return -1;
        }

        if (!header_done) {
            if (header_bytes + bytes > sizeof(header_buf)) {
                fprintf(stderr, "res: header too large\n");
                return -1;
            }
            memcpy(header_buf + header_bytes, buf, bytes);
            header_bytes += bytes;
            header_buf[header_bytes] = '\0';

            char *body_start = strstr(header_buf, "\r\n\r\n");
            if (body_start) {
                header_done = 1;
                body_start += 4;
                size_t header_len = body_start - header_buf;
                size_t body_len = header_bytes - header_len;
                fwrite(body_start, 1, body_len, fp);
            }
        } else {
            fwrite(buf, 1, bytes, fp);
        }
    }

    return 0;
}


int build_get_request(char *buf, size_t size, const char *hostname, const char *path) {
    const char *request_end = "\r\n\r\n";

    snprintf(buf, size,
             "GET %s HTTP/1.1\r\nConnection: close\r\nHost: %s\r\nUser-Agent: shget/0.1\r\nAccept: */*%s",
             path, hostname, request_end);

    return 0;
}

int write_req_plain(int sockfd, const char *hostname, const char *path) {
    char request[8192]; 
    build_get_request(request, sizeof request, hostname, path);

    size_t sent = 0;
    size_t total = strlen(request);

    while (sent < total) {
        ssize_t n = send(sockfd, request, total, 0);
        if (n < 0) {
            perror("plain send");
            return -1;
        }
        sent+=n;
    }
    return 0;
}

int write_req_ssl(SSL *ssl, const char *hostname, const char *path) {
    size_t written;

    char request[8192]; 
    build_get_request(request, sizeof request, hostname, path);


    if (!SSL_write_ex(ssl, request, strlen(request), &written)) {
        fprintf(stderr, "ssl: failed to write HTTP request\n");
        return -1;
    }
   
    return 0;
}

int set_ssl(SSL **ssl, SSL_CTX *ctx, const char *hostname) {

    
    *ssl = SSL_new(ctx);
    if (*ssl == NULL) {
        fprintf(stderr, "ssl: failed to create the SSL object\n");
        return -1;
        }
    
    if (!SSL_set_tlsext_host_name(*ssl, hostname)) {
        fprintf(stderr, "ssl: failed to set the SNI hostname\n");
        return -1;
    }

    if (!SSL_set1_host(*ssl, hostname)) {
        fprintf(stderr, "ssl: failed to set the certificate verification hostname");
        return -1;
    }
    return 0;
}

int set_ssl_ctx(SSL_CTX *ctx) {
    if (ctx == NULL) {
        fprintf(stderr, "ssl: failed to create the SSL_CTX\n");
        return -1;
    }
    // aborts handshake if certificate verification fails 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // sets path to store certificate
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "ssl: failed to set the default trusted certificate store\n");
        return -1;
    }

    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "ssl: failed to set the minimum TLS protocol version\n");
        return -1;
    }
    return 0;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}


int main(int argc, char *argv[]) {
    struct addrinfo *results = NULL;
    struct addrinfo hints, *p;
    SSL_CTX *ctx = NULL;
    int sockfd = -1;
    FILE *fp = NULL;
    SSL *ssl = NULL;

    int prot = 0;
    const char *outfile = "out.bin"; 
    const char *url = NULL;
    char hostname[2048];
    char path[2048];

    int ret = EXIT_FAILURE;
    

    // arg parsing
    if (parse_args(argc, argv, &outfile, &url) != 0) {
        goto cleanup;
    }

    if (parse_url(url, &prot, path, sizeof path, hostname, sizeof hostname) != 0) {
        goto cleanup;
    }

    // creates a config object for SSL
    if (prot == HTTPS) {
        SSL_library_init(); 
        SSL_load_error_strings(); 
        OpenSSL_add_all_algorithms();

        ctx = SSL_CTX_new(TLS_client_method());
        if (set_ssl_ctx(ctx) == -1) {
            goto cleanup;
        }
    }


    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, prot == HTTPS ? HTTPS_PORT : HTTP_PORT, &hints, &results);

    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        goto cleanup;
    }

    for (p = results; p != NULL; p = p->ai_next) {
       
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }


        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            continue;
        }

        break;

    }

    if (p == NULL) {
        goto cleanup;
    } else {
        // SOCKET CONNECTED

        // SSL Path
        if (prot == HTTPS) {
            // Creates an ssl object for the connection
            if (set_ssl(&ssl, ctx, hostname) == -1) {
                close(sockfd);
                goto cleanup;
            }

            if (SSL_set_fd(ssl, sockfd) == -1) {
                fprintf(stderr, "Failed to link socket to SSL\n");
                goto cleanup;
            }

            // establishes SSL connection; now encrypted text can be written to the socket
            if (SSL_connect(ssl) < 1) {
                fprintf(stderr, "Failed to connect to the server\n");
                fprintf(stderr, "%d\n", (int) SSL_get_verify_result(ssl));
                if (SSL_get_verify_result(ssl) != X509_V_OK)
                    fprintf(stderr, "Verify error: %s\n",
                        X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
                goto cleanup;
            }

            if (write_req_ssl(ssl, hostname, path) == -1) {
                goto cleanup;
            }

            if (write_res_to_file(ssl, ssl_reader, outfile)== -1) {
                goto cleanup;
            }

        } else {
            // No SSL
            if (write_req_plain(sockfd, hostname, path) == -1) {
                goto cleanup;
            }

            if (write_res_to_file(&sockfd, socket_reader, outfile)== -1) {
                goto cleanup;
            }
        }

        // Success
        ret = EXIT_SUCCESS;

    }

    cleanup:
        if (fp) fclose(fp);
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ctx) SSL_CTX_free(ctx);
        if (sockfd != -1) close(sockfd);
        if (results) freeaddrinfo(results);

    if (ret == EXIT_SUCCESS) {
        fprintf(stdout, "File downloaded under %s\n", outfile);
    }

}


