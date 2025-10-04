// Developer: Sreeraj 
// GitHub: https://github.com/s-r-e-e-r-a-j 

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define DEFAULT_WHOIS "whois.iana.org"
#define DEFAULT_PORT "43"
#define MAX_RESP_SIZE (256 * 1024)
#define MAX_LINE 1024
#define DEFAULT_TIMEOUT_MS 7000
#define MAX_REFERRALS 4

static const char *default_servers[] = {
    "whois.iana.org",
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net",
    "whois.verisign-grs.com",
    "whois.pir.org"
};
#define DEFAULT_SERVERS_COUNT (sizeof(default_servers)/sizeof(default_servers[0]))

static const char *ip_only_servers[] = {
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net"
};
static const int ip_only_count = sizeof(ip_only_servers) / sizeof(ip_only_servers[0]);

typedef struct {
    char **servers;
    int servers_count;
    char *port;
    int timeout_ms;
    int follow_referrals;
    int threads;
    int json;
} options_t;

typedef struct {
    char *query;
    options_t *opts;
} job_t;

typedef struct job_node {
    job_t *job;
    struct job_node *next;
} job_node_t;

typedef struct {
    job_node_t *head, *tail;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int stop;
} job_queue_t;

static job_queue_t jq;

int is_ip(const char *s) {
    struct in_addr addr4;
    struct in6_addr addr6;
    return inet_pton(AF_INET, s, &addr4) == 1 || inet_pton(AF_INET6, s, &addr6) == 1;
}

char *resolve_hostname_to_ip(const char *hostname) {
    struct addrinfo hints, *res;
    char buf[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        // Failed to resolve, return original hostname
        return strdup(hostname);
    }

    void *addr;
    if (res->ai_family == AF_INET) {
        addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    } else { // AF_INET6
        addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    }

    inet_ntop(res->ai_family, addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return strdup(buf);
}

// Check if a server requires an IP address
int server_requires_ip(const char *server) {
    for (int i = 0; i < ip_only_count; ++i) {
        if (strcmp(server, ip_only_servers[i]) == 0)
            return 1;
    }
    return 0;
}

// Convert hostname to IP if server requires it
char *maybe_resolve_hostname(const char *query, const char *server) {
    if (!server_requires_ip(server)) return strdup(query); // server accepts domains
    if (is_ip(query)) return strdup(query);              // already an IP
    return resolve_hostname_to_ip(query);                // convert hostname to IP
}

void job_queue_init(job_queue_t *q) {
    q->head = q->tail = NULL;
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->cv, NULL);
    q->stop = 0;
}

void job_queue_push(job_queue_t *q, job_t *job) {
    job_node_t *n = malloc(sizeof(*n));
    n->job = job;
    n->next = NULL;
    pthread_mutex_lock(&q->mu);
    if (!q->tail) {
        q->head = n;
        q->tail = n;
    } else {
        q->tail->next = n;
        q->tail = n;
    }
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->mu);
}

job_t* job_queue_pop(job_queue_t *q) {
    pthread_mutex_lock(&q->mu);
    while (!q->head && !q->stop) {
        pthread_cond_wait(&q->cv, &q->mu);
    }
    if (q->stop && !q->head) {
        pthread_mutex_unlock(&q->mu);
        return NULL;
    }
    job_node_t *n = q->head;
    q->head = n->next;
    if (!q->head) {
        q->tail = NULL;
    }
    pthread_mutex_unlock(&q->mu);
    job_t *j = n->job;
    free(n);
    return j;
}

void job_queue_stop(job_queue_t *q) {
    pthread_mutex_lock(&q->mu);
    q->stop = 1;
    pthread_cond_broadcast(&q->cv);
    pthread_mutex_unlock(&q->mu);
}

void job_queue_cleanup(job_queue_t *q) {
    job_queue_stop(q);
    pthread_mutex_destroy(&q->mu);
    pthread_cond_destroy(&q->cv);
    job_node_t *current = q->head;
    while (current) {
        job_node_t *next = current->next;
        free(current->job->query);
        free(current->job);
        free(current);
        current = next;
    }
    q->head = q->tail = NULL;
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int connect_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    if (timeout_ms <= 0) return connect(sockfd, addr, addrlen);
    int r = connect(sockfd, addr, addrlen);
    if (r == 0) return 0;
    if (errno != EINPROGRESS) return -1;
    fd_set wf;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&wf);
    FD_SET(sockfd, &wf);
    r = select(sockfd + 1, NULL, &wf, NULL, &tv);
    if (r <= 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) return -1;
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

int resolve_and_connect(const char *host, const char *port, int timeout_ms) {
    struct addrinfo hints, *res, *rp;
    int sfd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) continue;
        if (set_nonblocking(sfd) == -1) {
            close(sfd);
            sfd = -1;
            continue;
        }
        if (connect_timeout(sfd, rp->ai_addr, rp->ai_addrlen, timeout_ms) == 0) {
            int flags = fcntl(sfd, F_GETFL, 0);
            fcntl(sfd, F_SETFL, flags & ~O_NONBLOCK);
            break;
        }
        close(sfd);
        sfd = -1;
    }
    freeaddrinfo(res);
    return sfd;
}

char *recv_all(int sfd, int timeout_ms, size_t *out_len) {
    size_t cap = 8192;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    while (1) {
        if (len + 4096 > cap) {
            cap *= 2;
            if (cap > MAX_RESP_SIZE) cap = len + 4096;
            char *n = realloc(buf, cap);
            if (!n) break;
            buf = n;
        }
        ssize_t r = recv(sfd, buf + len, cap - len, 0);
        if (r > 0) {
            len += r;
            if (len >= MAX_RESP_SIZE) break;
            continue;
        } else if (r == 0) {
            break;
        } else {
            if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) break;
            break;
        }
    }
    if (len + 1 > cap) {
        char *n = realloc(buf, len + 1);
        if (!n) {
            free(buf);
            return NULL;
        }
        buf = n;
    }
    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

int send_all(int sfd, const char *buf, size_t len, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv));
    size_t off = 0;
    while (off < len) {
        ssize_t r = send(sfd, buf + off, len - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += r;
    }
    return 0;
}

char *find_referral(const char *resp) {
    if (!resp) return NULL;
    const char *p = resp;
    while (*p) {
        const char *line_end = strchr(p, '\n');
        size_t linelen = line_end ? (size_t)(line_end - p) : strlen(p);
        if (linelen > 0) {
            char line[MAX_LINE + 1];
            size_t copylen = linelen < MAX_LINE ? linelen : MAX_LINE;
            memcpy(line, p, copylen);
            line[copylen] = '\0';
            char lower[MAX_LINE + 1];
            for (size_t i = 0; i <= copylen; ++i) lower[i] = tolower((unsigned char)line[i]);
            lower[copylen] = '\0';
            const char *k;
            if ((k = strstr(lower, "whois server:")) ||
                (k = strstr(lower, "whois-server:")) ||
                (k = strstr(lower, "whois:")) ||
                (k = strstr(lower, "refer:")) ||
                (k = strstr(lower, "referralserver:")) ||
                (k = strstr(lower, "registrar whois server:"))) {
                const char *after = strchr(line, ':');
                if (after) {
                    ++after;
                    while (*after && isspace((unsigned char)*after)) ++after;
                    if (*after) {
                        char tmp[MAX_LINE + 1];
                        strncpy(tmp, after, MAX_LINE);
                        tmp[MAX_LINE] = '\0';
                        char *host = tmp;
                        if (strncmp(host, "rwhois://", 9) == 0) host += 9;
                        else if (strncmp(host, "whois://", 8) == 0) host += 8;
                        char *colon = strchr(host, ':');
                        if (colon) *colon = '\0';
                        char *end = host + strlen(host) - 1;
                        while (end > host && isspace((unsigned char)*end)) *end-- = '\0';
                        if (strlen(host) > 0) return strdup(host);
                    }
                } else {
                    char *tok = strtok(line, " \t");
                    while (tok) {
                        if (strstr(tok, "whois")) {
                            tok = strtok(NULL, " \t");
                            break;
                        }
                        tok = strtok(NULL, " \t");
                    }
                    if (tok) {
                        char *h = strdup(tok);
                        char *colon = strchr(h, ':');
                        if (colon) *colon = '\0';
                        return h;
                    }
                }
            }
        }
        if (!line_end) break;
        p = line_end + 1;
    }
    return NULL;
}

char *json_escape(const char *s) {
    if (!s) return strdup("");
    size_t cap = 128;
    char *out = malloc(cap);
    size_t o = 0;
    for (const char *p = s; *p; ++p) {
        if (o + 10 > cap) {
            cap *= 2;
            out = realloc(out, cap);
        }
        unsigned char c = (unsigned char)*p;
        if (c == '\\') {
            out[o++] = '\\';
            out[o++] = '\\';
        } else if (c == '"') {
            out[o++] = '\\';
            out[o++] = '"';
        } else if (c == '\b') {
            out[o++] = '\\';
            out[o++] = 'b';
        } else if (c == '\f') {
            out[o++] = '\\';
            out[o++] = 'f';
        } else if (c == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c == '\r') {
            out[o++] = '\\';
            out[o++] = 'r';
        } else if (c == '\t') {
            out[o++] = '\\';
            out[o++] = 't';
        } else {
            out[o++] = *p;
        }
    }
    out[o] = '\0';
    return out;
}

int response_usable(const char *resp) {
    if (!resp) return 0;
    while (*resp && isspace((unsigned char)*resp)) resp++;
    if (*resp == '\0') return 0;
    if (strncmp(resp, "ERROR:", 6) == 0) return 0;
    return 1;
}

char *whois_query_multi(char **servers, int servers_count, const char *port, const char *query, int timeout_ms, int follow_referrals) {
    char *cur_server = NULL;
    int initial_index = 0;
    char *resp_total = NULL;
    size_t total_len = 0;

    if (servers_count > 0 && initial_index < servers_count) {
        cur_server = strdup(servers[initial_index++]);
    } else {
        cur_server = strdup(DEFAULT_WHOIS);
    }

    for (int depth = 0; depth <= (follow_referrals ? MAX_REFERRALS : 0); ++depth) {
        int tried_from_list = 0;
        for (;;) {
            int sfd = resolve_and_connect(cur_server, port, timeout_ms);
            if (sfd < 0) {
                if (servers_count > 0 && initial_index < servers_count) {
                    free(cur_server);
                    cur_server = strdup(servers[initial_index++]);
                    tried_from_list = 1;
                    continue;
                } else {
                    char errbuf[256];
                    snprintf(errbuf, sizeof(errbuf), "ERROR: connect to %s:%s failed: %s\n", cur_server, port, strerror(errno));
                    if (!resp_total) {
                        resp_total = strdup(errbuf);
                        total_len = strlen(resp_total);
                    } else {
                        size_t nl = strlen(errbuf);
                        resp_total = realloc(resp_total, total_len + nl + 1);
                        memcpy(resp_total + total_len, errbuf, nl + 1);
                        total_len += nl;
                    }
                    break;
                }
            }
            char qline[512];
            snprintf(qline, sizeof(qline), "%s\r\n", query);
            if (send_all(sfd, qline, strlen(qline), timeout_ms) != 0) {
                close(sfd);
                if (servers_count > 0 && initial_index < servers_count) {
                    free(cur_server);
                    cur_server = strdup(servers[initial_index++]);
                    tried_from_list = 1;
                    continue;
                } else {
                    char errbuf[256];
                    snprintf(errbuf, sizeof(errbuf), "ERROR: send to %s failed: %s\n", cur_server, strerror(errno));
                    if (!resp_total) {
                        resp_total = strdup(errbuf);
                        total_len = strlen(resp_total);
                    } else {
                        size_t nl = strlen(errbuf);
                        resp_total = realloc(resp_total, total_len + nl + 1);
                        memcpy(resp_total + total_len, errbuf, nl + 1);
                        total_len += nl;
                    }
                    break;
                }
            }
            size_t resp_len = 0;
            char *resp = recv_all(sfd, timeout_ms, &resp_len);
            close(sfd);
            if (!resp) {
                if (servers_count > 0 && initial_index < servers_count) {
                    free(cur_server);
                    cur_server = strdup(servers[initial_index++]);
                    tried_from_list = 1;
                    continue;
                } else {
                    char errbuf[256];
                    snprintf(errbuf, sizeof(errbuf), "ERROR: receive from %s failed: %s\n", cur_server, strerror(errno));
                    if (!resp_total) {
                        resp_total = strdup(errbuf);
                        total_len = strlen(resp_total);
                    } else {
                        size_t nl = strlen(errbuf);
                        resp_total = realloc(resp_total, total_len + nl + 1);
                        memcpy(resp_total + total_len, errbuf, nl + 1);
                        total_len += nl;
                    }
                    break;
                }
            }
            if (!resp_total) {
                resp_total = resp;
                total_len = resp_len;
            } else {
                resp_total = realloc(resp_total, total_len + resp_len + 1);
                memcpy(resp_total + total_len, resp, resp_len + 1);
                total_len += resp_len;
                free(resp);
            }

            if (!response_usable(resp_total)) {
                if (servers_count > 0 && initial_index < servers_count) {
                    free(resp_total);
                    resp_total = NULL;
                    total_len = 0;
                    free(cur_server);
                    cur_server = strdup(servers[initial_index++]);
                    tried_from_list = 1;
                    continue;
                }
            }

            if (follow_referrals) {
                char *ref = find_referral(resp_total);
                if (ref && strlen(ref) > 0) {
                    if (cur_server && strcmp(cur_server, ref) == 0) {
                        free(ref);
                        break;
                    }
                    free(cur_server);
                    cur_server = ref;
                    continue;
                }
                if (ref) free(ref);
            }
            break;
        }
        break;
    }

    if (cur_server) free(cur_server);
    return resp_total;
}

void *worker_fn(void *arg) {
    options_t *opts = arg;
    while (1) {
        job_t *job = job_queue_pop(&jq);
        if (!job) break;

        char *actual_query = job->query;
        char *resp_total = NULL;

        for (int i = 0; i < opts->servers_count; ++i) {
            char *server = opts->servers[i];
            char *respected_query = maybe_resolve_hostname(actual_query, server);

            char *resp = whois_query_multi(&server, 1, opts->port ? opts->port : DEFAULT_PORT,
                                           respected_query, opts->timeout_ms, opts->follow_referrals);

            if (!resp_total) {
                resp_total = resp;
            } else {
                size_t len_total = strlen(resp_total);
                size_t len_resp = strlen(resp);
                resp_total = realloc(resp_total, len_total + len_resp + 2);
                memcpy(resp_total + len_total, "\n", 1);
                memcpy(resp_total + len_total + 1, resp, len_resp + 1);
                free(resp);
            }

            free(respected_query);
        }

        if (opts->json) {
            char *escq = json_escape(actual_query);

            size_t sslen = 0;
            for (int i = 0; i < opts->servers_count; ++i) sslen += strlen(opts->servers[i]) + 1;
            char *server_list_str = malloc(sslen + 1);
            server_list_str[0] = '\0';
            for (int i = 0; i < opts->servers_count; ++i) {
                if (i) strcat(server_list_str, ",");
                strcat(server_list_str, opts->servers[i]);
            }

            char *escs = json_escape(server_list_str);
            char *escresp = json_escape(resp_total ? resp_total : "");
            printf("{\"query\":\"%s\",\"servers\":\"%s\",\"response\":\"%s\"}\n", escq, escs, escresp);

            free(escq);
            free(escs);
            free(escresp);
            free(server_list_str);
        } else {
            size_t sslen = 0;
            for (int i = 0; i < opts->servers_count; ++i) sslen += strlen(opts->servers[i]) + 1;
            char *servers_display = malloc(sslen + 1);
            servers_display[0] = '\0';
            for (int i = 0; i < opts->servers_count; ++i) {
                if (i) strcat(servers_display, ",");
                strcat(servers_display, opts->servers[i]);
            }

            printf(">>> Query: %s\n--- WHOIS (servers: %s port:%s) ---\n%s\n",
                   actual_query,
                   servers_display,
                   opts->port ? opts->port : DEFAULT_PORT,
                   resp_total ? resp_total : "(no response)");
            free(servers_display);
        }

        free(job->query);
        free(job);
        if (resp_total) free(resp_total);
    }
    return NULL;
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] query1 [query2 ...]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -S server1,server2,...   Comma-separated list of WHOIS servers\n");
    fprintf(stderr, "  -p port                  Port number (default: 43)\n");
    fprintf(stderr, "  -t timeout_ms            Timeout in milliseconds (default: 7000)\n");
    fprintf(stderr, "  -r                       Follow referrals (default: off)\n");
    fprintf(stderr, "  -j                       JSON output\n");
    fprintf(stderr, "  -h                       Show this help\n");
}

int main(int argc, char *argv[]) {
    options_t opts = {0};
    opts.port = NULL;
    opts.timeout_ms = DEFAULT_TIMEOUT_MS;
    opts.follow_referrals = 0;
    opts.threads = 1;
    opts.json = 0;
    opts.servers = NULL;
    opts.servers_count = 0;

    int opt;
    while ((opt = getopt(argc, argv, "S:p:t:rjh")) != -1) {
        switch (opt) {
            case 'S': {
                char *token = strtok(optarg, ",");
                while (token) {
                    opts.servers = realloc(opts.servers, (opts.servers_count + 1) * sizeof(char*));
                    opts.servers[opts.servers_count++] = strdup(token);
                    token = strtok(NULL, ",");
                }
                break;
            }
            case 'p':
                opts.port = strdup(optarg);
                break;
            case 't':
                opts.timeout_ms = atoi(optarg);
                break;
            case 'r':
                opts.follow_referrals = 1;
                break;
            case 'j':
                opts.json = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    if (opts.servers_count == 0) {
        opts.servers = malloc(DEFAULT_SERVERS_COUNT * sizeof(char*));
        for (size_t i = 0; i < DEFAULT_SERVERS_COUNT; i++) {
            opts.servers[i] = strdup(default_servers[i]);
        }
        opts.servers_count = DEFAULT_SERVERS_COUNT;
    }

    job_queue_init(&jq);

    for (int i = optind; i < argc; i++) {
        job_t *job = malloc(sizeof(*job));
        job->query = strdup(argv[i]);
        job->opts = &opts;
        job_queue_push(&jq, job);
    }

    pthread_t *threads = malloc(opts.threads * sizeof(pthread_t));
    for (int i = 0; i < opts.threads; i++) {
        pthread_create(&threads[i], NULL, worker_fn, &opts);
    }

    // Signal workers that no more jobs will be added
    job_queue_stop(&jq);

    for (int i = 0; i < opts.threads; i++) {
        pthread_join(threads[i], NULL);
    }

    job_queue_cleanup(&jq);
    free(threads);
    for (int i = 0; i < opts.servers_count; i++) {
        free(opts.servers[i]);
    }
    free(opts.servers);
    if (opts.port) free(opts.port);

    return 0;
}
