#define _GNU_SOURCE

/*
 * libudp - Standalone UDP socket library
 * Extracted from ngtcp2 examples (https://github.com/ngtcp2/ngtcp2)
 *
 * Copyright (c) 2017 ngtcp2 contributors
 * Copyright (c) 2016 nghttp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <udp/udp_addr.h>

#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>

void udp_addr_init(struct udp_addr *addr) {
    memset(addr, 0, sizeof(*addr));
}

void udp_addr_set(struct udp_addr *addr, const struct sockaddr *sa,
                  socklen_t salen) {
    memset(addr, 0, sizeof(*addr));
    switch (sa->sa_family) {
    case AF_INET:
        memcpy(&addr->addr.sin, sa,
               salen < sizeof(addr->addr.sin) ? salen : sizeof(addr->addr.sin));
        break;
    case AF_INET6:
        memcpy(&addr->addr.sin6, sa,
               salen < sizeof(addr->addr.sin6) ? salen
                                                : sizeof(addr->addr.sin6));
        break;
    }
}

struct sockaddr *udp_addr_sa(struct udp_addr *addr) {
    return &addr->addr.sa;
}

const struct sockaddr *udp_addr_sa_const(const struct udp_addr *addr) {
    return &addr->addr.sa;
}

int udp_addr_family(const struct udp_addr *addr) {
    return addr->addr.sa.sa_family;
}

uint16_t udp_addr_port(const struct udp_addr *addr) {
    switch (addr->addr.sa.sa_family) {
    case AF_INET:
        return ntohs(addr->addr.sin.sin_port);
    case AF_INET6:
        return ntohs(addr->addr.sin6.sin6_port);
    default:
        return 0;
    }
}

void udp_addr_set_port(struct udp_addr *addr, uint16_t port) {
    switch (addr->addr.sa.sa_family) {
    case AF_INET:
        addr->addr.sin.sin_port = htons(port);
        break;
    case AF_INET6:
        addr->addr.sin6.sin6_port = htons(port);
        break;
    }
}

socklen_t udp_addr_size(const struct udp_addr *addr) {
    switch (addr->addr.sa.sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

int udp_addr_empty(const struct udp_addr *addr) {
    return addr->addr.sa.sa_family == AF_UNSPEC ||
           addr->addr.sa.sa_family == 0;
}

int udp_addr_resolve(struct udp_addr *addr, const char *host, const char *port,
                     int family) {
    struct addrinfo hints, *res;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        return -1;
    }

    udp_addr_set(addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 0;
}

int udp_addr_format(const struct udp_addr *addr, char *buf, size_t buflen) {
    char host[NI_MAXHOST];
    uint16_t port;

    switch (addr->addr.sa.sa_family) {
    case AF_INET:
        if (!inet_ntop(AF_INET, &addr->addr.sin.sin_addr, host,
                       sizeof(host))) {
            return -1;
        }
        port = ntohs(addr->addr.sin.sin_port);
        snprintf(buf, buflen, "%s:%u", host, port);
        return 0;
    case AF_INET6:
        if (!inet_ntop(AF_INET6, &addr->addr.sin6.sin6_addr, host,
                       sizeof(host))) {
            return -1;
        }
        port = ntohs(addr->addr.sin6.sin6_port);
        snprintf(buf, buflen, "[%s]:%u", host, port);
        return 0;
    default:
        return -1;
    }
}

int udp_addr_eq_inaddr(const struct udp_addr *addr,
                       const struct udp_inaddr *ia) {
    if (addr->addr.sa.sa_family != ia->family) {
        return 0;
    }
    switch (ia->family) {
    case AF_INET:
        return memcmp(&addr->addr.sin.sin_addr, &ia->addr.v4,
                      sizeof(struct in_addr)) == 0;
    case AF_INET6:
        return memcmp(&addr->addr.sin6.sin6_addr, &ia->addr.v6,
                      sizeof(struct in6_addr)) == 0;
    default:
        return 0;
    }
}

void udp_inaddr_init(struct udp_inaddr *ia) {
    memset(ia, 0, sizeof(*ia));
    ia->family = AF_UNSPEC;
}

int udp_inaddr_empty(const struct udp_inaddr *ia) {
    return ia->family == AF_UNSPEC;
}

const void *udp_inaddr_ptr(const struct udp_inaddr *ia) {
    switch (ia->family) {
    case AF_INET:
        return &ia->addr.v4;
    case AF_INET6:
        return &ia->addr.v6;
    default:
        return NULL;
    }
}
