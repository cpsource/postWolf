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
#ifndef UDP_ADDR_H
#define UDP_ADDR_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UDP address (IPv4 or IPv6). Discriminated by addr.sa.sa_family. */
struct udp_addr {
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_storage ss;
    } addr;
    uint32_t ifindex;
};

/* Raw IP address without port (for netlink lookups etc). */
struct udp_inaddr {
    int family; /* AF_UNSPEC=empty, AF_INET, AF_INET6 */
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
};

/* Initialize address to empty (AF_UNSPEC). */
void udp_addr_init(struct udp_addr *addr);

/* Set from a sockaddr pointer. sa->sa_family must be AF_INET or AF_INET6. */
void udp_addr_set(struct udp_addr *addr, const struct sockaddr *sa,
                  socklen_t salen);

/* Get pointer to the sockaddr inside. */
struct sockaddr *udp_addr_sa(struct udp_addr *addr);
const struct sockaddr *udp_addr_sa_const(const struct udp_addr *addr);

/* Get address family (AF_INET, AF_INET6, or AF_UNSPEC if empty). */
int udp_addr_family(const struct udp_addr *addr);

/* Get port in host byte order. */
uint16_t udp_addr_port(const struct udp_addr *addr);

/* Set port (host byte order). */
void udp_addr_set_port(struct udp_addr *addr, uint16_t port);

/* Get socklen for this address. */
socklen_t udp_addr_size(const struct udp_addr *addr);

/* Returns 1 if address is empty (not set), 0 otherwise. */
int udp_addr_empty(const struct udp_addr *addr);

/* Resolve host:port via getaddrinfo. family can be AF_UNSPEC, AF_INET,
 * or AF_INET6. Returns 0 on success, -1 on error. */
int udp_addr_resolve(struct udp_addr *addr, const char *host, const char *port,
                     int family);

/* Format address as "[host]:port" into buf. Returns 0 on success, -1 on
 * error. */
int udp_addr_format(const struct udp_addr *addr, char *buf, size_t buflen);

/* Compare udp_addr with a raw udp_inaddr. Returns 1 if equal, 0 if not. */
int udp_addr_eq_inaddr(const struct udp_addr *addr,
                       const struct udp_inaddr *ia);

/* Initialize inaddr to empty. */
void udp_inaddr_init(struct udp_inaddr *ia);

/* Returns 1 if inaddr is empty, 0 otherwise. */
int udp_inaddr_empty(const struct udp_inaddr *ia);

/* Get pointer to the raw address bytes (in_addr* or in6_addr*).
 * Undefined if empty. */
const void *udp_inaddr_ptr(const struct udp_inaddr *ia);

#ifdef __cplusplus
}
#endif

#endif /* UDP_ADDR_H */
