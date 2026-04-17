/*
 * libudp - Standalone UDP socket library
 * Extracted from ngtcp2 examples (https://github.com/ngtcp2/ngtcp2)
 *
 * Copyright (c) 2017 ngtcp2 contributors
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
#ifndef UDP_SOCK_H
#define UDP_SOCK_H

#include <udp/udp_addr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Flags for udp_server_socket / udp_client_socket convenience functions. */
#define UDP_FLAG_ECN      0x01u
#define UDP_FLAG_PKTINFO  0x02u
#define UDP_FLAG_PMTU     0x04u
#define UDP_FLAG_DONTFRAG 0x08u
#define UDP_FLAG_GRO      0x10u
#define UDP_FLAG_ALL      0x1Fu

/* Create a nonblocking UDP socket. Returns fd >= 0 on success, -1 on error. */
int udp_socket_create(int family);

/* Make an existing fd nonblocking. Returns 0 on success, -1 on error. */
int udp_socket_set_nonblock(int fd);

/* Bind socket to address. Returns 0 on success, -1 on error. */
int udp_socket_bind(int fd, const struct udp_addr *addr);

/* Connect socket to remote address. Returns 0 on success, -1 on error. */
int udp_socket_connect(int fd, const struct udp_addr *addr);

/* Close socket. */
void udp_socket_close(int fd);

/* Enable receiving ECN bits (IP_RECVTOS / IPV6_RECVTCLASS). */
int udp_socket_enable_ecn(int fd, int family);

/* Enable receiving local address (IP_PKTINFO / IPV6_RECVPKTINFO). */
int udp_socket_enable_pktinfo(int fd, int family);

/* Set PMTU discovery (IP_MTU_DISCOVER / IPV6_MTU_DISCOVER). */
int udp_socket_set_pmtu_discover(int fd, int family);

/* Set dont-fragment (IP_DONTFRAG / IPV6_DONTFRAG). */
int udp_socket_set_dontfrag(int fd, int family);

/* Enable UDP GRO (Linux only). */
int udp_socket_enable_gro(int fd);

/* Set SO_REUSEADDR. */
int udp_socket_set_reuseaddr(int fd);

/* Convenience: create + bind + set options for a server socket.
 * Returns fd >= 0 on success, -1 on error. */
int udp_server_socket(const struct udp_addr *bind_addr, unsigned int flags);

/* Convenience: create + connect + set options for a client socket.
 * Returns fd >= 0 on success, -1 on error. */
int udp_client_socket(const struct udp_addr *remote_addr, unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif /* UDP_SOCK_H */
