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
#ifndef UDP_RECV_H
#define UDP_RECV_H

#include <udp/udp_addr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return value for EAGAIN/EWOULDBLOCK (no data available). */
#define UDP_RECV_BLOCKED (-2)

/* Information extracted from a received datagram. */
struct udp_msg_info {
    struct udp_addr remote_addr;    /* source address of packet */
    struct udp_addr local_addr;     /* local destination (from IP_PKTINFO) */
    uint8_t ecn;                    /* ECN bits (0-3) */
    size_t gro_size;                /* GRO segment size (0 = not coalesced) */
    int have_local_addr;            /* nonzero if local_addr was extracted */
};

/* Receive datagram with ancillary data extraction (ECN, pktinfo, GRO).
 * |family| is the socket's address family (needed for cmsg interpretation).
 * Returns bytes received on success, -1 on error, UDP_RECV_BLOCKED on
 * EAGAIN. */
ssize_t udp_recv(int fd, void *buf, size_t buflen, int family,
                 struct udp_msg_info *info);

/* Simple receive (no ancillary data extraction).
 * Returns bytes received on success, -1 on error, UDP_RECV_BLOCKED on
 * EAGAIN. */
ssize_t udp_recv_simple(int fd, void *buf, size_t buflen,
                        struct sockaddr *src_addr, socklen_t *addrlen);

#ifdef __cplusplus
}
#endif

#endif /* UDP_RECV_H */
