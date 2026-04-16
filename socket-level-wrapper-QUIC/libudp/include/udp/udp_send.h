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
#ifndef UDP_SEND_H
#define UDP_SEND_H

#include <sys/uio.h>

#include <udp/udp_addr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return value for EAGAIN/EWOULDBLOCK (send would block). */
#define UDP_SEND_BLOCKED (-2)

/* Parameters for udp_send. All pointer fields are optional (NULL to skip). */
struct udp_send_info {
    const struct udp_addr *local_addr;  /* source addr via IP_PKTINFO */
    const struct udp_addr *remote_addr; /* destination (NULL if connected) */
    unsigned int ecn;                   /* ECN codepoint (0-3) */
    size_t gso_size;                    /* GSO segment size (0 to disable) */
};

/* Send datagram with optional ancillary data (ECN, pktinfo, GSO).
 * Returns bytes sent on success, -1 on error, UDP_SEND_BLOCKED on EAGAIN. */
ssize_t udp_send(int fd, const void *data, size_t datalen,
                 const struct udp_send_info *info);

/* Simple send on a connected socket (no ancillary data).
 * Returns bytes sent on success, -1 on error, UDP_SEND_BLOCKED on EAGAIN. */
ssize_t udp_send_simple(int fd, const void *data, size_t datalen);

/* Scatter-gather send with ancillary data.
 * Returns bytes sent on success, -1 on error, UDP_SEND_BLOCKED on EAGAIN. */
ssize_t udp_sendv(int fd, const struct iovec *iov, size_t iovcnt,
                  const struct udp_send_info *info);

#ifdef __cplusplus
}
#endif

#endif /* UDP_SEND_H */
