#define _GNU_SOURCE

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
#include <udp/udp_send.h>

#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#  include <netinet/udp.h>
#endif

/* Maximum cmsg space: pktinfo + ECN + GSO */
#define UDP_CMSG_BUFSIZE                                                       \
    (CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int)) +        \
     CMSG_SPACE(sizeof(uint16_t)))

static ssize_t do_sendmsg(int fd, const struct iovec *iov, size_t iovcnt,
                          const struct udp_send_info *info) {
    uint8_t cmsg_buf[UDP_CMSG_BUFSIZE];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    size_t controllen = 0;

    memset(&msg, 0, sizeof(msg));

    /* Set destination if provided (unconnected socket). */
    if (info && info->remote_addr && !udp_addr_empty(info->remote_addr)) {
        msg.msg_name = (void *)udp_addr_sa_const(info->remote_addr);
        msg.msg_namelen = udp_addr_size(info->remote_addr);
    }

    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = iovcnt;

    if (info) {
        memset(cmsg_buf, 0, sizeof(cmsg_buf));
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        cmsg = CMSG_FIRSTHDR(&msg);

        /* Local address via IP_PKTINFO / IPV6_PKTINFO */
        if (info->local_addr && !udp_addr_empty(info->local_addr)) {
            int family = udp_addr_family(info->local_addr);
            switch (family) {
            case AF_INET: {
                struct in_pktinfo pktinfo;
                memset(&pktinfo, 0, sizeof(pktinfo));
                pktinfo.ipi_ifindex = (int)info->local_addr->ifindex;
                pktinfo.ipi_spec_dst = info->local_addr->addr.sin.sin_addr;

                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(pktinfo));
                memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));

                controllen += CMSG_SPACE(sizeof(pktinfo));
                cmsg = (struct cmsghdr *)((uint8_t *)cmsg +
                                          CMSG_SPACE(sizeof(pktinfo)));
                break;
            }
            case AF_INET6: {
                struct in6_pktinfo pktinfo;
                memset(&pktinfo, 0, sizeof(pktinfo));
                pktinfo.ipi6_ifindex = info->local_addr->ifindex;
                pktinfo.ipi6_addr = info->local_addr->addr.sin6.sin6_addr;

                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(pktinfo));
                memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));

                controllen += CMSG_SPACE(sizeof(pktinfo));
                cmsg = (struct cmsghdr *)((uint8_t *)cmsg +
                                          CMSG_SPACE(sizeof(pktinfo)));
                break;
            }
            }
        }

        /* ECN codepoint via IP_TOS / IPV6_TCLASS */
        if (info->ecn) {
            unsigned int tos = info->ecn;
            int family = 0;

            if (info->remote_addr) {
                family = udp_addr_family(info->remote_addr);
            } else if (info->local_addr) {
                family = udp_addr_family(info->local_addr);
            }

            switch (family) {
            case AF_INET:
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_TOS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                controllen += CMSG_SPACE(sizeof(tos));
                cmsg = (struct cmsghdr *)((uint8_t *)cmsg +
                                          CMSG_SPACE(sizeof(tos)));
                break;
            case AF_INET6:
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_TCLASS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                controllen += CMSG_SPACE(sizeof(tos));
                cmsg = (struct cmsghdr *)((uint8_t *)cmsg +
                                          CMSG_SPACE(sizeof(tos)));
                break;
            }
        }

        /* GSO segment size via UDP_SEGMENT (Linux only) */
#ifdef UDP_SEGMENT
        if (info->gso_size > 0) {
            /* Compute total data length */
            size_t total = 0;
            for (size_t i = 0; i < iovcnt; i++) {
                total += iov[i].iov_len;
            }
            if (total > info->gso_size) {
                uint16_t gso = (uint16_t)info->gso_size;
                cmsg->cmsg_level = SOL_UDP;
                cmsg->cmsg_type = UDP_SEGMENT;
                cmsg->cmsg_len = CMSG_LEN(sizeof(gso));
                memcpy(CMSG_DATA(cmsg), &gso, sizeof(gso));
                controllen += CMSG_SPACE(sizeof(gso));
            }
        }
#endif

        if (controllen > 0) {
#ifdef __APPLE__
            msg.msg_controllen = (socklen_t)controllen;
#else
            msg.msg_controllen = controllen;
#endif
        } else {
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
        }
    }

    ssize_t nwrite;
    do {
        nwrite = sendmsg(fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return UDP_SEND_BLOCKED;
        }
        return -1;
    }

    return nwrite;
}

ssize_t udp_send(int fd, const void *data, size_t datalen,
                 const struct udp_send_info *info) {
    struct iovec iov;
    iov.iov_base = (void *)data;
    iov.iov_len = datalen;
    return do_sendmsg(fd, &iov, 1, info);
}

ssize_t udp_send_simple(int fd, const void *data, size_t datalen) {
    ssize_t nwrite;
    do {
        nwrite = send(fd, data, datalen, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return UDP_SEND_BLOCKED;
        }
        return -1;
    }
    return nwrite;
}

ssize_t udp_sendv(int fd, const struct iovec *iov, size_t iovcnt,
                  const struct udp_send_info *info) {
    return do_sendmsg(fd, iov, iovcnt, info);
}
