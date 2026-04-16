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
#include <udp/udp_recv.h>

#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#  include <netinet/udp.h>
#endif

#ifndef IPTOS_ECN_MASK
#  define IPTOS_ECN_MASK 0x03
#endif

/* cmsg space: ECN + pktinfo + GRO */
#define UDP_RECV_CMSG_BUFSIZE                                                  \
    (CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo)) +        \
     CMSG_SPACE(sizeof(int)))

static uint8_t extract_ecn(struct msghdr *msg, int family) {
    struct cmsghdr *cmsg;

    switch (family) {
    case AF_INET:
        for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP &&
#ifdef __APPLE__
                cmsg->cmsg_type == IP_RECVTOS
#else
                cmsg->cmsg_type == IP_TOS
#endif
                && cmsg->cmsg_len) {
                uint8_t tos;
                memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
                return tos & IPTOS_ECN_MASK;
            }
        }
        break;
    case AF_INET6:
        for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                cmsg->cmsg_type == IPV6_TCLASS && cmsg->cmsg_len) {
                unsigned int tclass;
                memcpy(&tclass, CMSG_DATA(cmsg), sizeof(int));
                return (uint8_t)(tclass & IPTOS_ECN_MASK);
            }
        }
        break;
    }
    return 0;
}

static int extract_local_addr(struct msghdr *msg, int family,
                              struct udp_addr *addr) {
    struct cmsghdr *cmsg;

    switch (family) {
    case AF_INET:
        for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo pktinfo;
                memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
                memset(addr, 0, sizeof(*addr));
                addr->ifindex = (uint32_t)pktinfo.ipi_ifindex;
                addr->addr.sin.sin_family = AF_INET;
                addr->addr.sin.sin_addr = pktinfo.ipi_addr;
                return 1;
            }
        }
        break;
    case AF_INET6:
        for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                cmsg->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo pktinfo;
                memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
                memset(addr, 0, sizeof(*addr));
                addr->ifindex = (uint32_t)pktinfo.ipi6_ifindex;
                addr->addr.sin6.sin6_family = AF_INET6;
                addr->addr.sin6.sin6_addr = pktinfo.ipi6_addr;
                return 1;
            }
        }
        break;
    }
    return 0;
}

static size_t extract_gro_size(struct msghdr *msg) {
#ifdef UDP_GRO
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
            int gso_size = 0;
            memcpy(&gso_size, CMSG_DATA(cmsg), sizeof(gso_size));
            return (size_t)gso_size;
        }
    }
#else
    (void)msg;
#endif
    return 0;
}

ssize_t udp_recv(int fd, void *buf, size_t buflen, int family,
                 struct udp_msg_info *info) {
    uint8_t cmsg_buf[UDP_RECV_CMSG_BUFSIZE];
    struct iovec iov;
    struct msghdr msg;
    ssize_t nread;

    memset(info, 0, sizeof(*info));

    iov.iov_base = buf;
    iov.iov_len = buflen;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &info->remote_addr.addr.ss;
    msg.msg_namelen = sizeof(info->remote_addr.addr.ss);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
#ifdef __APPLE__
    msg.msg_controllen = (socklen_t)sizeof(cmsg_buf);
#else
    msg.msg_controllen = sizeof(cmsg_buf);
#endif

    do {
        nread = recvmsg(fd, &msg, 0);
    } while (nread == -1 && errno == EINTR);

    if (nread == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return UDP_RECV_BLOCKED;
        }
        return -1;
    }

    info->ecn = extract_ecn(&msg, family);
    info->have_local_addr = extract_local_addr(&msg, family, &info->local_addr);
    info->gro_size = extract_gro_size(&msg);

    return nread;
}

ssize_t udp_recv_simple(int fd, void *buf, size_t buflen,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t nread;
    do {
        nread = recvfrom(fd, buf, buflen, 0, src_addr, addrlen);
    } while (nread == -1 && errno == EINTR);

    if (nread == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return UDP_RECV_BLOCKED;
        }
        return -1;
    }
    return nread;
}
