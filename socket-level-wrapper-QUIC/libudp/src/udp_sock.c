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
#include <udp/udp_sock.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#  include <netinet/udp.h>
#endif

int udp_socket_set_nonblock(int fd) {
    int flags;

    while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if (flags == -1) {
        return -1;
    }

    while (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        if (errno != EINTR) {
            return -1;
        }
    }

    return 0;
}

int udp_socket_create(int family) {
    int fd;

#ifdef SOCK_NONBLOCK
    fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (fd != -1) {
        return fd;
    }
    /* Fall through if SOCK_NONBLOCK not supported at runtime */
#endif

    fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        return -1;
    }

    if (udp_socket_set_nonblock(fd) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int udp_socket_bind(int fd, const struct udp_addr *addr) {
    return bind(fd, udp_addr_sa_const(addr), udp_addr_size(addr));
}

int udp_socket_connect(int fd, const struct udp_addr *addr) {
    return connect(fd, udp_addr_sa_const(addr), udp_addr_size(addr));
}

void udp_socket_close(int fd) {
    close(fd);
}

int udp_socket_enable_ecn(int fd, int family) {
    unsigned int val = 1;
    switch (family) {
    case AF_INET:
        return setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &val, sizeof(val));
    case AF_INET6:
        return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &val,
                          sizeof(val));
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
}

int udp_socket_enable_pktinfo(int fd, int family) {
    int val = 1;
    switch (family) {
    case AF_INET:
        return setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));
    case AF_INET6:
        return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
                          sizeof(val));
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
}

int udp_socket_set_pmtu_discover(int fd, int family) {
#if defined(IP_MTU_DISCOVER) && defined(IPV6_MTU_DISCOVER)
    int val;
    switch (family) {
    case AF_INET:
        val = IP_PMTUDISC_PROBE;
        return setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    case AF_INET6:
        val = IPV6_PMTUDISC_PROBE;
        return setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val,
                          sizeof(val));
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
#else
    (void)fd;
    (void)family;
    return 0;
#endif
}

int udp_socket_set_dontfrag(int fd, int family) {
#if defined(IP_DONTFRAG) && defined(IPV6_DONTFRAG)
    int val = 1;
    switch (family) {
    case AF_INET:
        return setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val));
    case AF_INET6:
        return setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &val, sizeof(val));
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
#else
    (void)fd;
    (void)family;
    return 0;
#endif
}

int udp_socket_enable_gro(int fd) {
#ifdef UDP_GRO
    int val = 1;
    return setsockopt(fd, IPPROTO_UDP, UDP_GRO, &val, sizeof(val));
#else
    (void)fd;
    return 0;
#endif
}

int udp_socket_set_reuseaddr(int fd) {
    int val = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
}

static int apply_flags(int fd, int family, unsigned int flags) {
    if ((flags & UDP_FLAG_ECN) && udp_socket_enable_ecn(fd, family) != 0) {
        return -1;
    }
    if ((flags & UDP_FLAG_PKTINFO) &&
        udp_socket_enable_pktinfo(fd, family) != 0) {
        return -1;
    }
    if ((flags & UDP_FLAG_PMTU) &&
        udp_socket_set_pmtu_discover(fd, family) != 0) {
        return -1;
    }
    if ((flags & UDP_FLAG_DONTFRAG) &&
        udp_socket_set_dontfrag(fd, family) != 0) {
        return -1;
    }
    if ((flags & UDP_FLAG_GRO) && udp_socket_enable_gro(fd) != 0) {
        return -1;
    }
    return 0;
}

int udp_server_socket(const struct udp_addr *bind_addr, unsigned int flags) {
    int family = udp_addr_family(bind_addr);
    int fd = udp_socket_create(family);
    if (fd < 0) {
        return -1;
    }

    if (udp_socket_set_reuseaddr(fd) != 0) {
        goto fail;
    }

    if (family == AF_INET6) {
        int val = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) !=
            0) {
            goto fail;
        }
    }

    if (apply_flags(fd, family, flags) != 0) {
        goto fail;
    }

    if (udp_socket_bind(fd, bind_addr) != 0) {
        goto fail;
    }

    return fd;

fail:
    close(fd);
    return -1;
}

int udp_client_socket(const struct udp_addr *remote_addr, unsigned int flags) {
    int family = udp_addr_family(remote_addr);
    int fd = udp_socket_create(family);
    if (fd < 0) {
        return -1;
    }

    if (apply_flags(fd, family, flags) != 0) {
        goto fail;
    }

    if (udp_socket_connect(fd, remote_addr) != 0) {
        goto fail;
    }

    return fd;

fail:
    close(fd);
    return -1;
}
