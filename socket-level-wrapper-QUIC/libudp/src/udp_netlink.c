/*
 * libudp - Standalone UDP socket library
 * Extracted from ngtcp2 examples (https://github.com/ngtcp2/ngtcp2)
 *
 * Copyright (c) 2019 ngtcp2 contributors
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
#ifdef __linux__

#include <udp/udp_netlink.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct nlmsg {
    struct nlmsghdr hdr;
    struct rtmsg msg;
    struct rtattr dst;
    uint8_t dst_addr[sizeof(struct sockaddr_storage)];
};

static int send_netlink_msg(int fd, const struct udp_addr *remote_addr,
                            uint32_t seq) {
    struct nlmsg nlmsg;
    struct sockaddr_nl sa;
    struct iovec iov;
    struct msghdr msg;
    ssize_t nwrite;
    int family = udp_addr_family(remote_addr);

    memset(&nlmsg, 0, sizeof(nlmsg));
    nlmsg.hdr.nlmsg_type = RTM_GETROUTE;
    nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlmsg.hdr.nlmsg_seq = seq;
    nlmsg.msg.rtm_family = (unsigned char)family;
    nlmsg.msg.rtm_protocol = RTPROT_KERNEL;
    nlmsg.dst.rta_type = RTA_DST;

    switch (family) {
    case AF_INET:
        nlmsg.dst.rta_len = RTA_LENGTH(sizeof(struct in_addr));
        memcpy(RTA_DATA(&nlmsg.dst), &remote_addr->addr.sin.sin_addr,
               sizeof(struct in_addr));
        break;
    case AF_INET6:
        nlmsg.dst.rta_len = RTA_LENGTH(sizeof(struct in6_addr));
        memcpy(RTA_DATA(&nlmsg.dst), &remote_addr->addr.sin6.sin6_addr,
               sizeof(struct in6_addr));
        break;
    default:
        return -1;
    }

    nlmsg.hdr.nlmsg_len =
        NLMSG_LENGTH(sizeof(nlmsg.msg) + nlmsg.dst.rta_len);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    iov.iov_base = &nlmsg;
    iov.iov_len = nlmsg.hdr.nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    do {
        nwrite = sendmsg(fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    return nwrite == -1 ? -1 : 0;
}

static int recv_netlink_msg(int fd, uint32_t seq,
                            struct udp_inaddr *local_addr) {
    uint8_t buf[8192];
    struct iovec iov;
    struct sockaddr_nl sa;
    struct msghdr msg;
    ssize_t nread;
    struct nlmsghdr *hdr;
    int found = 0;

    memset(&sa, 0, sizeof(sa));

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    do {
        nread = recvmsg(fd, &msg, 0);
    } while (nread == -1 && errno == EINTR);

    if (nread == -1) {
        return -1;
    }

    for (hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, nread);
         hdr = NLMSG_NEXT(hdr, nread)) {
        struct rtattr *rta;
        int attrlen;
        struct rtmsg *rtm;

        if (seq != hdr->nlmsg_seq) {
            return -1;
        }
        if (hdr->nlmsg_flags & NLM_F_MULTI) {
            return -1;
        }

        switch (hdr->nlmsg_type) {
        case NLMSG_DONE:
            return -1;
        case NLMSG_NOOP:
            continue;
        case NLMSG_ERROR: {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
            if (err->error != 0) {
                return -1;
            }
            continue;
        }
        }

        rtm = (struct rtmsg *)NLMSG_DATA(hdr);
        attrlen = (int)(hdr->nlmsg_len - NLMSG_SPACE(sizeof(struct rtmsg)));

        for (rta = (struct rtattr *)((uint8_t *)NLMSG_DATA(hdr) +
                                     sizeof(struct rtmsg));
             RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
            if (rta->rta_type != RTA_PREFSRC) {
                continue;
            }

            switch (rtm->rtm_family) {
            case AF_INET:
                if (RTA_LENGTH(sizeof(struct in_addr)) != rta->rta_len) {
                    return -1;
                }
                local_addr->family = AF_INET;
                memcpy(&local_addr->addr.v4, RTA_DATA(rta),
                       sizeof(struct in_addr));
                found = 1;
                break;
            case AF_INET6:
                if (RTA_LENGTH(sizeof(struct in6_addr)) != rta->rta_len) {
                    return -1;
                }
                local_addr->family = AF_INET6;
                memcpy(&local_addr->addr.v6, RTA_DATA(rta),
                       sizeof(struct in6_addr));
                found = 1;
                break;
            default:
                return -1;
            }
            break;
        }
    }

    if (!found) {
        return -1;
    }

    /* Read the ACK */
    memset(&sa, 0, sizeof(sa));
    memset(&msg, 0, sizeof(msg));

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    do {
        nread = recvmsg(fd, &msg, 0);
    } while (nread == -1 && errno == EINTR);

    if (nread == -1) {
        return -1;
    }

    for (hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, nread);
         hdr = NLMSG_NEXT(hdr, nread)) {
        if (seq != hdr->nlmsg_seq) {
            return -1;
        }
        if (hdr->nlmsg_flags & NLM_F_MULTI) {
            return -1;
        }

        switch (hdr->nlmsg_type) {
        case NLMSG_DONE:
            return -1;
        case NLMSG_NOOP:
            continue;
        case NLMSG_ERROR: {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
            if (err->error != 0) {
                return -1;
            }
            break;
        }
        }
    }

    return 0;
}

int udp_get_preferred_source(const struct udp_addr *remote_addr,
                             struct udp_inaddr *local_addr) {
    struct sockaddr_nl sa;
    int fd;
    uint32_t seq = 1;
    int rv;

    udp_inaddr_init(local_addr);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd == -1) {
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        goto fail;
    }

    if (send_netlink_msg(fd, remote_addr, seq) != 0) {
        goto fail;
    }

    rv = recv_netlink_msg(fd, seq, local_addr);
    close(fd);
    return rv;

fail:
    close(fd);
    return -1;
}

#endif /* __linux__ */
