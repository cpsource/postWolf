/*
 * libudp echo server example
 *
 * Usage: echo_server [port]
 *
 * Listens on the given UDP port (default 9999) and echoes back any
 * datagram it receives, preserving the ECN codepoint and using the
 * correct local address for the reply.
 */
#include <udp/udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>

static volatile int running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv) {
    const char *port = argc > 1 ? argv[1] : "9999";
    struct udp_addr bind_addr;
    int fd;
    uint8_t buf[65536];
    char addr_str[128];

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* Bind to IPv6 any (also accepts IPv4 on dual-stack systems) */
    udp_addr_init(&bind_addr);
    if (udp_addr_resolve(&bind_addr, "::", port, AF_INET6) != 0) {
        /* Fall back to IPv4 */
        if (udp_addr_resolve(&bind_addr, "0.0.0.0", port, AF_INET) != 0) {
            fprintf(stderr, "Failed to resolve bind address\n");
            return 1;
        }
    }

    fd = udp_server_socket(&bind_addr, UDP_FLAG_ECN | UDP_FLAG_PKTINFO);
    if (fd < 0) {
        perror("udp_server_socket");
        return 1;
    }

    printf("Echo server listening on port %s (fd=%d)\n", port, fd);

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    while (running) {
        int nfds = poll(&pfd, 1, 1000);
        if (nfds <= 0) {
            continue;
        }

        struct udp_msg_info mi;
        int family = udp_addr_family(&bind_addr);
        ssize_t n = udp_recv(fd, buf, sizeof(buf), family, &mi);

        if (n == UDP_RECV_BLOCKED || n < 0) {
            continue;
        }

        if (udp_addr_format(&mi.remote_addr, addr_str, sizeof(addr_str)) ==
            0) {
            printf("Received %zd bytes from %s (ecn=%u)\n", n, addr_str,
                   mi.ecn);
        }

        /* Echo back */
        struct udp_send_info si;
        memset(&si, 0, sizeof(si));
        si.remote_addr = &mi.remote_addr;
        si.local_addr = mi.have_local_addr ? &mi.local_addr : NULL;
        si.ecn = mi.ecn;

        ssize_t sent = udp_send(fd, buf, (size_t)n, &si);
        if (sent < 0 && sent != UDP_SEND_BLOCKED) {
            perror("udp_send");
        }
    }

    printf("\nShutting down\n");
    udp_socket_close(fd);
    return 0;
}
