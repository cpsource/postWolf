/*
 * libudp echo client example
 *
 * Usage: echo_client [host [port [message]]]
 *
 * Sends a message to the echo server and prints the reply.
 */
#include <udp/udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "::1";
    const char *port = argc > 2 ? argv[2] : "9999";
    const char *message = argc > 3 ? argv[3] : "hello from libudp!";
    struct udp_addr remote;
    int fd;
    uint8_t buf[65536];
    char addr_str[128];

    udp_addr_init(&remote);
    if (udp_addr_resolve(&remote, host, port, AF_UNSPEC) != 0) {
        fprintf(stderr, "Failed to resolve %s:%s\n", host, port);
        return 1;
    }

    fd = udp_client_socket(&remote, UDP_FLAG_ECN);
    if (fd < 0) {
        perror("udp_client_socket");
        return 1;
    }

    if (udp_addr_format(&remote, addr_str, sizeof(addr_str)) == 0) {
        printf("Sending to %s: \"%s\"\n", addr_str, message);
    }

    ssize_t sent = udp_send_simple(fd, message, strlen(message));
    if (sent < 0) {
        perror("udp_send_simple");
        udp_socket_close(fd);
        return 1;
    }
    printf("Sent %zd bytes\n", sent);

    /* Wait for reply with timeout */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    int nfds = poll(&pfd, 1, 3000);
    if (nfds <= 0) {
        fprintf(stderr, "No reply received (timeout)\n");
        udp_socket_close(fd);
        return 1;
    }

    struct udp_msg_info mi;
    ssize_t n = udp_recv(fd, buf, sizeof(buf) - 1, udp_addr_family(&remote),
                         &mi);
    if (n < 0) {
        perror("udp_recv");
        udp_socket_close(fd);
        return 1;
    }

    buf[n] = '\0';
    printf("Reply (%zd bytes, ecn=%u): %s\n", n, mi.ecn, buf);

    udp_socket_close(fd);
    return 0;
}
