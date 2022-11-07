/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022 Alexander Graf
 */

/*
 * This application provides a Virtualization.Framework compatible UNIX
 * domain socket that is backed by slirp.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "libslirp.h"

/* Maximum number of open connections */
#define FDS_MAX 10240

static const bool debug = false;
static const bool enable_ipv6 = false;

static Slirp *slirp;
static uint8_t input_buf[10240];
static struct pollfd fds[FDS_MAX];
static int cur_poll;
static int unix_fd;
static struct sockaddr_un client_addr;
static socklen_t client_len = sizeof(client_addr);

struct hostfwd {
    uint32_t host_port;
    uint32_t guest_port;
};

#define HOSTFWD_MAX 64

/* Print a frame for debugging */
static void print_frame(const uint8_t *data, size_t len) {
    size_t i;

    printf("got packet size %zd:\n", len);
    for (i = 0; i < len; i++) {
        if (i && i % 16 == 0)
            printf("\n");
        printf("%s%02x", i % 16 ? " " : "", data[i]);
    }
    if (len % 16 != 0)
        printf("\n");
    printf("\n");
}

/* This is called when receiving a packet from the virtual network, for the
 * guest */
static ssize_t send_packet(const void *buf, size_t len, void *opaque) {
    ssize_t r;

    if (debug) {
        printf("Slirp -> UNIX: ");
        print_frame(buf, len);
    }
    r = sendto(unix_fd, buf, len, 0, (struct sockaddr *)&client_addr, client_len);
    if (r < 0) {
        if (errno == ENOBUFS) {
            /* Our buffer is just full, need to apply some back pressure. Drop the packet. */
            return 0;
        }
        printf("WARN: Send returned '%s'\n", strerror(errno));
    }

    return r;
}

static void guest_error(const char *msg, void *opaque) {
    printf("guest error %s\n",  msg);
}

static int64_t clock_get_ns(void *opaque) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
}

static void *timer_new_opaque(SlirpTimerId id, void *cb_opaque, void *opaque) {
    /* Not implemented for now */
    fprintf(stderr, "WARNING: Slirp tries to create a timer\n");
    return NULL;
}

static void timer_free(void *_timer, void *opaque) {
    /* Not implemented for now */
}

static void timer_mod(void *_timer, int64_t expire_time, void *opaque) {
    /* Not implemented for now */
}

/*
 * Dumb polling implementation
 */
static void register_poll_fd(int fd, void *opaque) {
}

static void unregister_poll_fd(int fd, void *opaque) {
}

static void notify(void *opaque) {
    /* No need for this in single-thread case */
}

/* poll() variant */
static int add_poll_cb(int fd, int events, void *opaque)
{
    short poll_events = 0;

    if (cur_poll >= FDS_MAX) {
        fprintf(stderr, "ERROR: cur_poll(%d) > MAX_FDS(%d)\n", cur_poll, FDS_MAX);
        return 0;
    }
    fds[cur_poll].fd = fd;

    if (events & SLIRP_POLL_IN)
        poll_events |= POLLIN;
    if (events & SLIRP_POLL_OUT)
        poll_events |= POLLOUT;
    if (events & SLIRP_POLL_PRI)
        poll_events |= POLLPRI;
    if (events & SLIRP_POLL_ERR)
        poll_events |= POLLERR;
    if (events & SLIRP_POLL_HUP)
        poll_events |= POLLHUP;
    fds[cur_poll].events = poll_events;

    return cur_poll++;
}

static int get_revents_cb(int idx, void *opaque)
{
    int r = 0;
    uint32_t revents;

    assert(idx < FDS_MAX);

    revents = fds[idx].revents;
    if (revents & POLLIN)
        r |= SLIRP_POLL_IN;
    if (revents & POLLOUT)
        r |= SLIRP_POLL_OUT;
    if (revents & POLLPRI)
        r |= SLIRP_POLL_PRI;
    if (revents & POLLERR)
        r |= SLIRP_POLL_ERR;
    if (revents & POLLHUP)
        r |= SLIRP_POLL_HUP;

    return r;
}

static void dopoll(void) {
    uint32_t timeout = 1000000;
    ssize_t len;
    int err;
    int unix_idx;

    cur_poll = 0;

    unix_idx = add_poll_cb(unix_fd, SLIRP_POLL_IN, NULL);
    slirp_pollfds_fill(slirp, &timeout, add_poll_cb, NULL);

    err = poll(fds, cur_poll, timeout);

    /* Slirp -> UNIX */
    slirp_pollfds_poll(slirp, err < 0, get_revents_cb, NULL);

    /* UNIX -> Slirp */
    if (fds[unix_idx].revents & POLL_IN) {
        while ((len = recvfrom(unix_fd, input_buf, sizeof(input_buf), 0, (struct sockaddr *)&client_addr, &client_len)) > 0) {
            if (debug) {
                printf("UNIX -> Slirp: ");
                print_frame(input_buf, len);
            }
            slirp_input(slirp, input_buf, len);
        }
    }
}

static struct SlirpCb callbacks = {
    .send_packet = send_packet,
    .guest_error = guest_error,
    .clock_get_ns = clock_get_ns,
    .timer_new_opaque = timer_new_opaque,
    .timer_free = timer_free,
    .timer_mod = timer_mod,
    .register_poll_fd = register_poll_fd,
    .unregister_poll_fd = unregister_poll_fd,
    .notify = notify,
};

static void usage(char **argv)
{
    fprintf(stderr, "\
Slirp UNIX socket proxy\n\
-----------------------\n\
\n\
Usage: %s [-p path] [-f host_port:guest_port]\n\
\n\
  -p path                  Define the path for the UNIX socket. Defaults to /tmp/slirp.\n\
  -f host_port:guest_port  Add port forward to a guest socket. Can be supplied multiple times.\n", argv[0]);
}

int main(int argc, char *argv[]) {
    struct in_addr any_ip = {
        .s_addr = 0,
    };
    SlirpConfig config = {
        .version = 4,
        .restricted = false,
        .in_enabled = true,
        .vnetwork.s_addr = htonl(0x0a000200),
        .vnetmask.s_addr = htonl(0xffffff00),
        .vhost.s_addr = htonl(0x0a000202),
        .vdhcp_start.s_addr = htonl(0x0a00020f),
        .vnameserver.s_addr = htonl(0x0a000203),
        .disable_host_loopback = false,
        .enable_emu = false,
        .disable_dns = false,
    };
    struct sockaddr_un addr = {
        .sun_family = AF_LOCAL,
        .sun_path = "/tmp/slirp",
    };
    struct hostfwd hostfwd[HOSTFWD_MAX] = {};
    int buflen = 4 * 1024 * 1024;
    int hostfwd_count = 0;
    int ch;
    int i;

    while ((ch = getopt(argc, argv, "p:f:")) != -1) {
        switch (ch) {
        case 'p':
            strncpy(addr.sun_path, optarg, sizeof(addr.sun_path) - 1);
            break;
        case 'f':
            if (sscanf(optarg, "%d:%d",
                       &hostfwd[hostfwd_count].host_port,
                       &hostfwd[hostfwd_count].guest_port) != 2) {
                usage(argv);
                exit(1);
            }
            hostfwd_count++;
            break;
        case 'h':
        case '?':
        default:
            usage(argv);
            exit(1);
        }
    }

    if (optind != argc) {
        usage(argv);
        exit(1);
    }

    /* Remove any stale file at the desired path */
    unlink(addr.sun_path);

    /* Set up slirp */
    printf("Slirp version %s\n", slirp_version_string());
    printf("UNIX socket: %s\n", addr.sun_path);

    inet_pton(AF_INET6, "fec0::", &config.vprefix_addr6);
    config.vprefix_len = 64;
    config.vhost6 = config.vprefix_addr6;
    config.vhost6.s6_addr[15] = 2;
    config.vnameserver6 = config.vprefix_addr6;
    config.vnameserver6.s6_addr[15] = 2;
    config.in6_enabled = enable_ipv6,

    slirp = slirp_new(&config, &callbacks, NULL);
    if (!slirp) {
        fprintf(stderr, "ERROR: Could not spawn slirp environment\n");
        exit(1);
    }

    for (i = 0; i < hostfwd_count; i++) {
        struct hostfwd *fwd = &hostfwd[i];
        assert(!slirp_add_hostfwd(slirp, false, any_ip, fwd->host_port, any_ip, fwd->guest_port));
        printf("Port forward host:%d -> guest:%d\n", fwd->host_port, fwd->guest_port);
    }

    /* Bind to the UNIX socket at path defined in -p */
    unix_fd = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (unix_fd < 0) {
        fprintf(stderr, "ERROR: Could not create socket: %s\n", strerror(errno));
        exit(1);
    }

    setsockopt(unix_fd, SOL_SOCKET, SO_RCVBUF, &buflen, sizeof(buflen));
    setsockopt(unix_fd, SOL_SOCKET, SO_SNDBUF, &buflen, sizeof(buflen));

    if (bind(unix_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ERROR: Could not bind socket: %s\n", strerror(errno));
        exit(1);
    }

    /* and make it non blocking so we can drop packets if needed */
    fcntl(unix_fd, F_SETFL, fcntl(unix_fd, F_GETFL, NULL) | O_NONBLOCK);

    /* Process packets */
    while (1) {
        dopoll();
    }

    slirp_cleanup(slirp);
}

