/*
* Handle TCP setup
*
* Copyright (C) 2014 - Brian Caswell <bmc@lungetech.com>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "utils.h"
#include "sockets.h"

void null_stderr() {
#ifndef DEBUG
       int dev_null = open("/dev/null", O_WRONLY);

       if (dev_null == -1)
          err(-1, "unable to open /dev/null");

        close(STDERR_FILENO);
        VERIFY(fcntl, dev_null, F_DUPFD, STDERR_FILENO);
        stderr = fdopen(STDERR_FILENO, "w");
        close(dev_null);
#endif
}

void setup_sockpairs(const int program_count, int destination_fd) {
    int sockets[2];
    int i;

    if (program_count > 1) {
#ifdef DEBUG
        printf("opening %d socket pairs\n", program_count);
#endif

        for (i = 0; i < program_count; i++) {
            close(destination_fd);
            close(destination_fd + 1);

            VERIFY(socketpair, AF_UNIX, SOCK_STREAM, 0, sockets);
#ifdef DEBUG
            printf("opened %d and %d\n", sockets[0], sockets[1]);
            printf("putting on on %d and %d\n", destination_fd, destination_fd + 1);
#endif

            if (sockets[0] != destination_fd)
                VERIFY(fcntl, sockets[0], F_DUPFD, destination_fd);

            destination_fd++;

            if (sockets[1] != destination_fd)
                VERIFY(fcntl, sockets[1], F_DUPFD, destination_fd);

            destination_fd++;
        }
    }
}


void setup_pairwise_wait(int pause_sockets[2]) {
    VERIFY(socketpair, AF_LOCAL, SOCK_STREAM, PF_UNSPEC, pause_sockets);
}

#define READY_STR '1'
void wait_pairwise(int pause_sockets[2]) {
    char c = 0;

    close(pause_sockets[0]);
    if (read(pause_sockets[1], &c, sizeof(c)) != sizeof(c) || c != READY_STR)
        errx(-1, "pause_socket: read");
    close(pause_sockets[1]);
}

void ready_pairwise(int pause_sockets[2]) {
    char c = READY_STR;

    close(pause_sockets[1]);
    if (write(pause_sockets[0], &c, sizeof(c)) != sizeof(c))
        errx(-1, "pause_socket: write");
    close(pause_sockets[0]);
}

void send_all(int fd, char *buf, const size_t size) {
    ssize_t sent = 0;
    size_t total_sent = 0;

    while (total_sent < size) {
        sent = send(fd, buf + total_sent, size - total_sent, 0);
        if (sent <= 0)
            err(-1, "send_all failed. got %zd\n", sent);

        total_sent += sent;
    }
}

size_t read_size(int fd, char *buf, const size_t size) {
    ssize_t bytes_read = 0;
    size_t total = 0;
    size_t bytes_to_read = size;

    while (bytes_to_read > 0) {
        bytes_read = read(fd, buf + total, bytes_to_read);

        if (bytes_read <= 0)
            err(-1, "unable to read %zu bytes from %d", size, fd);

        total += (size_t) bytes_read;
        bytes_to_read = size - total;
    }

    return total;
}

uint32_t read_uint32_t(int fd) {
    uint32_t value;
    size_t read;

    read = read_size(fd, (char *) &value, sizeof(value));
    if (read != sizeof(value))
        err(-1, "read uint32_t failed: Expected %u bytes, got %zu bytes", sizeof(value), read);

    return value;
}

unsigned char * read_buffer(const int fd, const size_t size) {
    unsigned char *buf;
    size_t read;

    buf = malloc(size);
    if (!buf)
        err(-1, "unable to allocate %u bytes\n", size);

    read = read_size(fd, (void *) buf, size);
    if (read != size)
        err(-1, "read buffer failed: Expected %u bytes, got %zu bytes", size, read);

    return buf;
}
