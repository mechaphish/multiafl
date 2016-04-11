/* From service-launcher */

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


void close_saved_sockets(int *sockets) {
    close(sockets[0]);
    close(sockets[1]);
}

void reset_base_sockets(int *sockets) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    VERIFY(fcntl, sockets[0], F_DUPFD, STDIN_FILENO);
    VERIFY(fcntl, sockets[1], F_DUPFD, STDOUT_FILENO);
}

void setup_connection(const int connection, int program_count, int *sockets) {

    int last_fd = program_count * 2 + 3;

    VERIFY_ASSN(sockets[0], fcntl, STDIN_FILENO, F_DUPFD, last_fd);
    VERIFY_ASSN(sockets[1], fcntl, STDOUT_FILENO, F_DUPFD, last_fd + 1);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);

#ifdef DEBUG
       int dev_null = open("/dev/null", O_WRONLY);

       if (dev_null == -1)
          err(-1, "unable to open /dev/null");

        close(STDERR_FILENO);
        VERIFY(fcntl, dev_null, F_DUPFD, STDERR_FILENO);
        stderr = fdopen(STDERR_FILENO, "w");
        close(dev_null);
#endif

    VERIFY(fcntl, connection, F_DUPFD, STDIN_FILENO);
    VERIFY(fcntl, connection, F_DUPFD, STDOUT_FILENO);
}

void setup_sockpairs(const int program_count, int destination_fd) {
    int sockets[2];
    int i;

    if (program_count > 1) {
#ifdef DEBUG
        fprintf(stderr, "opening %d socket pairs\n", program_count);
#endif

        for (i = 0; i < program_count; i++) {
            close(destination_fd);
            close(destination_fd + 1);

            VERIFY(socketpair, AF_UNIX, SOCK_STREAM, 0, sockets);
#ifdef DEBUG
            fprintf(stderr, "opened %d and %d\n", sockets[0], sockets[1]);
            fprintf(stderr, "putting on on %d and %d\n", destination_fd, destination_fd + 1);
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

