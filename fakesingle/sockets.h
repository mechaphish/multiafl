/* From service-launcher */

#ifndef SOCKETS_H
#define SOCKETS_H

void reset_base_sockets(int *sockets);
void setup_connection(int connection, int program_count, int *sockets);
void setup_sockpairs(int program_count, int destination_fd);
void close_saved_sockets(int *);
void setup_pairwise_wait(int pause_sockets[2]);
void ready_pairwise(int pause_sockets[2]);
void wait_pairwise(int pause_sockets[2]);

#endif
