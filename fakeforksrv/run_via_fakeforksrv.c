/* Kind of a "fake afl-showmap". Same invocation as fakeforksrv. */

#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


#include "../afl/config.h"
_Static_assert(FORKSRV_FD == 198, "Altered FORKSRV_FD? fakeforksrv has it hardcoded");

// My own utils, like the always-on fancy assert()
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define VAL_TO_STR_intern(x) #x
#define VAL_TO_STR(x) VAL_TO_STR_intern(x)
#define V(x) if (unlikely(!(x)))   errx(-9, __FILE__ ":" VAL_TO_STR(__LINE__) " %s, it's not %s", __PRETTY_FUNCTION__, #x)
#define VE(x) if (unlikely(!(x))) err(-9, __FILE__ ":" VAL_TO_STR(__LINE__) " %s, it's not %s", __PRETTY_FUNCTION__, #x)

#ifdef DEBUG
# define DBG_PRINTF(...) fprintf(stderr, "RUNNER: " __VA_ARGS__)
#else
# define DBG_PRINTF(...) do { ; } while(0)
#endif

static int forksrv_pid = 0;

static volatile bool accept_more = true;
static void stop_accepting(__attribute__((unused)) int sig)
{
    fprintf(stderr, "RUNNER: will stop after this run.\n");
    accept_more = false;
}
static void stop_all(__attribute__((unused)) int sig)
{
    //fprintf(stderr, "RUNNER: got SIGTERM, will try to kill everything.\n");
    if (forksrv_pid > 0)
        killpg(-forksrv_pid, SIGTERM);
    exit(SIGTERM);
}


// Shared bitmap handling adapted from afl-showmap.c

static uint8_t *trace_bits; // Actual bitmap

#include <sys/ipc.h>
#include <sys/shm.h>
static int shm_id;
static void remove_shm() { shmctl(shm_id, IPC_RMID, NULL); }
static void setup_shm()
{
    VE((shm_id = shmget(IPC_PRIVATE, MAP_SIZE + EXTRA_SHM_SIZE, IPC_CREAT | IPC_EXCL | 0600)) != -1);
    atexit(remove_shm);
    char shm_str[100];
    V(snprintf(shm_str, 100, "%d", shm_id) < 100);
    V(getenv(SHM_ENV_VAR) == NULL);
    setenv(SHM_ENV_VAR, shm_str, 1);
    VE((trace_bits = shmat(shm_id, NULL, 0)) != ((void*) -1));
}


int main(int argc, char **argv)
{
    int port = -1, socketserver;
    if ((argc > 1) && ((strcmp(argv[1],"--port")==0) || (strcmp(argv[1],"-p")==0))) {
        if (argc < 3)
            errx(1, "Missing port number argument");
        //port = atoi(argv[2])
        errno = 0; char *endptr;
        long l = strtol(argv[2], &endptr, 10);
        if ((errno != 0) || (l < 0) || (l > 65535) || (*endptr != '\0'))
            err(1, "Error parsing --port");
        port = (int) l;
        argc -= 2;
        argv += 2;
    }
    signal(SIGPIPE, SIG_IGN); // I prefer the error return

    signal(SIGINT, stop_accepting);   // CTRL-C = stop after this one
    signal(SIGTERM, stop_all);        // SIGTERM = stop all, immediately


    const int CTL_FD = FORKSRV_FD; // The "forkserver protocol" is spoken over these (fixed) int fds
    const int ST_FD = FORKSRV_FD + 1;
    const int CONNPASSER_FD = FORKSRV_FD + 100; // Special protocol to allow for cb-test. Not for AFL.
    int ctl, st, connpasser; // Local fds to fakeforksrv
    uint32_t msg;

    // 1. Initial setup /////////////////////////////////////////////////////////////

    setup_shm();

    // Adapted from init_forkserver (afl-fuzz.c)
    // KEEP IN SYNC WITH afl-showmap
    int st_pipe[2], ctl_pipe[2];
    if (pipe(st_pipe) || pipe(ctl_pipe))
        err(-90, "pipe() failed");
    int connpasser_sockets[2];
    if (port != -1)
        VE(socketpair(AF_UNIX, SOCK_DGRAM, 0, connpasser_sockets) == 0);

    forksrv_pid = fork();
    if (forksrv_pid == -1)
        err(-80, "Could not fork for fakeforksrv");

    if (forksrv_pid == 0) {
        VE(dup2(ctl_pipe[0], CTL_FD) != -1);
        VE(dup2(st_pipe[1], ST_FD) != -1);
        close(ctl_pipe[0]); close(ctl_pipe[1]);
        close(st_pipe[0]); close(st_pipe[1]);
        if (port != -1) {
            VE(dup2(connpasser_sockets[0], CONNPASSER_FD) != -1);
            close(connpasser_sockets[0]); close(connpasser_sockets[1]);
        }

        VE(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == 0);

        argv[0] = "fakeforksrv";
        argv[argc] = NULL;

        if (getenv("AFL_PATH") == NULL) {
            /* Run from the current directory */
            /* Must also set AFL_PATH, as it's mandatory after Pizza's changes */
            char afl_path[300];
            VE(getcwd(afl_path, 280) != NULL);
            strcat(afl_path, "/../afl");
            VE(setenv("AFL_PATH", afl_path, 0 /* no overwrite */) == 0);
            execv("./fakeforksrv", argv);
            err(-2, "Could not exec ./fakeforksrv");
        } else {
            /* Run from AFL_PATH */
            char fakeforksrv_path[400];
            strcpy(fakeforksrv_path, getenv("AFL_PATH"));
            strcat(fakeforksrv_path, "/fakeforksrv");
            execv(fakeforksrv_path, argv);
            err(-2, "Could not exec $AFL_PATH/fakeforksrv (%s)", fakeforksrv_path);
        }
    } else {
        close(ctl_pipe[0]); close(st_pipe[1]);
        ctl = ctl_pipe[1];
        st = st_pipe[0];
        if (port != -1) {
            close(connpasser_sockets[0]);
            connpasser = connpasser_sockets[1];
        }

        DBG_PRINTF("Waiting for fakeforksrv to tell us that it's ready...\n");
        if (read(st, &msg, 4) != 4)
            err(-20, "Could not read back from the status pipe, something went wrong");
        V(msg == 0xC6CAF1F5); // Just as a sanity check
        DBG_PRINTF("OK, fakeforksrv ready :)\n");
    }


    // Start listening, if requested. Note that this is _after_ fork(),
    // so that the socket is not visible to the forkservers (or the CBs)
    if (port != -1) {
        // Adapted from service-launcher's socket_bind
        socketserver = socket(AF_INET, SOCK_STREAM, 0);

        // Same options. Note the 5 seconds linger on close()
        int opt = 1;
        struct linger so_linger = { .l_onoff=1, .l_linger=5 };
        VE(setsockopt(socketserver, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != -1);
        VE(setsockopt(socketserver, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) != -1);
        VE(setsockopt(socketserver, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)) != -1);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        VE(bind(socketserver, (struct sockaddr *)&addr, sizeof(addr)) != -1);
        VE(listen(socketserver, SOMAXCONN) != -1);
        DBG_PRINTF("Listening on port %d\n", port);
    }


    // 2. Turn connections / stdin into a fork request //////////////////////////////
    // Similar to cb-server, but handles only one connection at a time
    int signaled_count = 0;
    while (accept_more) {
        int connection;
        if (port != -1) {
            VE((connection = accept(socketserver, NULL, 0)) != -1);

            // Special protocol to relay the connection fd
            // Similar to how I relay the socketpairs
            struct cmsghdr* cmsg = (struct cmsghdr*) malloc(CMSG_SPACE(sizeof(int)));
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cmsg), &connection, sizeof(int));
            struct msghdr msghdr = {0};
            msghdr.msg_control = cmsg;
            msghdr.msg_controllen = cmsg->cmsg_len;
            VE(sendmsg(connpasser, &msghdr, 0) != -1);
            // TODO: Close the connection now?

            DBG_PRINTF("Accepted and relayed TCP connection\n");
            msg = 0xC6CF550C; // CGC FS SOCket
        } else msg = 0;

        VE(write(ctl, &msg, 4) == 4);

        DBG_PRINTF("Waiting for the fork() pid report...\n");
        pid_t child_pid;
        VE(read(st, &child_pid, 4) == 4);
        DBG_PRINTF("fakeforksrv reports (QEMU CB_0) pid %d...\n", child_pid);

        DBG_PRINTF("Waiting for the status report...\n");
        int status;
        if (read(st, &status, 4) != 4)
            err(-10, "Could not read the status report from fakeforksrv! errno, if not just exit");

        if (WIFEXITED(status)) {
            DBG_PRINTF("Regular exit(%d)\n", WEXITSTATUS(status));
        } else {
            signaled_count++;
            V(WIFSIGNALED(status));
            if (WTERMSIG(status) == SIGKILL) {
                DBG_PRINTF("reported a SIGKILL!\n");
            } else if (WTERMSIG(status) == SIGUSR2) {
                DBG_PRINTF("!!! ERROR: reported a SIGUSR2! (should be hidden!)\n");
            } else DBG_PRINTF("reported signal %d\n", WTERMSIG(status));
        }

        if (port == -1)
            break; // Only one round, if using actual stdin/stdout
        else close(connection);
    }

    // 3. Clean up, output
    killpg(-forksrv_pid, SIGTERM);

#ifdef WRITE_TRACE_BITS
    DBG_PRINTF("Raw trace bitmap:\n");
    for (int i = 0; i < MAP_SIZE; i++) {
        if (trace_bits[i])
            fprintf(stderr, "%06u:%u\n", i, trace_bits[i]);
    }
#endif
    int nzc = 0;
    for (int i = 0; i < MAP_SIZE; i++)
        if (trace_bits[i])
            nzc++;
    fprintf(stderr, "Count of non-zero bytes in trace bitmap: %d (%d%% map)\n", nzc, nzc*100/MAP_SIZE);

    nzc = 0;
    for (int i = 0; i < EXTRA_SHM_SIZE; i++)
        if (trace_bits[MAP_SIZE+i])
            nzc++;
    fprintf(stderr, "Count of non-zero bytes in the extra shared memory: %d\n", nzc);

    fprintf(stderr, "Total signaled: %d\n", signaled_count);
    return (signaled_count > 0) ? -1 : 0;
}
