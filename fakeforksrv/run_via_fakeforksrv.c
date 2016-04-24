/* Kind of a "fake afl-showmap". Same invocation as fakeforksrv. */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <assert.h>
#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


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


// Shared bitmap handling adapted from afl-showmap.c

static uint8_t *trace_bits; // Actual bitmap

#include <sys/ipc.h>
#include <sys/shm.h>
static int shm_id;
static void remove_shm() { shmctl(shm_id, IPC_RMID, NULL); }
static void setup_shm()
{
    VE((shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600)) != -1);
    atexit(remove_shm);
    char shm_str[100];
    V(snprintf(shm_str, 100, "%d", shm_id) < 100);
    V(getenv(SHM_ENV_VAR) == NULL);
    setenv(SHM_ENV_VAR, shm_str, 1);
    VE((trace_bits = shmat(shm_id, NULL, 0)) != ((void*) -1));
}


int main(int argc, char **argv)
{
    const int CTL_FD = FORKSRV_FD; // The "forkserver protocol" is spoken over these (fixed) int fds
    const int ST_FD = FORKSRV_FD + 1;
    int ctl, st; // Local fds to fakeforksrv
    uint32_t msg;

    // 1. Initial setup /////////////////////////////////////////////////////////////

    setup_shm();

    // Rest adapted from init_forkserver (afl-fuzz.c)
    int st_pipe[2], ctl_pipe[2];
    if (pipe(st_pipe) || pipe(ctl_pipe))
        err(-90, "pipe() failed");

    pid_t pid = fork();
    if (pid == -1)
        err(-80, "Could not fork for fakeforksrv");

    if (pid == 0) {
        VE(dup2(ctl_pipe[0], CTL_FD) != -1);
        VE(dup2(st_pipe[1], ST_FD) != -1);
        close(ctl_pipe[0]); close(ctl_pipe[1]);
        close(st_pipe[0]); close(st_pipe[1]);

        argv[0] = "fakeforksrv";
        argv[argc] = NULL;
        execv("./fakeforksrv", argv);
        err(-2, "Could not exec ./fakeforksrv");
    } else {
        close(ctl_pipe[0]); close(st_pipe[1]);
        ctl = ctl_pipe[1];
        st = st_pipe[0];

        DBG_PRINTF("Waiting for fakeforksrv to tell us that it's ready...\n");
        if (read(st, &msg, 4) != 4)
            err(-20, "Could not read back from the status pipe, something went wrong");
        V(msg == 0xC6CAF1F5); // Just as a sanity check
        DBG_PRINTF("OK, fakeforksrv ready :)\n");
    }


    // 2. Turn connections / stdin into a fork request //////////////////////////////
    int signaled_count = 0;
    {
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
    }

    // 3. Clean up, output
    signal(SIGTERM, SIG_IGN);
    killpg(0, SIGTERM);
    signal(SIGTERM, SIG_DFL);

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

    fprintf(stderr, "Total signaled: %d\n", signaled_count);
    return (signaled_count > 0) ? -1 : 0;
}
