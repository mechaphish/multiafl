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


// From AFL's config.h
#define FORKSRV_FD 198

// My own utils, like the always-on fancy assert()
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define VAL_TO_STR_intern(x) #x
#define VAL_TO_STR(x) VAL_TO_STR_intern(x)
#define V(x) if (unlikely(!(x)))   errx(-9, __FILE__ ":" VAL_TO_STR(__LINE__) " %s, it's not %s", __PRETTY_FUNCTION__, #x)
#define VE(x) if (unlikely(!(x))) err(-9, __FILE__ ":" VAL_TO_STR(__LINE__) " %s, it's not %s", __PRETTY_FUNCTION__, #x)

#ifdef DEBUG
# define DBG_PRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
# define DBG_PRINTF(...) do { ; } while(0)
#endif

static void sigchld_from_forksrv(int sig, siginfo_t *info, void *ctx)
{
    // Note: these are from the QEMU _forkservers_, not the CBs (or even the CB QEMUs)!
    //       So I treat them as a fatal failure of the entire thing
    //       (restart the entire thing if desired.)
    assert(sig == SIGCHLD);
    fprintf(stderr, "QEMU forkserver died (pid %d), killing the entire process group.\n", info->si_pid);
    fprintf(stderr, "   %s %d\n", (info->si_code == CLD_EXITED) ? "exit()ed with status" : (info->si_code == CLD_KILLED) ? "killed by signal" : "UNEXPECTED si_code! si_status =", info->si_status);
    (void) ctx;

    // Prevent zombies
    int dummy;
    waitpid(info->si_pid, &dummy, 0);
    signal(SIGCHLD, SIG_IGN); 

    VE(killpg(0, SIGKILL) == 0);
}


int main(int argc, char **argv)
{
    ///////////////////////////////////////////////////////////////////////////////////////////////
    //
    // 0. Find the CBs.
    //
    //    Borrowing from fakesingle
    //    TODO: keep in sync
    //
#ifdef HARDCODED_CBS
    const char *hardcoded_cbs[] = { HARDCODED_CBS };
    argc = sizeof(hardcoded_cbs)/sizeof(const char*);
    argv = malloc((1+argc)*sizeof(char*));
    for (i = 0; i < argc; i++)
        argv[i] = strdup(hardcoded_cbs[i]);
    argv[argc] = NULL; /* Just to be safe */
    DBG_PRINTF("Using %d HARDCODED_CBS:\n", argc);
    for (i = 0; i < argc; i++)
        DBG_PRINTF("  Hardcoded CB %d: %s\n", i+1, argv[i]);
#else
    char *cbs_from_env[50];
    int cbs_from_env_count = 0;
    if (argc == 1 || getenv("FORCE_CB_ENV") != NULL) {
        // Try to get the names from CB_1, CB_2, etc.
        // Turns them into argc/argv, same as getting them as arguments
        for (int i = 1; i <= 50; i++) {
            char varname[10];
            snprintf(varname, sizeof(varname), "CB_%d", i);
            char *val = getenv(varname);
            if (val != NULL) {
                cbs_from_env[i-1] = val;
                cbs_from_env_count++;
                DBG_PRINTF("Taking CB_%d='%s'\n", i, val);
            } else break;
        }
        if (cbs_from_env_count > 0) {
            argc = cbs_from_env_count;
            argv = cbs_from_env;
            argv[argc] = NULL;
        } else {
            fprintf(stderr, "Usage: %s cb1 [cb2] [...]\n       CB_1=cb1 [CB_2=cb2] [...up to 50] [FORCE_CB_ENV=1] %s\n", argv[0], argv[0]);
            exit(1);
        }
    } else {
        argc -= 1;
        argv += 1;
    }
#endif

    const int program_count = argc;
    char **programs = argv;
    V(program_count <= FD_SETSIZE);


    ///////////////////////////////////////////////////////////////////////////////////////////////
    //
    // 1. Global initial setup (QEMU forkservers, like afl does)
    //  
     
    // First of all, set up everything so we can propagate process deaths
    setsid();                   // This process, the QEMU forkservers, and the CB-running QEMUs are in a single process group
    signal(SIGUSR2, SIG_IGN);   // SIGUSR2 on the group is used to kill all current CBs (but not us or the forkservers)
    struct sigaction act;       // Instead, deaths of forkservers are a problem and must be propagated to the full group
    memset(&act, 0, sizeof(act));
    act.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;
    act.sa_sigaction = sigchld_from_forksrv;
    VE(sigaction(SIGCHLD, &act, NULL) == 0);


    const int CTL_FD = FORKSRV_FD; // The "forkserver protocol" is spoken over these (fixed) int fds
    const int ST_FD = FORKSRV_FD + 1;
    const int FDPASSER_FD = FORKSRV_FD - 2; // -1 is TSL_FD (QEMU translations)
    uint32_t msg;

    // QEMU status "globals"
    int qemuforksrv_ctl_fd[program_count];   // QEMU forksever communication pipes
    int qemuforksrv_st_fd[program_count];
    int qemuforksrv_fdpasser[program_count]; // UNIX socket to the QEMU forkserver (used to pass CB socketpair file descriptors)
    pid_t qemucb_pid[program_count];         // fork()ed QEMUs running CBs

    char program_i_str[10], program_count_str[10]; // Arguments for the custom QEMU
    snprintf(program_count_str, 10, "%d", program_count);

    for (int i = 0; i < program_count; i++) {
        // Adapted from init_forkserver (afl-fuzz.c)
        int st_pipe[2], ctl_pipe[2];
        if (pipe(st_pipe) || pipe(ctl_pipe))
            err(-90, "pipe() failed");

        int fdpassers[2];
        VE(socketpair(AF_UNIX, SOCK_DGRAM, 0, fdpassers) == 0);

        pid_t pid = fork();
        if (pid == -1)
            err(-80, "Could not fork for QEMU forkserver %d", i);

        if (pid == 0) {
            VE(dup2(ctl_pipe[0], CTL_FD) != -1); // QEMU reads from our control pipe
            VE(dup2(st_pipe[1], ST_FD) != -1);   // QEMU writes to our status pipe
            VE(dup2(fdpassers[0], FDPASSER_FD) != -1);  // Notionally, QEMU "reads" (recvmsg)
            close(ctl_pipe[0]); close(ctl_pipe[1]);
            close(st_pipe[0]); close(st_pipe[1]);
            close(fdpassers[0]); close(fdpassers[1]);

            if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);
            
            // Note: SIGUSR2 remains ignored, the QEMU forkservers must also be immune to it
            snprintf(program_i_str, 10, "%d", i);
            execl(__STRING(AFL_QEMU_PATH), "multicb-qemu",
                    "--multicb_i", program_i_str, "--multicb_tot", program_count_str,
                    programs[i], (char *) NULL);
            err(-2, "Could not exec qemu (forkserver) %s", __STRING(AFL_QEMU_PATH));
        } else {
            close(ctl_pipe[0]); close(st_pipe[1]); close(fdpassers[0]);
            qemuforksrv_ctl_fd[i] = ctl_pipe[1];
            qemuforksrv_st_fd[i] = st_pipe[0];
            qemuforksrv_fdpasser[i] = fdpassers[1];

            DBG_PRINTF("Waiting for QEMU forkserver %d to tell us that it's ready... ", i);
            if (read(qemuforksrv_st_fd[i], &msg, 4) != 4)
                err(-20, "Could not read back from QEMU forkserver %d status pipe, something went wrong", i);
            V(msg == 0xC6CAF1F5); // Just as a sanity check
            DBG_PRINTF("OK :)\n");
        }
    }

    // Now that all QEMU's told us they are ready, we can do the same with AFL :)
    DBG_PRINTF("All QEMUs up, giving AFL the OK to proceed\n");
    VE(write(ST_FD, &msg, 4) == 4);


    ///////////////////////////////////////////////////////////////////////////////////////////////
    //
    // 2. React to fork requests, and report back the (aggregate) status.
    //

    while (1) {
        VE(read(CTL_FD, &msg, 4) == 4);
        DBG_PRINTF("Forking up!\n");

        // Rough equivalent of the setup_sockpairs (service-launcher / fakesingle)
        int cbsockets[2*program_count];
        for (int i = 0; i < program_count; i++)
            VE(socketpair(AF_UNIX, SOCK_STREAM, 0, &cbsockets[i*2]) == 0);

        // Pass them to the QEMU forkservers (man cmsg)
        struct cmsghdr* cmsg = (struct cmsghdr*) malloc(CMSG_SPACE(sizeof(cbsockets)));
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_len = CMSG_LEN(sizeof(cbsockets));
        memcpy(CMSG_DATA(cmsg), cbsockets, sizeof(cbsockets));
        struct msghdr msghdr = {0};
        msghdr.msg_control = cmsg;
        msghdr.msg_controllen = cmsg->cmsg_len;
        for (int i = 0; i < program_count; i++)
            VE(sendmsg(qemuforksrv_fdpasser[i], &msghdr, 0) != -1);

        DBG_PRINTF("Waiting for QEMU forkservers fork() pid reports...\n");
        for (int i = 0; i < program_count; i++) {
            VE(read(qemuforksrv_ctl_fd[i], &qemucb_pid[i], 4) == 4);
            DBG_PRINTF("QEMU for CB_%d: pid %d...\n", i, qemucb_pid[i]);
        }

        for (int i = 0; i < program_count; i++)
            close(cbsockets[i]);

        // AFL can now proceed
        // Note: it can kill() the pid we return, thinking it's the running program (timeouts, stop, etc.).
        //       As a workaround, I return the first qemucb pid, and will take care of "propagating" the kill on forkserver return
        DBG_PRINTF("AFL GO!\n");
        VE(write(ST_FD, &qemucb_pid[0], 4) == 4);

        // Wait for the process exit reports
        fd_set s; FD_ZERO(&s);
        int maxfd = 0;
        for (int i = 0; i < program_count; i++) {
            FD_SET(qemuforksrv_st_fd[i], &s);
            maxfd = (maxfd < qemuforksrv_st_fd[i]) ? qemuforksrv_st_fd[i] : maxfd;
        }

        int alive_cbs = program_count, died_cb_i = -1, died_cb_status, aggregate_status = -1;
        while (alive_cbs > 0) {
            VE(select(maxfd+1, &s, NULL, NULL, NULL) > 0);
            for (int i = 0; i < program_count; i++)
                if (FD_ISSET(qemuforksrv_st_fd[i], &s))
                    died_cb_i = i;
            assert(died_cb_i != -1);
            qemucb_pid[died_cb_i] = 0;
            alive_cbs--;
            VE(read(qemuforksrv_st_fd[died_cb_i], &died_cb_status, 4) == 4); 
            if (WIFEXITED(died_cb_status)) {
                // Regular _terminate().
                // No need to propagate, and use as global status only if no signals.
                DBG_PRINTF("Regular exit for CB_%d (ret: %d)\n", died_cb_i, WEXITSTATUS(died_cb_status));
                if (aggregate_status == -1)
                    aggregate_status = died_cb_status;
                continue;
            }
            // Terminated by a signal.
            // Kill all others, return as status.
            // TODO: Prioritize SIGSEGV/SIGILL/SIGBUS over the others?
            V(WIFSIGNALED(died_cb_status));
            if (WTERMSIG(died_cb_status) == SIGKILL) {
                DBG_PRINTF("CB_%d SIGKILLed! (probably by AFL)\n", died_cb_i);
            } else if (WTERMSIG(died_cb_status) == SIGUSR2) {
                DBG_PRINTF("CB_%d killed via SIGUSR2 (probably by us, sending this all around)\n", died_cb_i);
            } else DBG_PRINTF("CB_%d terminated by signal %d!\n", died_cb_i, WTERMSIG(died_cb_status));
            if ((aggregate_status == -1) || WIFEXITED(aggregate_status)) {
                aggregate_status = died_cb_status;
                DBG_PRINTF("Kill all other CBs with SIGUSR2\n");
                killpg(0, SIGUSR2);
            }
            // Note: still waits for all the others to report their exits
        }
        assert(aggregate_status != -1);
        for (int i = 0; i < program_count; i++)
            assert(qemucb_pid[i] == 0);

        // All QEMUs done. Report the aggregate status to AFL and wait for a new fork command.
        DBG_PRINTF("All QEMUs done, reporting status %#x to AFL\n", aggregate_status);
        VE(write(ST_FD, &aggregate_status, 4) == 4);
    }
}
