#include <sys/socket.h>
#include <sys/stat.h>
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

#define FATAL(x...) do { \
    puts(x); \
    exit(1); \
  } while (0)

#define alloc_printf(_str...) ({ \
    char * _tmp; \
    int _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = malloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

#ifdef DEBUG
# define DBG_PRINTF(...) fprintf(stderr, "FAKEFORKSRV: "  __VA_ARGS__)
#else
# define DBG_PRINTF(...) do { ; } while(0)
#endif

static void sigkill_entire_group() {
    signal(SIGCHLD, SIG_IGN); // Prevent zombies
    VE(killpg(0, SIGKILL) == 0);
}
static void sigterm_entire_group() {
    signal(SIGCHLD, SIG_IGN); // Prevent zombies
    signal(SIGTERM, SIG_IGN); // Allow regular exit from myself
    VE(killpg(0, SIGTERM) == 0);
}

static void sigchld_from_forksrv(int sig, siginfo_t *info, void *ctx)
{
    // Note: these are from the QEMU _forkservers_, not the CBs (or even the CB QEMUs)!
    //       So I treat them as a fatal failure of the entire thing
    //       (restart the entire thing if desired.)
    assert(sig == SIGCHLD);
    fprintf(stderr, "!!! QEMU forkserver died (pid %d) %s %d. Killing the entire process group !!!\n", info->si_pid, (info->si_code == CLD_EXITED) ? "exit()ed with status" : (info->si_code == CLD_KILLED) ? "killed by signal" : "UNEXPECTED si_code! si_status =", info->si_status);
    (void) ctx;

    int dummy;
    waitpid(info->si_pid, &dummy, 0);

    sigkill_entire_group();
}

char *multicb_qemu_path = NULL;

int main(int argc, char *argv[])
{
    struct stat multicb_qemu_filestats;
    char *tmp = NULL;

    tmp = getenv("AFL_PATH");

    if (tmp) {
        multicb_qemu_path = alloc_printf("%s/multicb-qemu", tmp);
    } else {
        err(88, "Could not getenv(\"AFL_PATH\") = '%s'!", tmp);
    }

    if (stat(multicb_qemu_path, &multicb_qemu_filestats) != 0)
        err(88, "Could not stat multicb_qemu_path = '%s'!", multicb_qemu_path);
    V(S_ISREG(multicb_qemu_filestats.st_mode));
    V((multicb_qemu_filestats.st_mode & S_IXUSR) == S_IXUSR);

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //
    // 0. Find the CBs. Note: Counts them 0-based, differently from the sample Makefiles.
    //
    //    Borrowing from fakesingle
    //    TODO: keep them in some sync.
    //
    int program_count;
    const char **programs;

#ifdef HARDCODED_CBS
    DBG_PRINTF("Using HARDCODED_CBS\n");
    const char *hardcoded_cbs[] = { HARDCODED_CBS };
    program_count = sizeof(hardcoded_cbs)/sizeof(const char*);
    programs = hardcoded_cbs;
#else
    const char *cbs_from_env[50];
    int cbs_from_env_count = 0;
    if (argc == 1 || getenv("FORCE_CB_ENV") != NULL) {
        DBG_PRINTF("Getting CBs from env vars CB_0, CB_1, ...\n");
        for (int i = 0; i < 50; i++) {
            char varname[10];
            snprintf(varname, sizeof(varname), "CB_%d", i);
            const char *val = getenv(varname);
            if (val != NULL) {
                cbs_from_env[i] = val;
                cbs_from_env_count++;
            } else break;
        }
        if (cbs_from_env_count > 0) {
            program_count = cbs_from_env_count;
            programs = cbs_from_env;
        } else {
            fprintf(stderr, "Usage: %s cb0 [cb1] [...]\n       CB_0=cb0 [CB_1=cb1] [...up to 50] [FORCE_CB_ENV=1] %s\n", argv[0], argv[0]);
            exit(1);
        }
    } else {
        program_count = argc - 1;
        programs = (const char **) argv + 1;
    }
#endif
    DBG_PRINTF("fakeforksrv pid %d, running %d CBs:\n", getpid(), program_count);
    for (int i = 0; i < program_count; i++)
        DBG_PRINTF("   CB_%d = %s\n", i, programs[i]);

    signal(SIGPIPE, SIG_IGN); // I prefer the error return. Also, it's problematic when TCP is involved.


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

    // There's no regular exit!
    // Always kill all remaining QEMUs
    atexit(sigterm_entire_group);


    const int CTL_FD = FORKSRV_FD; // The "forkserver protocol" is spoken over these (fixed) int fds
    const int ST_FD = FORKSRV_FD + 1;
    const int FDPASSER_FD = FORKSRV_FD - 2; // -1 is TSL_FD (QEMU translations)
    const int CONNPASSER_FD = FORKSRV_FD + 100; // Special protocol for run_via_fakeforksrv (not AFL)
    uint32_t msg;
    uint32_t mypid = getpid();

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
            for (int j = 0; j < i; j++) {
                close(qemuforksrv_ctl_fd[j]);
                close(qemuforksrv_st_fd[j]);
                close(qemuforksrv_fdpasser[j]);
            }
            close(CONNPASSER_FD);

            if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

            DBG_PRINTF("Launching the QEMU forkserver for CB_%d (%s) with pid %d\n", i, programs[i], getpid());
            
            // Note: SIGUSR2 remains ignored, the QEMU forkservers must also be immune to it
            snprintf(program_i_str, 10, "%d", i);
            V(programs[i] != NULL);
            execl(
#if defined(SPAWN_IN_GDB)
                    "/usr/bin/xterm", "xterm-for-gdb", "-e", "gdb", "--args",
                    multicb_qemu_path,
#elif defined(SPAWN_IN_XTERM)
                    "/usr/bin/xterm", "xterm-for-qemu", "-e",
                    multicb_qemu_path,
#else
                    multicb_qemu_path, multicb_qemu_path,
#endif
                    "-multicb_i", program_i_str, "-multicb_count", program_count_str,
                    programs[i], NULL);
            err(-2, "Could not exec qemu (forkserver) %s", multicb_qemu_path);
        } else {
            close(ctl_pipe[0]); close(st_pipe[1]); close(fdpassers[0]);
            qemuforksrv_ctl_fd[i] = ctl_pipe[1];
            qemuforksrv_st_fd[i] = st_pipe[0];
            qemuforksrv_fdpasser[i] = fdpassers[1];

            DBG_PRINTF("Waiting for QEMU forkserver %d to tell us that it's ready...\n", i);
            if (read(qemuforksrv_st_fd[i], &msg, 4) != 4)
                err(-20, "Could not read back from QEMU forkserver %d status pipe, something went wrong", i);
            V(msg == 0xC6CAF1F5); // Just as a sanity check
            DBG_PRINTF("QEMU forkserver %d up :)\n", i);
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
        int read_from_afl = read(CTL_FD, &msg, 4);
        if (read_from_afl == 0) {
            DBG_PRINTF("Can't read(CTL_FD) = 0, interpreting this as AFL death\n");
            exit(2);
        }
        if (read_from_afl != 4)
            err(3, "read(CTL_FD) not in (0,4), something unexpected is going on");

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
        DBG_PRINTF("Relaying to the forkservers the socketpairs (controllen = %zu)...\n", msghdr.msg_controllen);
        for (int i = 0; i < program_count; i++)
            VE(sendmsg(qemuforksrv_fdpasser[i], &msghdr, 0) != -1);

        // Special protocol to allow for cb-test using run_via_fakeforksrv
        // This is not used by AFL
        int connection = -1;
        if (msg == 0xC6CF550C) { // CGC FS SOCket
            // Relay an extra cmsg with the connection (my CONNPASSER_FD -> their FDPASSER_FD)
            // The forkservers will dup it to stdin/stdout
            // This code is a rough duplicate of the socketpair one (TODO: library?)
            struct cmsghdr* cmsg = (struct cmsghdr*) malloc(CMSG_SPACE(sizeof(int)));
            struct msghdr msghdr = {0};
            msghdr.msg_control = cmsg;
            msghdr.msg_controllen = CMSG_SPACE(sizeof(int));
            VE(recvmsg(CONNPASSER_FD, &msghdr, 0) == 0);
            V(cmsg->cmsg_type == SCM_RIGHTS);
            V(msghdr.msg_controllen == CMSG_LEN(sizeof(int)));
            memcpy(&connection, CMSG_DATA(cmsg), sizeof(int));

            memset(cmsg, 0, sizeof(*cmsg));
            memset(&msghdr, 0, sizeof(msghdr));
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cmsg), &connection, sizeof(int));
            msghdr.msg_control = cmsg;
            msghdr.msg_controllen = cmsg->cmsg_len;
            DBG_PRINTF("Relaying to the QEMU forkservers the TCP connection...\n");
            for (int i = 0; i < program_count; i++)
                VE(sendmsg(qemuforksrv_fdpasser[i], &msghdr, 0) != -1);
            // TODO: can close(connection) now?
        }
        
        DBG_PRINTF("Sending fork() commands...\n");
        for (int i = 0; i < program_count; i++)
            VE(write(qemuforksrv_ctl_fd[i], &msg, 4) == 4);

        DBG_PRINTF("Waiting for QEMU forkservers fork() pid reports...\n");
        for (int i = 0; i < program_count; i++) {
            VE(read(qemuforksrv_st_fd[i], &qemucb_pid[i], 4) == 4);
            DBG_PRINTF("QEMU for CB_%d: pid %d...\n", i, qemucb_pid[i]);
        }

        for (int i = 0; i < 2*program_count; i++)
            close(cbsockets[i]);

        // AFL can now proceed
        // Note: it can kill() the pid we return, thinking it's the running program (timeouts, stop, etc.).
        //       I return my own pid, and modified AFL to also kill via SIGUSR2 to the group.
        //       Can't return a CB PID, because it may die before the others.
        DBG_PRINTF("AFL GO!\n");
        VE(write(ST_FD, &mypid, 4) == 4);

        // Wait for the process exit reports
        int alive_cbs = program_count, died_cb_i = -1, died_cb_status, aggregate_status = -1;
        while (alive_cbs > 0) {
            // died_cb_i = first one with ready status fd
            fd_set s; FD_ZERO(&s);
            int maxfd = 0;
            for (int i = 0; i < program_count; i++)
                if (qemucb_pid[i] != 0) {
                    FD_SET(qemuforksrv_st_fd[i], &s);
                    maxfd = (maxfd < qemuforksrv_st_fd[i]) ? qemuforksrv_st_fd[i] : maxfd;
                }
            assert(maxfd > 0);
            VE(select(maxfd+1, &s, NULL, NULL, NULL) > 0);
            for (int i = 0; i < program_count; i++)
                if (FD_ISSET(qemuforksrv_st_fd[i], &s))
                    died_cb_i = i;
            assert(died_cb_i != -1);
            qemucb_pid[died_cb_i] = 0;
            alive_cbs--;

            //DBG_PRINTF("According to select(), CB_%d died. Reading status...\n", died_cb_i);
            VE(read(qemuforksrv_st_fd[died_cb_i], &died_cb_status, 4) == 4); 

            // Act on the status
            if (WIFEXITED(died_cb_status)) {
                // Regular _terminate().
                // No need to propagate, and use as global status only if no signals.
                DBG_PRINTF("Regular exit for CB_%d (ret: %d)\n", died_cb_i, WEXITSTATUS(died_cb_status));
                if (WEXITSTATUS(died_cb_status) == 146) {
                    // Note: exit(146) is special, it's for the double-EOF heuristic.
                    //       Means we should wind down everything, but report still success to AFL.
                    DBG_PRINTF("DOUBLE_EOF exit heuristic on CB_%d. Killing all other CBs with SIGUSR2\n", died_cb_i);
                    killpg(0, SIGUSR2);
                }
                if (aggregate_status == -1)
                    aggregate_status = died_cb_status;
                    // TODO: preference to 146 for debugging?
                continue;
            }
            // Terminated by a signal.
            // Kill all others, return as status.
            // TODO: Prioritize SIGSEGV/SIGILL/SIGBUS over the others?
            V(WIFSIGNALED(died_cb_status));
            if (WTERMSIG(died_cb_status) == SIGUSR2) {
                DBG_PRINTF("CB_%d killed via SIGUSR2 (probably by us or AFL timer, sending this all around)\n", died_cb_i);
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

        if (connection != -1)
            close(connection);

        // All QEMUs done. Report the aggregate status to AFL and wait for a new fork command.
        DBG_PRINTF("All QEMUs done, reporting status %#x to AFL\n", aggregate_status);
        VE(write(ST_FD, &aggregate_status, 4) == 4);
    }
}
