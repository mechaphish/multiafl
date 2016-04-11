/* Modeled after service-launcher. */

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <unistd.h>

#include "sockets.h"
#include "utils.h"


static int num_children;


static void self_destruct(int sig)
{
    DBG_PRINT("*** Killing all others...\n");

    /* Prevent zombies */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP | SA_NOCLDWAIT;
    VERIFY(sigaction, SIGCHLD, &sa, NULL);

    /* Terminate all remaining children.
     * TODO: Should keep pids and SIGKILL? PTRACE_O_EXITKILL? */
    signal(SIGHUP, SIG_IGN);
    killpg(0, SIGHUP);

    /* Reproduce the signal on myself, so AFL gets it */
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_RESTART;
    VERIFY(sigaction, sig, &sa, NULL);

    DBG_PRINT("*** Re-raising signal %d on myself...\n", sig);
    VERIFY(raise, sig);
}

static void sigchld(int sig, siginfo_t *info, void *_context)
{
    DBG_PRINT("--- Got SIGCHLD for pid %d, si_code %d, si_status %d\n", info->si_pid, info->si_code, info->si_status);
    VERIFY(waitpid, info->si_pid, NULL, 0);

    if (info->si_code == CLD_EXITED) {
        /* Benign exit. Just wait for the others to exit too. */
        DBG_PRINT("    Regular exit with code %d\n", info->si_status);
        num_children--;
        if (num_children == 0) {
            DBG_PRINT(":)  All exited normally, terminating.\n");
            exit(0); /* All CBs exited normally */
        } else return;
    }

    if ((info->si_code != CLD_KILLED) && (info->si_code != CLD_DUMPED)) {
        fprintf(stderr, "XXX Unexpected si_code %d, ignoring\n", info->si_code);
        return;
    }

    /* CB killed by a signal.
     * Kill everything else, and re-raise the signal. */
    DBG_PRINT(":(  Killed (%s) by signal %d (%s)\n",
            (info->si_code == CLD_KILLED) ? "CLD_KILLED" : "CLD_DUMPED",
            info->si_status,
            (info->si_status == SIGSEGV) ? "SIGSEGV" : (info->si_status == SIGILL) ? "SIGILL" : (info->si_status == SIGBUS) ? "SIGBUS" : "[unusual signal!]");
    self_destruct(info->si_status);

    (void) sig, (void) _context;
}



static void start_program(char *program, int program_i)
{
    DBG_PRINT("[%d] Starting %s...\n", program_i, program);
    char *envp[] = {NULL};
#ifdef QEMU
    char *argv[] = {QEMU, program, "--cb-num", program_i, NULL};
    VERIFY(execve, QEMU, argv, envp);
#else
    char *argv[] = {program, NULL};
    (void) program_i;
    VERIFY(execve, program, argv, envp);
#endif
    __builtin_unreachable();
}

int main(int argc, char **argv)
{
#ifdef HARDCODED_CBS
    char* programs[] = {  "./bin/EAGLE_00004_1","./bin/EAGLE_00004_2","./bin/EAGLE_00004_3" };
    int program_count = sizeof(programs)/sizeof(programs[0]);
#else
    if (argc == 1) {
        fprintf(stderr, "Usage: %s cb1 [cb2] [...]\n", argv[0]);
        exit(1);
    }
    int program_count = argc - 1;
    char **programs = argv + 1;
#endif

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP | SA_SIGINFO;
    VERIFY(sigaction, SIGCHLD, &sa, NULL);

    num_children = program_count;

    /* DARPA's IPC pipes
     * Note: leaves alone 0,1,2 and the high ones (afl, for instance). */
    setup_sockpairs(program_count, STDERR_FILENO + 1); 

    //setsid();
    VERIFY(setpgrp);

    for (int i = 0; i < program_count; i++) {
        pid_t pid;
        VERIFY_ASSN(pid, fork);
        if (pid == 0)
            start_program(programs[i], i);
    }

    sigset_t mask;
    sigemptyset(&mask);
    while (1)
        sigsuspend(&mask);

    return 99;
}

