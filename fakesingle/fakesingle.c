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
    int program_count = 0;
    char **programs;
    if (argc == 1 || getenv("FORCE_CB_ENV") != NULL) {
        // Try to get the names from CB_1, CB_2, etc.
        programs = malloc(50*sizeof(char*));
        for (int i = 1; i <= 50; i++)
            programs[i-1] = NULL;
        for (int i = 1; i <= 50; i++) {
            char varname[10];
            snprintf(varname, sizeof(varname), "CB_%d", i);
            char *val = getenv(varname);
            if (val != NULL) {
                programs[i-1] = val;
                program_count++;
                DBG_PRINT("Using CB_%d = %s\n", i, val);
            } else break;
        }
        if (program_count == 0) {
            fprintf(stderr, "Usage: %s cb1 [cb2] [...]\n       CB_1=cb1 [CB_2=cb2] [...up to 50] [FORCE_CB_ENV=1] %s\n", argv[0], argv[0]);
            exit(1);
        }
    } else {
        program_count = argc - 1;
        programs = argv + 1;
    }

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

