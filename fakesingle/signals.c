/*
* Setup signals
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

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <time.h>
#include <asm/unistd.h>
#include <string.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include "utils.h"
#include "signals.h"

void sigchld(const int sig);

extern unsigned long num_children;
extern int monitor_process;

int exit_val = 0;

static void print_registers(pid_t pid);

void sigchld(const int sig) {
    int status;
    pid_t pid;
    struct rusage ru;

    /* unused argument */
    (void) sig;
    int signum;

    while ((pid = wait4(-1, &status, WNOHANG, &ru)) > 0) {
        signum = 0;

        if (WIFEXITED(status)) {
            dprintf(STDERR_FILENO, "CB exited (pid: %d, exit code: %d)\n", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            signum = WTERMSIG(status);
            dprintf(STDERR_FILENO, "SIGNALED %d (pid: %d)\n", signum, pid);
        } else if (WIFSTOPPED(status)) {
            signum = WSTOPSIG(status);
            dprintf(STDERR_FILENO, "STOPPED %d (pid: %d)\n", signum, pid);
            if (signum == SIGPIPE) {
                dprintf(STDERR_FILENO, "continuing on SIGPIPE\n");
                ptrace(PT_CONTINUE, pid, (caddr_t)1, signum);
                continue;
            }
        }

        switch (signum) {
            case 0:
            case SIGUSR1:
                /* exited normally */
                break;

            case SIGALRM:
                if (monitor_process == 1)
                    dprintf(STDERR_FILENO, "CB timed out (pid: %d)\n", pid);

                if (exit_val == 0) {
                    exit_val = -signum;
                }
                break;

            case SIGSEGV:
            case SIGILL:
            case SIGBUS:
                print_registers(pid);
           
            default:
                if (monitor_process == 1)
                    dprintf(STDERR_FILENO, "CB generated signal (pid: %d, signal: %d)\n", pid, signum);

                if (exit_val == 0) {
                    exit_val = -signum;
                }

                break;
        }

        ptrace(PT_DETACH, pid, 0, 0);

        if (signum == 0)
            signum = SIGUSR1;

        kill(pid, signum);

        if (num_children)
            num_children--;
    }
}

void setup_signals(void) {
    sigset_t blocked_set;
    struct sigaction setup_action;

    sigemptyset(&blocked_set);
    sigaddset(&blocked_set, SIGCHLD);

    setup_action.sa_handler = sigchld;
    setup_action.sa_mask = blocked_set;
    setup_action.sa_flags = 0;

    VERIFY(sigaction, SIGCHLD, &setup_action, NULL);

    sigprocmask(SIG_BLOCK, &blocked_set, NULL);

    if (signal(SIGUSR1, SIG_IGN) == SIG_ERR)
        err(-1, "signal(SIGINFO) failed");
}

void unsetup_signals(void) {
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
        err(-1, "signal(SIGCHLD) failed");

    if (signal(SIGUSR1, SIG_DFL) == SIG_ERR)
        err(-1, "signal(SIGINFO) failed");
}

void handle_blocked_children(void) {
    sigset_t blocked_set;
    sigemptyset(&blocked_set);
    sigaddset(&blocked_set, SIGCHLD);
    sigprocmask(SIG_UNBLOCK, &blocked_set, NULL);
    /* if we had any SIGCHLD waiting, we should hit it... now */
    sigprocmask(SIG_BLOCK, &blocked_set, NULL);
}

void wait_for_signal(void) {
    sigset_t empty_set;
    sigemptyset(&empty_set);

    if (exit_val < 0) {
        kill(-getpid(), SIGUSR1);
    }
        
    sigsuspend(&empty_set);
}

void setup_ptrace(pid_t pid) {
    int status;

    if (ptrace(PT_ATTACH, pid, 0, 0) != 0) {
        err(-1, "ptrace attach failed");
    }

    if (waitpid(pid, &status, 0) == pid) {
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGSTOP) {
                if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) != 0) {
                    err(-1, "ptrace continue failed");
                }
                return;
            }
        }

        err(-1, "unexpected waitpid status: %d\n", status);
    }
}

void continue_ptrace(pid_t pid) {
    int status;

    if (waitpid(pid, &status, 0) == pid) {
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP) {
                if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) != 0) {
                    err(-1, "ptrace continue failed");
                }
                return;
            }
        }
        err(-1, "unexpected waitpid status (continue): %d\n", status);
    }
}

static void print_registers(pid_t pid) {
    /* TODO: sync with Salls and co. in how to communicate the crash info */
    return;

    int res;
    struct user_regs_struct registers;
    res = ptrace(PT_GETREGS, pid, 0, (caddr_t)&registers);
    if (res == 0) {
        fprintf(stderr, "register states - ");
        fprintf(stderr, "eax: %08lx ", registers.eax);
        fprintf(stderr, "ecx: %08lx ", registers.ecx);
        fprintf(stderr, "edx: %08lx ", registers.edx);
        fprintf(stderr, "ebx: %08lx ", registers.ebx);
        fprintf(stderr, "esp: %08lx ", registers.esp);
        fprintf(stderr, "ebp: %08lx ", registers.ebp);
        fprintf(stderr, "esi: %08lx ", registers.esi);
        fprintf(stderr, "edi: %08lx ", registers.edi);
        fprintf(stderr, "eip: %08lx\n", registers.eip);
    } else {
        warn("Could not use PT_GETREGS on %d!", pid);
    }
}

/* Local variables: */
/* mode: c */
/* c-basic-offset: 4 */
/* End: */
