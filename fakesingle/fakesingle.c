/*
 * Adapted from service-launcher.
 *
 * Original copyright:
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <unistd.h>

#include "signals.h"
#include "sockets.h"
#include "utils.h"

extern volatile unsigned long num_children;
extern int exit_val;

int monitor_process;

volatile unsigned long num_children;


static void set_core_size(int size) {
    // Was in resources.c
    struct rlimit rlim = {size, size};
    VERIFY(setrlimit, RLIMIT_CORE, &rlim);
}



static void start_program(char *program, int program_i, int program_count) {
    unsetup_signals();

#ifdef DEBUG
    dprintf(STDERR_FILENO, "pid=%d CB_%d program=%s\n", getpid(), program_i, program);
#endif

    /* Modified to inherit environment, but fixed argv */
#ifdef QEMU_PATH
    char program_i_str[10], program_count_str[10]; // TODO: make faster?
    snprintf(program_i_str, 10, "%d", program_i);
    snprintf(program_count_str, 10, "%d", program_count);
    VERIFY(execl, __STRING(QEMU_PATH), "multi-qemu", program, "--multicb_i", program_i_str, "--multicb_tot", program_count_str, (char *) NULL);
#else
    VERIFY(prctl, PR_SET_DUMPABLE, 1, 0, 0, 0); // Won't necessarily create the core dump (use set_core_size)
    VERIFY(execl, program, program, (char *) NULL);
    (void) program_i; (void) program_count;
#endif
}

static void handle(const int program_count, char **programs) {
    int i;
    pid_t pid;
    monitor_process = 1;

    null_stderr(); // Only remaining part of setup_connection

    setup_sockpairs(program_count, STDERR_FILENO + 1);

    num_children = program_count;

    for (i = 0; i < program_count; i++) {
        //int pause_sockets_1[2];
        //int pause_sockets_2[2];
        //setup_pairwise_wait(pause_sockets_1);
        //setup_pairwise_wait(pause_sockets_2);

        VERIFY_ASSN(pid, fork);

        if (pid == 0) {
            //ready_pairwise(pause_sockets_1);
            //wait_pairwise(pause_sockets_2);

            start_program(programs[i], i, program_count);
            break;
        } else {
            //wait_pairwise(pause_sockets_1);

            //if (wrapper == NULL && no_attach_flag == 0)
            //    setup_ptrace(pid);

            //ready_pairwise(pause_sockets_2);

            //if (wrapper == NULL && no_attach_flag == 0)
            //    continue_ptrace(pid);
        }
    }

    while (num_children > 0)
        wait_for_signal();

    if (exit_val < 0) {
        unsetup_signals();
        set_core_size(0);
        raise(-exit_val);
        pause();
    }
    _exit(exit_val);
}

int main(int argc, char **argv) {
    int core_size = 0; // DEFAULTED TO 0 (still dumpable, but no core dump)
    int i;
    num_children = 0;


#ifdef HARDCODED_CBS
    const char *hardcoded_cbs[] = { HARDCODED_CBS };
    argc = sizeof(hardcoded_cbs)/sizeof(const char*);
    argv = malloc((1+argc)*sizeof(char*));
    for (i = 0; i < argc; i++)
        argv[i] = strdup(hardcoded_cbs[i]);
    argv[argc] = NULL; /* Just to be safe */
# ifdef DEBUG
    dprintf(STDERR_FILENO, "Using %d HARDCODED_CBS:\n", argc);
    for (i = 0; i < argc; i++)
        dprintf(STDERR_FILENO, "  Hardcoded CB %d: %s\n", i+1, argv[i]);
# endif
#else
    char *cbs_from_env[50];
    int cbs_from_env_count = 0;
    if (argc == 1 || getenv("FORCE_CB_ENV") != NULL) {
        // Try to get the names from CB_1, CB_2, etc.
        // Turns them into argc/argv, same as getting them as arguments
        for (i = 1; i <= 50; i++) {
            char varname[10];
            snprintf(varname, sizeof(varname), "CB_%d", i);
            char *val = getenv(varname);
            if (val != NULL) {
                cbs_from_env[i-1] = val;
                cbs_from_env_count++;
#ifdef DEBUG
                dprintf(STDERR_FILENO, "Taking CB_%d='%s'\n", i, val);
#endif
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

    if (core_size != -1)
        set_core_size(core_size);

    setup_signals();

    // Note: would set NODELAY and 5s LINGER (keep sending after close) on the server socket

    //for (;;) {
    handle_blocked_children();
    num_children++;

    exit_val = 0;
    handle(argc, argv);
#ifdef DEBUG
    dprintf(STDERR_FILENO, "WEIRD: fakesingle should not return from handle!");
#endif

    // Not sure why repeated
    handle_blocked_children();

    while (num_children > 0) {
        wait_for_signal();
    }

    if (exit_val != 0) {
        unsetup_signals();
        set_core_size(0);
        exit_val = -exit_val;
    }

    return exit_val;
}

/* Local variables: */
/* mode: c */
/* c-basic-offset: 4 */
/* End: */
