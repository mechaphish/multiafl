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

#include <getopt.h>

#include "signals.h"
#include "sockets.h"
#include "utils.h"

extern volatile unsigned long num_children;
extern int exit_val;

int monitor_process;

volatile unsigned long num_children;

char *seed = NULL;

static void set_core_size(int size) {
    // Was in resources.c
    struct rlimit rlim;
    if (size == -1) {
        size = (int) RLIM_INFINITY;
    }

    rlim.rlim_cur = size;
    rlim.rlim_max = size;

    VERIFY(setrlimit, RLIMIT_CORE, &rlim);
}



static void start_program(const char *program, int program_i, int program_count) {
    unsetup_signals();

    DBG_PRINTF("pid=%d CB_%d program=%s\n", getpid(), program_i, program);
    /* Modified to inherit environment, but fixed argv */
    VERIFY(prctl, PR_SET_DUMPABLE, 1, 0, 0, 0); // Won't necessarily create the core dump (use set_core_size)
    if (seed) {
        VERIFY(execl, program, program, seed, (char *) NULL);
    } else
        VERIFY(execl, program, program, (char *) NULL);
    (void) program_i; (void) program_count;
}

static void handle(const int program_count, const char **programs) {
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
    int core_size = -1;
    int i;
    num_children = 0;

    setsid(); // So kill on process group works on this CB only

    //// Keep in sync with fakeforksrv.c 
    int program_count;
    const char **programs;
#ifdef HARDCODED_CBS
    DBG_PRINTF("Using HARDCODED_CBS, ignoring argc/argv\n"); (void) argc; (void) argv;
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
            fprintf(stderr, "Usage: %s [-c coresize] [-s seed] cb0 [cb1] [...]\n       CB_0=cb0 [CB_1=cb1] [...up to 50] [FORCE_CB_ENV=1] %s\n", argv[0], argv[0]);
            exit(1);
        }
    } else {
        int opt;
        while ((opt = getopt(argc, argv, "+c:s:")) > 0) 
            switch (opt) {

                case 'c':
                    core_size = atoi(optarg);
                    break;
                case 's':
                    seed = malloc(strlen(optarg) + 6);
                    if (!seed) {
                        perror("malloc");
                        exit(1);
                    }
                    sprintf(seed, "seed=%s", optarg);
                    break;
            }

        program_count = argc - optind;
        programs = (const char **) argv + optind;
    }
#endif
    DBG_PRINTF("Running %d CBs:", program_count);
    for (i = 0; i < program_count; i++)
        DBG_PRINTF("   CB_%d = %s\n", i, programs[i]);

    set_core_size(core_size);

    setup_signals();

    // Note: would set NODELAY and 5s LINGER (keep sending after close) on the server socket

    //for (;;) {
    handle_blocked_children();
    num_children++;

    exit_val = 0;
    handle(program_count, programs);
    DBG_PRINTF("WEIRD: fakesingle should not return from handle!\n");

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
