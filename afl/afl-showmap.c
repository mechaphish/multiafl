/*
   american fuzzy lop - map display utility
   ----------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014, 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   Exit code is 2 if the target program crashes; 1 if it times out or
   there is a problem executing it; or 0 if execution is successful.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>



_Static_assert(FORKSRV_FD == 198, "Altered FORKSRV_FD? fakeforksrv has it hardcoded");

// My own utils, like the always-on fancy assert()
#include <err.h>
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




static s32 child_pid;                 /* PID of the tested program         */

static u8* trace_bits;                /* SHM with instrumentation bitmap   */

static u8 *out_file,                  /* Trace output file                 */
          *doc_path,                  /* Path to docs                      */
          *target_path,               /* Path to target binary             */
          *at_file;                   /* Substitution string for @@        */

static u32 exec_tmout;                /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

static s32 shm_id;                    /* ID of the SHM region              */

static u8  quiet_mode,                /* Hide non-essential messages?      */
           edges_only,                /* Ignore hit counts?                */
           cmin_mode;                 /* Generate output in afl-cmin mode? */

static volatile u8
           stop_soon,                 /* Ctrl-C pressed?                   */
           child_timed_out,           /* Child timed out?                  */
           child_crashed;             /* Child crashed?                    */

/* Classify tuple counts. Instead of mapping to individual bits, as in
   afl-fuzz.c, we map to more user-friendly numbers between 1 and 8. */

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym),  AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym),  AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static u8 count_class_lookup[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 3,
  /* 4 - 7:      +4 */ AREP4(4),
  /* 8 - 15:     +8 */ AREP8(5),
  /* 16 - 31:   +16 */ AREP16(6),
  /* 32 - 127:  +96 */ AREP64(7), AREP32(7),
  /* 128+:     +128 */ AREP128(8)

};

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;

  if (edges_only) {

    while (i--) {
      if (*mem) *mem = 1;
      mem++;
    }

  } else {

    while (i--) {
      *mem = count_class_lookup[*mem];
      mem++;
    }

  }

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}


/* Configure shared memory. */

static void setup_shm(void) {

  u8* shm_str;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE + EXTRA_SHM_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}

/* Write results. */

static u32 write_results(void) {

  s32 fd;
  FILE* f;
  u32 i, ret = 0;
  u8  cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
      caa = !!getenv("AFL_CMIN_ALLOW_ANY");

  if (!strncmp(out_file,"/dev/", 5)) {

    fd = open(out_file, O_WRONLY, 0600);
    if (fd < 0) PFATAL("Unable to open '%s'", out_file);

  } else {

    unlink(out_file); /* Ignore errors */
    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  }

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  for (i = 0; i < MAP_SIZE; i++) {

    if (!trace_bits[i]) continue;
    ret++;

    if (cmin_mode) {

      if (child_timed_out) break;
      if (!caa && child_crashed != cco) break;

      fprintf(f, "%u%u\n", trace_bits[i], i);

    } else fprintf(f, "%06u:%u\n", i, trace_bits[i]);

  }
  
  fclose(f);

  return ret;

}


/* Handle timeout signal. */

static void handle_timeout(int sig) {

  child_timed_out = 1;
  if (child_pid > 0) kill(-child_pid, SIGKILL); // Differently from afl-fuzz, it's OK to kill the forkservers too
}


/* Execute target application. */

static void run_target(char** argv) {

  static struct itimerval it;
  int status = 0;

  if (!quiet_mode)
    SAYF("-- Program output begins --\n" cRST);

  MEM_BARRIER();

  // Adapted from init_forkserver / run_via_fakeforkserver
  const int CTL_FD = FORKSRV_FD; // The "forkserver protocol" is spoken over these (fixed) int fds
  const int ST_FD = FORKSRV_FD + 1;
  int ctl, st; // Local fds to fakeforksrv
  uint32_t msg;

  int st_pipe[2], ctl_pipe[2];
  if (pipe(st_pipe) || pipe(ctl_pipe))
      err(-90, "pipe() failed");
  int forksrv_pid = fork();
  if (forksrv_pid == -1)
      err(-80, "Could not fork for fakeforksrv");

  if (forksrv_pid == 0) {
      VE(dup2(ctl_pipe[0], CTL_FD) != -1);
      VE(dup2(st_pipe[1], ST_FD) != -1);
      close(ctl_pipe[0]); close(ctl_pipe[1]);
      close(st_pipe[0]); close(st_pipe[1]);
      if (quiet_mode) {
          s32 fd = open("/dev/null", O_RDWR);
          if (fd < 0 || dup2(fd, 1) < 0 /* || dup2(fd, 2) < 0 */) {
              *(u32*)trace_bits = EXEC_FAIL_SIG;
              PFATAL("Descriptor initialization failed");
          }
          close(fd);
      }
      execv(target_path, argv);
      err(-2, "Could not exec %s", target_path);
  } else {
      close(ctl_pipe[0]); close(st_pipe[1]);
      ctl = ctl_pipe[1];
      st = st_pipe[0];
      DBG_PRINTF("Waiting for fakeforksrv to tell us that it's ready...\n");
      if (read(st, &msg, 4) != 4)
          err(-20, "Could not read back from the status pipe, something went wrong");
      V(msg == 0xC6CAF1F5); // Just as a sanity check
      DBG_PRINTF( "OK, fakeforksrv ready :)\n");
  }

  msg = 0;
  VE(write(ctl, &msg, 4) == 4);

  DBG_PRINTF("Waiting for the fork() pid report...\n");
  VE(read(st, &child_pid, 4) == 4);
  DBG_PRINTF("fakeforksrv reports (QEMU CB_0) pid %d...\n", child_pid);

  /* Configure timeout, wait for child, cancel timeout. */

  if (exec_tmout) {

    child_timed_out = 0;
    it.it_value.tv_sec = (exec_tmout / 1000);
    it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);


  DBG_PRINTF("Waiting for the status report...\n");
  if (read(st, &status, 4) != 4)
      err(-10, "Could not read the status report from fakeforksrv! errno, if not just exit");
  if (WIFEXITED(status)) {
      DBG_PRINTF("Regular exit(%d)\n", WEXITSTATUS(status));
  } else {
      V(WIFSIGNALED(status));
      if (WTERMSIG(status) == SIGKILL) {
          DBG_PRINTF("reported a SIGKILL!\n");
      } else if (WTERMSIG(status) == SIGUSR2) {
          DBG_PRINTF("!!! ERROR: reported a SIGUSR2! (should be hidden!)\n");
      } else DBG_PRINTF("reported signal %d\n", WTERMSIG(status));
  }
  killpg(-forksrv_pid, SIGTERM);

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", argv[0]);

  classify_counts(trace_bits);

  if (!quiet_mode)
    SAYF(cRST "-- Program output ends --\n");

  if (!child_timed_out && !stop_soon && WIFSIGNALED(status))
    child_crashed = 1;

  if (!quiet_mode) {

    if (child_timed_out)
      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
    else if (stop_soon)
      SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);
    else if (child_crashed)
      SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST, WTERMSIG(status));

  }


}


/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (child_pid > 0) kill(-child_pid, SIGKILL);

}


/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

  setenv("ASAN_OPTIONS", "abort_on_error=1:"
                         "detect_leaks=0:"
                         "symbolize=0:"
                         "allocator_may_return_null=1", 0);

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "symbolize=0:"
                         "abort_on_error=1:"
                         "allocator_may_return_null=1:"
                         "msan_track_origins=0", 0);

  if (getenv("AFL_LD_PRELOAD"))
    setenv("LD_PRELOAD", getenv("AFL_LD_PRELOAD"), 1);

}


/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

}


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      if (!at_file) FATAL("@@ syntax is not supported by this tool.");

      /* Be sure that we're always using fully-qualified paths. */

      if (at_file[0] == '/') aa_subst = at_file;
      else aa_subst = alloc_printf("%s/%s", cwd, at_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (at_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Show banner. */

static void show_banner(void) {

  SAYF(cCYA "afl-showmap " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

}

/* Display usage hints. */

static void usage(u8* argv0) {

  show_banner();

  SAYF("\n%s [ options ] -Q /path/to/CB_0 [/path/to/CB_1] [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -o file       - file to write the trace data to\n\n"

       "Execution control settings:\n\n"

       "  -t msec       - timeout for each run (none)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

       "Other settings:\n\n"

       "  -q            - sink program's output and don't show messages\n"
       "  -e            - show edge coverage only, ignore hit counts\n\n"

       "This tool displays raw tuple data captured by AFL instrumentation.\n"
       "*** THIS ONE IS FOR multicb. Will use fakeforksrv ***\n\n" cRST,

       argv0, MEM_LIMIT);

  exit(1);

}


/* Find binary. */

static void find_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);

    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4) break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }

}


/* Fix up argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 2, argv + 1, sizeof(char*) * argc);

  new_argv[1] = target_path;
  //new_argv[1] = "--"; REMOVED FOR SIMPLICITY IN FAKEFORKSRV

  /* Now we need to actually find qemu for argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/fakeforksrv", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", cp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/fakeforksrv", own_copy);
    /* Mandatory after Pizza's changes */
    VE(setenv("AFL_PATH", own_copy, 0) == 0);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else ck_free(own_copy);

  FATAL("Unable to find 'fakeforksrv'.");

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u8  mem_limit_given = 0, timeout_given = 0, qemu_mode = 0;
  u32 tcnt;
  char** use_argv;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  while ((opt = getopt(argc,argv,"+o:m:t:A:eqZQ")) > 0)

    switch (opt) {

      case 'o':

        if (out_file) FATAL("Multiple -o options not supported");
        out_file = optarg;
        break;

      case 'm': {

          u8 suffix = 'M';

          errx(88, "DID NOT IMPLEMENT mem_limit");

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 't':

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        if (strcmp(optarg, "none")) {
          exec_tmout = atoi(optarg);

          if (exec_tmout < 20 || optarg[0] == '-')
            FATAL("Dangerously low value of -t");

        }

        break;

      case 'e':

        if (edges_only) FATAL("Multiple -e options not supported");
        edges_only = 1;
        break;

      case 'q':

        if (quiet_mode) FATAL("Multiple -q options not supported");
        quiet_mode = 1;
        break;

      case 'Z':

        /* This is an undocumented option to write data in the syntax expected
           by afl-cmin. Nobody else should have any use for this. */

        cmin_mode  = 1;
        quiet_mode = 1;
        break;

      case 'A':

        /* Another afl-cmin specific feature. */
        at_file = optarg;
        break;

      case 'Q':

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        qemu_mode = 1;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !out_file) usage(argv[0]);

  setup_shm();
  setup_signal_handlers();

  set_up_environment();

  find_binary(argv[optind]);

  if (!quiet_mode) {
    show_banner();
    ACTF("Executing '%s'...\n", target_path);
  }

  detect_file_args(argv + optind);

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    FATAL("multiafl needs -Q!");

  run_target(use_argv);

  tcnt = write_results();

  if (!quiet_mode) {

    if (!tcnt) FATAL("No instrumentation detected" cRST);
    OKF("Captured %u tuples in '%s'." cRST, tcnt, out_file);

  }

  exit(child_crashed * 2 + child_timed_out);

}

