/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.2.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <assert.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include "../../config.h"

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2 ERROR_SNIPPET2_WAS_REMOVED

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

void afl_setup(void);
void afl_forkserver(CPUArchState*);
static inline void afl_maybe_log(abi_ulong);

static void afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,
                                      target_ulong, uint64_t);


/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};


/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/


// ADDED: Split map so multiple can run concurrently ////////////////////////////////
extern int multicb_i, multicb_count;
static inline abi_ulong limit_to_my_map(abi_ulong map_offset)
{
    // Given MAP_SIZE_POW2       originally 16, maybe 18
    //    so MAP_SIZE            (1 << MAP_SIZE_POW2)
    // split the map keeping it page-aligned
    // TODO: Align to more? 16k?
    //       (Sync with the debug print below)
    assert(multicb_i != -1);
    assert(multicb_count != -1);
    abi_ulong pages_per_cb = MAP_SIZE / 4096 / multicb_count;
    abi_ulong bytes_per_cb = pages_per_cb * 4096;
    abi_ulong mystart = multicb_i * bytes_per_cb;
    return mystart + (map_offset % bytes_per_cb);
}


/* Set up SHM region and initialize other stuff. */

void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1)
        err(-20, "afl_area_ptr = shmat(shm_id = %d)", shm_id);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

}


/* Fork server logic, invoked once we hit _start. */

void afl_forkserver(CPUArchState *env) {

  //if (!afl_area_ptr)
  //    errx(-20, "afl_area_ptr == NULL, unsupported!");


  uint32_t hello = 0xC6CAF1F5; // ADDED: Sanity check that it's actually our multi-CB QEMU /////
  if (write(FORKSRV_FD + 1, &hello, 4) != 4)
      err(-90, "I want to run as a forkserver");

  if ((multicb_i == -1) || (multicb_count == -1))
      err(-90, "No --multicb_i or --multicb_count argument?");

#if defined(DEBUG) || defined(DEBUG_MULTICB)
  fprintf(stderr, "Running as multi-CB forkserver, CB_%d (%d of %d)\n", multicb_i, multicb_i+1, multicb_count); 
  {
      abi_ulong pages_per_cb = MAP_SIZE / 4096 / multicb_count; // Sync with above
      abi_ulong mystart = limit_to_my_map(0);
      fprintf(stderr, "Will use %u/%u pages of the bitmap [%#x,%#x]\n", pages_per_cb, MAP_SIZE/4096, mystart, mystart-1+4096*pages_per_cb);
      assert((MAP_SIZE % 4096) == 0);
      assert((mystart % 4096) == 0);
      assert(limit_to_my_map(4096*pages_per_cb) == limit_to_my_map(0));
      assert(limit_to_my_map(4096*pages_per_cb+1) == limit_to_my_map(1));
      assert(limit_to_my_map(4096*pages_per_cb-1) == (limit_to_my_map(0)-1+4096*pages_per_cb));
  }
#endif

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    uint32_t forkcmd;
    if (read(FORKSRV_FD, &forkcmd, 4) != 4) exit(2);

    // ADDED: Get the multi-CB socketpairs //////////////////////////////////////////
    const int FDPASSER_FD = FORKSRV_FD - 2;
    const size_t num_fds = 2*multicb_count;
    struct cmsghdr* cmsg = (struct cmsghdr*) malloc(CMSG_SPACE(sizeof(int)*num_fds));
    struct msghdr msghdr = {0};
    msghdr.msg_control = cmsg;
    msghdr.msg_controllen = CMSG_SPACE(sizeof(int)*num_fds);
    if (recvmsg(FDPASSER_FD, &msghdr, 0) != 0)
      err(-9, "recvmsg from FDPASSER_FD");
    if (cmsg->cmsg_type != SCM_RIGHTS)
      errx(-10, "Unexpected control message");
    if (msghdr.msg_controllen != CMSG_LEN(sizeof(int)*num_fds))
      errx(-11, "Unexpected number of socketpair fds passed");
    int* cbsockets = (int*) CMSG_DATA(cmsg);
    for (int i = 0; i < num_fds; i++) {
        // The fds we get can be on the wrong number...
        if (cbsockets[i] == (3+1)) continue;
        // ...so if wrong move them out of the way...
        int newfd = fcntl(cbsockets[i], F_DUPFD, 50+num_fds);
        if (newfd == -1)
            err(-14, "Could not F_DUPFD the %d-th passed fd (%d)! Maybe out of file descriptors?", i, cbsockets[i]);
        close(cbsockets[i]);
        cbsockets[i] = newfd;
    }
    for (int i = 0; i < num_fds; i++) {
      if (cbsockets[i] == (3+i)) continue;
      // ...and then dup to the right one
      int newfd = fcntl(cbsockets[i], F_DUPFD, 3+i);
      if (newfd != (3+i)) {
        warn("Could not set file descriptor %d, probably it was already open! I need it for multi-CB socketpairs. fcntl() = %d, errno, if any, was", 3+i, newfd);
        exit(-12);
      }
      close(cbsockets[i]);
    }

    // ADDED: Extra protocol to allow for cb-test ///////////////////////////////////
    // Note: AFL does not use this
    int test_connection = -1;
    if (forkcmd == 0xC6CF550C) { // CGC FS SOCket
        struct cmsghdr* cmsg = (struct cmsghdr*) malloc(CMSG_SPACE(sizeof(int)));
        struct msghdr msghdr = {0};
        msghdr.msg_control = cmsg;
        msghdr.msg_controllen = CMSG_LEN(sizeof(int));
        if (recvmsg(FDPASSER_FD, &msghdr, 0) != 0)
          err(-91, "recvmsg from FDPASSER_FD [SPECIAL FOR test_connection]");
        if (cmsg->cmsg_type != SCM_RIGHTS)
          errx(-101, "Unexpected control message [SPECIAL FOR test_connection]");
        if (msghdr.msg_controllen != CMSG_LEN(sizeof(int)))
          errx(-111, "Unexpected number of socketpair fds passed [SPECIAL FOR test_connection] (%zu != %zu = CMSG_LEN(sizeof(int))", msghdr.msg_controllen, CMSG_LEN(sizeof(int)));
        memcpy(&test_connection, CMSG_DATA(cmsg), sizeof(int));
        assert(test_connection != TSL_FD);
        assert(test_connection != -1);
    }

    /* Establish a channel with child to grab translation commands. We'll 
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */
      
      signal(SIGUSR2, SIG_DFL); // ADDED: used to kill only CB-running QEMUs ////////
      close(FDPASSER_FD);       // ADDED: child won't need this anymore /////////////

      // ADDED: stdin/stdout from test_connection
      if (test_connection != -1) {
        // Note: discarding actual stdin/stdout -- should I assign them to last_fd(+1)?
        if (dup2(test_connection, 0) == -1)
          err(-113, "dup test_connection to 0");
        if (dup2(test_connection, 1) == -1)
          err(-114, "dup test_connection to 1");
        close(test_connection);
      }
#if !defined(DEBUG) && !defined(ALLOW_CB_STDERR)
      // This is what service-launcher does if run without --debug
      int dev_null_fd = open("/dev/null", O_WRONLY);
      if (dev_null_fd == -1)
        err(-115, "Cannot open /dev/null!?!"); 
      if (dup2(dev_null_fd, 2) == -1)
        err(-115, "dup /dev/null to 2");
      close(dev_null_fd);
#endif

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);
    for (int i = 0; i < num_fds; i++) // ADDED: new children will need new ones /////
        close(3+i);
    if (test_connection != -1)
        close(test_connection);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  // ADDED: limit_to_my_map
  afl_area_ptr[limit_to_my_map(cur_loc ^ prev_loc)]++;
  prev_loc = limit_to_my_map(cur_loc >> 1);

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {

  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb_find_slow(env, t.pc, t.cs_base, t.flags);

  }

  close(fd);

}

