To use:

    git clone cgc/multiafl
    make -j  # Will also checkout branch multicb_afl of cgc/qemu
    cd afl
    ./afl-fuzz {-i, -t, ...} -Q CB0 [CB1] [CB2] ...

If samples are available, you can also `make -j check`. See [fakeforksrv/Makefile](fakeforksrv/Makefile).


How it works
============


Basically:

    AFL  <-- forksrv protocol -->  fakeforksrv  <-- modif. forksrv protocol -->  QEMU forksrv for CB_0
                                                                        ... -->  QEMU forksrv for CB_1
                                                                        ...              ...


Note that the CB\_0, CB\_1, etc. QEMUs run in parallel. Current approach is that they split the shared memory (`trace_bits`) among themselves, page-aligned.



**Base forkserver protocol**:
0. forksrv -> AFL   *hello*
1. AFL -> forksrv   *fork!*
2. forksrv -> AFL   *child PID*
3. forksrv -> AFL   *child wait() status*
4. back to 1.


**Modified protocol**:
0. QEMU fs -> me    *hello*
1. me -> QEMU fs    *fork!*
2. me -> QEMU fs    *pass the socketpairs*
3. forksrv -> me    *child PID*
4. forksrv -> me    *child wait() status*
5. back to 1.


**In more detail**:
 0. AFL spawns fakeforksrv
 1. fakeforksrv spawns a QEMU forkserver for each CB
 2. each QEMU forksrv --> fakeforkrsv     *hello*
 3. fakeforksrv --> AFL                   *hello*
 4. AFL -> fakeforksrv                    *fork!*
 5. fakeforksrv creates the socketpairs
 6. fakeforksrv --> each QEMU forksrv     *fork!*
 7. fakeforksrv --> each QEMU forksrv     *socketpairs fds*
 8. each QEMU forksrv dups the socketpairs to the correct fds
 9. each QEMU forksrv forks for its CB-runner child
10. each QEMU forksrv --> fakeforksrv     *CB-runner PID*
11. CB-runner QEMUs run, updating their portion of `trace_bits` and relaying translation request to their QEMU forkserver (regular AFL procedure, if not for the "partitioned" bitmap)
12. fakeforksrv -> AFL                    *PID of QEMU child running CB_0*
13. each QEMU forksrv --> fakeforksrv     *CB-runner wait() status*
14. fakeforksrv -> AFL                    *signaled status, if any, a regular exit() otherwise*
15. back to 4.


**Note:**
- At step 13, fakeforsrv does `select()` on the active CBs. If any CB ends due to a signal, the others will also be killed (SIGUSR2 to the process group, ignored by the forkservers only).
- `run_via_fakeforsrv` is a test wrapper akin to `cb-server`. It can either use regular stdin/stdout (for manual testing) or accept multiple connections (e.g., from cb-replay), so that the entire thing can be tested with multiple runs without involving the real AFL.
    - Its *fork* commands use a magic constant, indicating a slight variation on the protocol: the original TCP connection is also passed via `sendmsg` (like the socketpairs). The CB-running QEMUs will `dup` it to 0 and 1.



TODO
====

Testing:

- Check efficiency with real AFL, try to find bugs -- in the CBs on in my code :)
- Why is it so slow with `LUNGE_00005`? (Poll test ~3 times slower! Other challenge sets fare better. Could be because the polls are kinda bad and it almost always exists immediately?)


Code:

- Expose the signal kill info to the CRS. (Rest can probably just reuse the regular AFL integration.)
- Delay the forkserver at the first receive(stdin) from *any* CB? (This is tricky, see comment in `syscall.c`)
- The exit-on-double-empty-receive heuristic is counting for _any_ fd. Separate count for each fd?
- Better fix for forkserver syscalls interrupted by SIGCHLD. Block/wait like service-launcher does?
- Re-ask Nick for other integrations / useful modifications :)


Notes for debugging
===================

- Compile stuff with `-O0` or `-Og` (set CFLAGS for afl and fakeforksrv, run `cgc_configure_debug` for QEMU).
- Set `DEBUG_STDERR` in [afl-fuzz.c](afl/afl-fuzz.c) to have it go to `/tmp/my_stderr.txt` instead of `/dev/null`.
- fakeforksrv can spawn the QEMUs in separate xterm windows, possibly with gdb (set [CFLAGS](fakeforksrv/Makefile)).
- An `afl/qemu_mode/qemu_dev` dir is used by preference, if available, and left alone w.r.t. deletion and reconfiguration.
