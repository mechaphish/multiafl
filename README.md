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

- **NON-LUNGE POLLS FAILED!
- **Fix signals being fatal for the QEMU forkservers too! (exit(2)?!?)**
- **Test with actual AFL**. For now I've been testing with the polls (`run_via_fakeforsrv` + `cb_replay`).
- Automated `make check`.


Code:

- Delay the forkserver at the first receive/transmit/fdwait?
- The exit-on-double-empty-receive heuristic is currently disabled. Reintroduce with separate count for each fd?
- Expose the signal kill info to the CRS. (Rest can probably just reuse the regular AFL integration.)
- Ask Nick for other integrations / useful modifications.
