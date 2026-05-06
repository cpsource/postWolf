# socket-level-wrapper-QUIC — DEPRECATED 2026-05-06

This directory contained an in-progress UDP/QUIC-inspired post-quantum
transport (MQCP) that was never finished.  TODO #10 in
`mtc-keymaster/README-bugsandtodo.md` documents the open handshake
bug ("MQCP echo handshake never completes").

**As of phase-25 it is no longer built or installed.**
`make -f Makefile.tools` skips this directory.  The `quic` target
in `Makefile.tools` is now a no-op kept only so any external
scripts that ran `make -f Makefile.tools quic` don't break.

The source files remain checked in for history.  Recover them via
`git log` if you ever want to revive the work.  No tooling outside
this directory references MQCP at runtime.

If you're looking for postWolf's working post-quantum transport,
see `socket-level-wrapper-MQC/` (TCP-based, fully shipped).
