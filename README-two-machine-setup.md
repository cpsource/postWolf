Practical setup tips:

  1. One-shot test — confirm Claude can reach the other host:
  ssh -o BatchMode=yes ubuntu@frflashy.com 'echo OK && hostname'
  2. Keep the connection warm — add this to ~/.ssh/config on the box running Claude so each ssh invocation reuses one
  TCP/TLS session (saves ~200ms per command):
  Host frflashy.com
      ControlMaster auto
      ControlPath ~/.ssh/cm-%r@%h:%p
      ControlPersist 10m
  3. For files — scp ubuntu@frflashy.com:/path /tmp/local or rsync work the same way through ssh.
  4. Tell Claude to use it — at the start of the session, drop a line like "For commands on frflashy, prefix with ssh
  ubuntu@frflashy.com" and Claude will pick it up.

  Tradeoff: every cross-host command is a separate SSH round-trip in Claude's transcript — the back-and-forth gets
  verbose, and you can't pipe data between boxes inside a single Bash call without quoting carefully. For most ops (read a
   file, run a tool, check a service) it's fine; for heavy interactive work it's better to run a separate Claude Code
  session on each box and have them coordinate via git.

  Want me to spawn the claude-code-guide agent for a more authoritative writeup, or is this enough to get going?
