#!/usr/bin/env python3
"""Record the procscope TUI to an asciicast v2 file with a forced terminal size.

Headless GIF tooling gives the program a 0x0 pty, so ratatui renders nothing.
This harness opens a pty, forces the window size, runs procscope as a child with
that pty as its controlling terminal, and logs timed output as an asciicast.
"""
import os
import pty
import fcntl
import termios
import struct
import time
import json
import select
import signal
import sys

COLS, ROWS = 110, 30
DURATION = float(os.environ.get("DURATION", "10"))
OUT = os.environ.get("OUT", "/tmp/demo.cast")
CMD = ["/src/target/release/procscope"]

pid, master = pty.fork()
if pid == 0:
    # Child: stdout/stdin are the slave pty (also the controlling terminal).
    fcntl.ioctl(sys.stdout.fileno(), termios.TIOCSWINSZ,
                struct.pack("HHHH", ROWS, COLS, 0, 0))
    os.environ["TERM"] = "xterm-256color"
    os.execv(CMD[0], CMD)
    os._exit(127)

# Parent: drain the master, timestamp output, stop after DURATION.
events = []
start = time.time()
flags = fcntl.fcntl(master, fcntl.F_GETFL)
fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
while time.time() - start < DURATION:
    r, _, _ = select.select([master], [], [], 0.1)
    if master in r:
        try:
            data = os.read(master, 65536)
        except OSError:
            break
        if not data:
            break
        events.append([round(time.time() - start, 4), "o",
                       data.decode("utf-8", "replace")])

try:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
except (ProcessLookupError, ChildProcessError):
    pass

with open(OUT, "w") as f:
    f.write(json.dumps({"version": 2, "width": COLS, "height": ROWS,
                        "env": {"TERM": "xterm-256color"}}) + "\n")
    for ev in events:
        f.write(json.dumps(ev) + "\n")

print(f"wrote {OUT}: {len(events)} output chunks")
