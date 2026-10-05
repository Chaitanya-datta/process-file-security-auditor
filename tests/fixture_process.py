"""Controlled test process used by scenarios A-F.

This is a harmless stand-in for "a process doing something". It only ever:
  * opens a file inside tests/sandbox/ for reading and keeps it open,
  * optionally starts one child shell that just sleeps,
  * waits, then exits.

It talks to the test harness over stdin / stdout with one JSON line per event.
It exits when its lifetime ends or when the harness closes its stdin, so it
cannot be left running by accident. Standard library only.
"""

import argparse
import json
import os
import select
import signal
import subprocess
import sys
import time

open_handles = []
child = None


def say(**event):
    print(json.dumps(event), flush=True)


def open_and_hold(path):
    handle = open(path, "r")          # read-only; the file is never modified
    handle.read(1)
    open_handles.append(handle)
    say(event="opened", path=path, time=time.time())


def stop_child():
    if child is not None and child.poll() is None:
        child.terminate()


def on_terminate(_signum, _frame):
    stop_child()
    sys.exit(0)


def main():
    global child
    parser = argparse.ArgumentParser()
    parser.add_argument("--psa-test-process", action="store_true",
                        help="marker that identifies a controlled test process")
    parser.add_argument("--open", help="file to open and hold at start-up")
    parser.add_argument("--spawn-shell", action="store_true",
                        help="start one child shell that only sleeps")
    parser.add_argument("--lifetime", type=float, default=90.0)
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, on_terminate)
    deadline = time.time() + args.lifetime

    if args.open:
        open_and_hold(args.open)

    child_pid, spawn_time = None, None
    if args.spawn_shell:
        # A shell loop (instead of one long sleep) keeps the shell itself alive
        # as the child process; it ends on its own after the lifetime.
        loop = f"i=0; while [ $i -lt {int(args.lifetime)} ]; do sleep 1; i=$((i+1)); done"
        child = subprocess.Popen(["/bin/sh", "-c", loop])
        child_pid, spawn_time = child.pid, time.time()

    say(event="ready", pid=os.getpid(), child_pid=child_pid, spawn_time=spawn_time, time=time.time())

    try:
        while time.time() < deadline:
            readable, _, _ = select.select([sys.stdin], [], [], 0.5)
            if not readable:
                continue
            line = sys.stdin.readline()
            if not line:                 # harness closed stdin
                break
            command, _, argument = line.strip().partition(" ")
            if command == "open":
                open_and_hold(argument)
            elif command == "quit":
                break
    finally:
        stop_child()


if __name__ == "__main__":
    main()
