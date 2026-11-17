"""The panel's terminal must be a real controlling terminal, with a size.

Reported as "the terminal runs the shell on a channel, not on a pty". The
record was imprecise in a way that matters: pty.openpty() was already there.
What was missing is that the pty never became the child's *controlling*
terminal. `start_new_session=True` calls setsid(2), and a session leader made
that way has no controlling terminal at all; an inherited descriptor does not
become one, which on FreeBSD takes TIOCSCTTY and nothing issued it.

The visible half was "can't set terminal process group", no job control, ^C
reaching nobody, and top/vi/less misbehaving. The second half was the size: a
fresh pty is 0x0, /api/terminal/resize was named in the agent's allowlist with
no handler behind it and no caller in app.js, so full-screen programs were
drawing into a terminal of no size.

These tests start a real session and interrogate the pty the child actually
got. Asserting on the source of TerminalSession would not distinguish a pty
that is controlling from one that merely exists -- which is the whole defect.
"""
from __future__ import annotations

import fcntl
import os
import struct
import termios
import time
import unittest

from gatebsd_ui import api


def _drain(session: api.TerminalSession, deadline: float = 5.0) -> bytes:
    """Read until the child stops producing, or the deadline passes."""
    collected = b""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        chunk = session.read(timeout=0.25)
        if chunk:
            collected += chunk
        elif collected:
            break
    return collected


class TerminalIsAControllingTerminal(unittest.TestCase):
    """The child is run directly, not through su(1).

    su -l needs an account and a password database this harness has no business
    arranging; the property under test belongs to how the session is forked,
    not to which program it forks.
    """

    def setUp(self) -> None:
        self.session: api.TerminalSession | None = None

    def tearDown(self) -> None:
        if self.session is not None:
            self.session.close()

    def _start(self, program: list[str]) -> api.TerminalSession:
        self.session = api.TerminalSession("root", argv=program)
        return self.session

    # ------------------------------------------------------------- the defect
    def test_the_child_has_a_controlling_terminal(self) -> None:
        """/dev/tty *opens* only for a process that has one.

        `[ -r /dev/tty ]` is not that test and was tried first: the node exists
        and its permission bits allow reading, so the check passed with no
        controlling terminal at all and the defect went on being invisible.
        Opening it is what fails with ENXIO.
        """
        session = self._start(
            ["/bin/sh", "-c", "if : < /dev/tty 2>/dev/null; then echo CTTY-YES; else echo CTTY-NO; fi"]
        )
        output = _drain(session)
        self.assertIn(b"CTTY-YES", output, output)
        self.assertNotIn(b"CTTY-NO", output)

    def test_the_child_is_its_own_session_leader_and_process_group(self) -> None:
        """That is what makes killpg on the pid reach the shell and its children.

        Asked of the kernel from this side rather than by running ps(1) in the
        child: the first version did that and failed where ps is not installed,
        which says something about the harness and nothing about the session.
        """
        session = self._start(["/bin/sh", "-c", "echo READY; sleep 5"])
        _drain(session, deadline=2.0)
        self.assertEqual(os.getpgid(session.pid), session.pid)
        self.assertEqual(os.getsid(session.pid), session.pid)

    def test_the_terminal_reports_the_size_it_was_given(self) -> None:
        """A fresh pty is 0x0, and stty reads it from the tty, not from us."""
        session = self._start(["/bin/sh", "-c", "stty size < /dev/tty"])
        output = _drain(session)
        self.assertIn(b"24 80", output, output)

    def test_resize_reaches_the_pty(self) -> None:
        session = self._start(["/bin/sh", "-c", "sleep 5"])
        session.set_window_size(40, 132)
        packed = fcntl.ioctl(session.master_fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _, _ = struct.unpack("HHHH", packed)
        self.assertEqual((rows, cols), (40, 132))

    def test_an_absurd_size_is_clamped_rather_than_passed_to_ioctl(self) -> None:
        session = self._start(["/bin/sh", "-c", "sleep 5"])
        session.set_window_size(10 ** 6, 10 ** 6)
        packed = fcntl.ioctl(session.master_fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _, _ = struct.unpack("HHHH", packed)
        self.assertEqual((rows, cols), (api._TERMINAL_MAX_ROWS, api._TERMINAL_MAX_COLS))
        session.set_window_size(0, 0)
        packed = fcntl.ioctl(session.master_fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _, _ = struct.unpack("HHHH", packed)
        self.assertEqual((rows, cols), (1, 1))

    # ------------------------------------------------------------- lifecycle
    def test_an_exited_child_is_reaped_and_reported_once(self) -> None:
        """waitpid answers once per child; asking twice used to raise.

        Popen cached this. Replacing it with a bare waitpid would have made
        is_running() flip back to True for a dead session on the second call.
        """
        session = self._start(["/bin/sh", "-c", "exit 0"])
        _drain(session)
        for _ in range(100):
            if not session.is_running():
                break
            time.sleep(0.05)
        self.assertFalse(session.is_running())
        self.assertFalse(session.is_running())

    def test_close_is_safe_to_call_twice(self) -> None:
        session = self._start(["/bin/sh", "-c", "sleep 30"])
        session.close()
        session.close()
        self.assertFalse(session.is_running())

    def test_close_takes_down_what_the_shell_started(self) -> None:
        """The signal goes to the process group, not to the shell alone."""
        session = self._start(["/bin/sh", "-c", "sleep 30 & echo CHILD=$!; wait"])
        output = _drain(session, deadline=3.0)
        marker = b"CHILD="
        self.assertIn(marker, output, output)
        child_pid = int(output.split(marker)[1].split()[0])

        session.close()
        for _ in range(100):
            try:
                os.kill(child_pid, 0)
            except OSError:
                break
            time.sleep(0.05)
        else:
            self.fail("the shell's child outlived the session")


class ResizeEndpointIsWired(unittest.TestCase):
    """It was in the agent's allowlist with nothing behind it."""

    def test_the_agent_lets_the_resize_call_through(self) -> None:
        from gatebsd_ui import agent

        self.assertIn("/api/terminal/resize", agent._IDENTITY_BEARING_PATHS)
        allowed = getattr(agent, "_WRITE_PATHS", None) or getattr(agent, "WRITE_PATHS", None)
        if allowed is not None:
            self.assertIn("/api/terminal/resize", allowed)

    def test_a_non_numeric_size_is_refused_before_any_session_is_touched(self) -> None:
        status, payload = api.terminal_resize({}, "eighty", "twenty-four")
        self.assertEqual(status, 400)
        self.assertIn("integers", payload["error"])

    def test_a_zero_size_is_refused(self) -> None:
        status, payload = api.terminal_resize({}, 0, 80)
        self.assertEqual(status, 400)
        self.assertIn("positive", payload["error"])


if __name__ == "__main__":
    unittest.main()
