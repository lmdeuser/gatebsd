"""Contract tests for the FreeBSD rc.d boot scripts.

The router must come up unattended with no console access, so the failure modes
here are boot hangs, wrong ordering and killing the wrong process. rcorder(8)
treats an unsatisfiable REQUIRE as a warning and still emits the file, and
/etc/rc discards both the warning and rcorder's exit status -- so a typo in a
dependency name silently removes an ordering constraint rather than failing
loudly.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RCDIR = ROOT / "rc.d"

# Providers that exist outside this repository: FreeBSD base rc scripts and the
# ports this package depends on (see ci/build.sh).
EXTERNAL_PROVIDERS = {
    # base system anchors
    "DAEMON",
    "FILESYSTEMS",
    "LOGIN",
    "NETWORKING",
    "SERVERS",
    "cleanvar",
    "devfs",
    "netif",
    "routing",
    # First-boot provisioning must run before sshd publishes the host keys the
    # image shipped with. Confirmed on FreeBSD 15.1: /etc/rc.d/sshd declares
    # `PROVIDE: sshd`, so rcorder honours the constraint.
    "sshd",
    "syslogd",
    "var",
    # ports this package installs
    "isc-dhcpd",
    "mpd5",
    "nginx",
    "unbound",
    "pf",
}


def rc_scripts() -> list[Path]:
    return sorted(path for path in RCDIR.iterdir() if path.is_file())


def keyword_tokens(text: str, keyword: str) -> list[str]:
    tokens: list[str] = []
    for line in text.splitlines():
        match = re.match(rf"^#\s*{keyword}:\s*(.*)$", line)
        if match:
            tokens.extend(match.group(1).split())
    return tokens


class RcOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scripts = rc_scripts()
        self.assertTrue(self.scripts, "no rc.d scripts found")
        self.sources = {path: path.read_text(encoding="utf-8") for path in self.scripts}
        self.provided: set[str] = set()
        for text in self.sources.values():
            self.provided.update(keyword_tokens(text, "PROVIDE"))

    def test_every_script_declares_exactly_one_provider(self) -> None:
        for path, text in self.sources.items():
            with self.subTest(script=path.name):
                provides = keyword_tokens(text, "PROVIDE")
                self.assertEqual(len(provides), 1, f"{path.name}: {provides}")
                self.assertEqual(provides[0], path.name)

    def test_every_requirement_resolves_to_a_real_provider(self) -> None:
        """The regression this file exists for.

        rc.d/ru_bypass and rc.d/gatewayctl_apply required "mpd" and "amnezia".
        The net/mpd5 port provides "mpd5", and no rc script named "amnezia"
        exists at all -- the tunnel is brought up by gatewayctl_apply. Both
        requirements resolved to nothing, so the intended "wait for PPPoE"
        ordering did not exist and ru_bypass could run before the WAN had a
        gateway.
        """
        known = self.provided | EXTERNAL_PROVIDERS
        for path, text in self.sources.items():
            for keyword in ("REQUIRE", "BEFORE"):
                for token in keyword_tokens(text, keyword):
                    with self.subTest(script=path.name, keyword=keyword, token=token):
                        self.assertIn(
                            token,
                            known,
                            f"{path.name} {keyword}s '{token}', which no rc.d script "
                            f"provides and which is not a known external provider; "
                            f"rcorder would silently drop this ordering constraint",
                        )

    def test_dependency_graph_is_acyclic(self) -> None:
        graph: dict[str, set[str]] = {}
        for path, text in self.sources.items():
            name = path.name
            graph.setdefault(name, set())
            for token in keyword_tokens(text, "REQUIRE"):
                if token in self.provided:
                    graph[name].add(token)
            for token in keyword_tokens(text, "BEFORE"):
                if token in self.provided:
                    graph.setdefault(token, set()).add(name)

        state: dict[str, int] = {}

        def visit(node: str, trail: list[str]) -> None:
            if state.get(node) == 2:
                return
            self.assertNotEqual(
                state.get(node), 1, f"dependency cycle: {' -> '.join(trail + [node])}"
            )
            state[node] = 1
            for dependency in sorted(graph.get(node, ())):
                visit(dependency, trail + [node])
            state[node] = 2

        for node in sorted(graph):
            visit(node, [])

    def test_lock_cleanup_runs_before_networking(self) -> None:
        text = self.sources[RCDIR / "gatebsd_lock_cleanup"]
        self.assertIn("FILESYSTEMS", keyword_tokens(text, "REQUIRE"))
        self.assertIn("NETWORKING", keyword_tokens(text, "BEFORE"))

    def test_services_that_mutate_routes_require_lock_cleanup(self) -> None:
        for name in ("gatebsd", "gatebsd_failover", "ru_bypass", "gatewayctl_apply"):
            with self.subTest(script=name):
                requires = keyword_tokens(self.sources[RCDIR / name], "REQUIRE")
                self.assertIn("gatebsd_lock_cleanup", requires)
                self.assertIn("NETWORKING", requires)


class RcProcessIdentityTests(unittest.TestCase):
    """A pidfile PID must be verified before it is signalled.

    The kernel recycles PIDs. A stale pidfile plus a recycled PID means `kill`
    hits an unrelated process, and because gatebsd-healthcheck.sh restarts these
    services from cron every five minutes, that is automated rather than a
    one-off operator mistake. If the recycled PID belonged to mpd5, stopping
    GateBSD would drop PPPoE and take the only uplink offline.
    """

    def test_every_rc_script_command_checks_before_signalling(self) -> None:
        for path in rc_scripts():
            text = path.read_text(encoding="utf-8")
            if "kill " not in text:
                continue
            with self.subTest(script=path.name):
                self.assertIn(
                    "-o command=",
                    text,
                    f"{path.name} signals a pidfile PID without verifying the "
                    f"process identity",
                )

    def test_gatebsd_verifies_agent_and_ui_module_names(self) -> None:
        text = (RCDIR / "gatebsd").read_text(encoding="utf-8")
        self.assertIn("gatebsd_ui.agent", text)
        self.assertIn("gatebsd_ui.server", text)
        # The helper must reject a mismatch rather than only checking existence.
        self.assertRegex(text, r"case \"\$_command\" in")

    def test_pidfiles_are_not_followed_through_symlinks(self) -> None:
        text = (RCDIR / "gatebsd").read_text(encoding="utf-8")
        self.assertIn('[ ! -L "$_pidfile" ]', text)


class RcBootBlockingTests(unittest.TestCase):
    """No rc script may block boot on an unbounded operation."""

    def test_retry_loops_are_bounded(self) -> None:
        for path in rc_scripts():
            text = path.read_text(encoding="utf-8")
            for index, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped.startswith("while"):
                    continue
                with self.subTest(script=path.name, line=index):
                    # A bounded loop compares a counter or tests a deadline; an
                    # unconditional `while :` or `while true` in an rc script
                    # would hang boot.
                    self.assertNotRegex(
                        stripped,
                        r"^while\s+(:|true)\s*(;|$)",
                        f"{path.name}:{index} has an unbounded loop",
                    )

    def test_lockf_calls_specify_a_timeout(self) -> None:
        # Matches an actual invocation, not a case(1) pattern that merely mentions
        # lockf while matching a process command line.
        invocation = re.compile(r"(?:^|[;&|(]|\s)(?:/[\w./-]*/)?lockf\s+-")
        for path in rc_scripts():
            text = path.read_text(encoding="utf-8")
            for index, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#") or not invocation.search(line):
                    continue
                with self.subTest(script=path.name, line=index):
                    self.assertRegex(
                        line,
                        r"lockf\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*t\b",
                        f"{path.name}:{index} calls lockf without -t, which can "
                        f"block boot indefinitely",
                    )

    def test_daemonised_work_is_not_run_synchronously(self) -> None:
        # These two scripts exist specifically to keep route/tunnel application
        # off the boot path; both must keep using daemon(8) with a pidfile.
        #
        # gatewayctl_apply is the regression: it called `gatewayctl apply`
        # synchronously. That path runs `awg-quick up`, which resolves the peer
        # endpoint with no timeout of its own, and then waits for a handshake.
        # A dead upstream resolver therefore stalled /etc/rc before LOGIN, so
        # sshd, nginx and the web UI never started -- an unreachable router
        # whose only uplink is the link being configured.
        for name in ("ru_bypass", "gatewayctl_apply"):
            with self.subTest(script=name):
                text = (RCDIR / name).read_text(encoding="utf-8")
                self.assertIn("/usr/sbin/daemon", text)
                self.assertIn('-p "$pidfile"', text)

    def test_gatewayctl_apply_never_calls_apply_synchronously(self) -> None:
        # Match an actual invocation of the gatewayctl binary, not a diagnostic
        # message that merely mentions the words.
        invocation = re.compile(r"(?:^|[;&|(]|\s)(?:/[\w./-]*/)?gatewayctl\s+(?:apply|up)\b")
        text = (RCDIR / "gatewayctl_apply").read_text(encoding="utf-8")
        found = False
        for index, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or not invocation.search(line):
                continue
            found = True
            with self.subTest(line=index):
                # daemon(8) is invoked on a preceding line, so the whole start
                # function is the unit under test rather than the single line.
                start = text.index("gatewayctl_apply_start() {")
                body = text[start : text.index("\n}", start)]
                self.assertIn(
                    "/usr/sbin/daemon",
                    body,
                    f"gatewayctl_apply:{index} runs `gatewayctl apply` on the "
                    f"boot path without daemon(8); awg-quick's endpoint "
                    f"resolution is unbounded and would hang boot",
                )
        self.assertTrue(found, "gatewayctl_apply no longer applies the gateway at all")

    def test_backgrounded_workers_are_stopped_by_process_group(self) -> None:
        """Verified behaviour on FreeBSD 15.1, not an assumption.

        With ``daemon -f -p`` the supervisor is the process-group leader.
        Sending TERM to only the child PID recorded in the pidfile left the
        supervisor alive -- still holding the pidfile lock, so the next start
        failed with "already locked" -- and orphaned the worker's own children
        (awg-quick and its resolver, or the route helper). Signalling the group
        ends all of them, releases the lock and unlinks the pidfile.
        """
        for name in ("ru_bypass", "gatewayctl_apply"):
            with self.subTest(script=name):
                text = (RCDIR / name).read_text(encoding="utf-8")
                self.assertIn("-o pgid=", text, f"{name} does not read a process group")
                self.assertRegex(
                    text,
                    r'kill -TERM -"\$_pgid"',
                    f"{name} must signal the worker's process group, not only "
                    f"the pidfile PID",
                )

    def test_gatewayctl_apply_stop_ends_the_worker_before_taking_the_lock(self) -> None:
        # `gatewayctl teardown` takes the gateway lock with `lockf -t 5`. A
        # running background apply holds that lock, so stopping without first
        # ending the worker would time out and leave the default route inside
        # the tunnel.
        text = (RCDIR / "gatewayctl_apply").read_text(encoding="utf-8")
        start = text.index("gatewayctl_apply_stop() {")
        body = text[start : text.index("\n}", start)]
        stop_worker = body.index("_stop_worker")
        teardown = body.index("gatewayctl teardown")
        self.assertLess(
            stop_worker, teardown, "the worker must be stopped before the teardown runs"
        )

    def test_gatewayctl_apply_start_honours_the_operator_disabled_marker(self) -> None:
        # `gatewayctl apply` clears the marker when it succeeds. Without a check
        # before the worker is launched, every reboot -- and every package
        # upgrade, which restarts this service -- would switch the tunnel back on
        # for an operator who had deliberately turned it off.
        text = (RCDIR / "gatewayctl_apply").read_text(encoding="utf-8")
        start = text.index("gatewayctl_apply_start() {")
        body = text[start : text.index("\n}", start)]
        guard = body.index("gatewayctl_apply_disabled_flag")
        launch = body.index("/usr/sbin/daemon")
        self.assertLess(guard, launch, "the marker must be read before the worker starts")
        self.assertIn(': ${gatewayctl_apply_disabled_flag:="/var/db/gatebsd/vpn_disabled"}', text)

    def test_long_lived_services_are_supervised(self) -> None:
        """The three processes that must be running whenever the router is.

        On 31 July all three were started by a package upgrade and were gone
        within the minute, silently: no trap ran, no state was written, and
        nothing would have started them again. The watchdog is the worst case --
        it is what notices a dead uplink -- but a router with no web UI is not a
        product either. daemon(8) restarts what it supervises.
        """
        for name, count in (("gatebsd", 2), ("gatebsd_failover", 1)):
            text = (RCDIR / name).read_text(encoding="utf-8")
            launches = [
                line for line in text.splitlines()
                if "/usr/sbin/daemon" in line and not line.strip().startswith("#")
            ]
            with self.subTest(script=name):
                self.assertEqual(len(launches), count, launches)
                for line in launches:
                    self.assertRegex(
                        line, r"\s-r\b",
                        f"{name} starts an unsupervised long-lived process; if "
                        f"it dies nothing brings it back",
                    )
                # A restart delay, so a process that fails immediately -- a bad
                # config after an upgrade -- retries at a rate somebody can read
                # in a log rather than spinning.
                self.assertRegex(text, r"\s-R\s+\d+")

    def test_supervised_services_are_stopped_through_their_supervisor(self) -> None:
        """Verified on FreeBSD 15.1, not assumed.

        daemon(8) -r restarts its child after *any* exit, status 0 included. A
        stop that signals only the child is therefore undone within seconds and
        merely looks like it worked -- the upgrade path would then stop a
        service, start a second copy, and leave both pidfiles disagreeing. TERM
        to the supervisor does reach the child, so its own handler still runs.
        """
        for name in ("gatebsd", "gatebsd_failover"):
            text = (RCDIR / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                self.assertIn("-P ", text, f"{name} records no supervisor pidfile")
                start = text.index(f"{name}_stop() {{")
                body = text[start : text.index("\n}", start)]
                self.assertIn(
                    "supervisor", body,
                    f"{name}_stop does not signal the supervisor, so daemon(8) "
                    f"restarts what it just stopped",
                )

    def test_stale_supervisor_pidfiles_are_cleaned_at_boot(self) -> None:
        # A hard power loss leaves every pidfile behind naming PIDs the kernel
        # has since handed to someone else, and the stop paths read them to
        # decide what to signal.
        cleanup = (ROOT / "sbin" / "gatebsd-lock-cleanup").read_text(encoding="utf-8")
        for pidfile in ("agent-supervisor.pid", "ui-supervisor.pid",
                        "watchdog-supervisor.pid"):
            with self.subTest(pidfile=pidfile):
                self.assertIn(f"cleanup_pidfile {pidfile}", cleanup)

    def test_handshake_wait_survives_the_gatewayctl_lock_reexec(self) -> None:
        # gatewayctl re-execs itself under lockf with `env -i`, which drops every
        # inherited variable. A knob the rc script sets is silently ignored
        # unless it is listed in that re-exec.
        rc_text = (RCDIR / "gatewayctl_apply").read_text(encoding="utf-8")
        self.assertIn("VPN_HANDSHAKE_WAIT=", rc_text)
        gatewayctl = (ROOT / "sbin" / "gatewayctl").read_text(encoding="utf-8")
        reexec = gatewayctl[gatewayctl.index("exec env -i") : gatewayctl.index('lockf -k -t 5 "$LOCK_FILE"')]
        self.assertIn("VPN_HANDSHAKE_WAIT=", reexec)


if __name__ == "__main__":
    unittest.main()
