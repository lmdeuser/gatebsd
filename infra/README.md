# GateBSD infrastructure

This directory is the reproducible, secret-free description of the local
GateBSD delivery environment.

## Topology

- `ci-master` (`10.88.0.163`) is a Debian VM on the Hyper-V host. It
  runs CI controllers only and reaches N100 through the dedicated
  `ci_deployer` SSH key.
- `stand-bsd` (`10.88.0.166`) is the FreeBSD build, package, mirror and local
  Git server. It is a Hyper-V VM and does not host CI virtual machines.
- Forgejo is published by nginx at
  `https://git.example.lan/forgejo/`. Its application process listens only on
  `127.0.0.1:3000`.
- FreeBSD source, ports and documentation mirrors are published below
  `http://mirror.example.lan/freebsd/`.
- GateBSD packages and build artifacts are published below
  `http://mirror.example.lan/gatebsd/packages/` and
  `http://mirror.example.lan/ci/artifacts/`. A pkg(8) client points at the build
  poudriere last committed:
  `http://mirror.example.lan/gatebsd/packages/<mastername>/latest/`. poudriere names
  that directory `.latest`, which the dotted-path deny rule rejects and
  autoindex hides; `install-poudriere-repo-route.sh` resolves the dot
  server-side so the URL a client uses carries none.
- poudriere's own build UI is published at `http://mirror.example.lan/poudriere/`,
  with the build tree it reads below `/poudriere/data/`. The two share a prefix
  because they have to: the UI resolves its data relative to the page and then
  asks for `.data.json`, a name the dotted-path deny rejects, so
  `install-poudriere-web-route.sh` takes that one subtree out of regex matching
  with `^~` and restates inside it the guards that matter. Before it, the page
  loaded, stayed empty and reported nothing.
- Signed releases are published at a stable, version-addressed URL below
  `http://mirror.example.lan/gatebsd/releases/`, with `current` and
  `versions/<VERSION>` symlinks a pkg(8) client can point at directly.
- **`gatebsd` in the two URLs above is a project slug, not a fixed name.** One
  stand serves the closed development loop of more than one product, so the
  tree root and the release root `/tank/<slug>/releases` both come from
  `PROJECT_SLUG`, which the route installers, `gatebsd-ci-build`,
  `prepare-gatebsd-build-jail.sh` and `ci-dashboard-update.sh` all read. Its
  default is `gatebsd`, and that default is load-bearing: appliances in the
  field carry `/usr/local/etc/pkg/repos/gatebsd.conf` pinned to these exact
  URLs, and the only way to hand one a new URL is a package fetched over the
  URL being changed. Setting the variable stands a second product up beside
  this one; it is not a way to move this one. An empty value is refused rather
  than defaulted, and anything outside `[a-z0-9-]` is refused too — the slug
  reaches an nginx regex.
- **What `deployment.manifest` covers is not the whole stand.** The dashboard
  generator, the three route installers and the mirror index each install
  themselves and have no manifest row, so `verify-deployment.sh` and
  `install-ci-host.sh --check` can both report a machine as matching the
  repository while one of them was never installed on it at all. That is not
  hypothetical: after the move to the VM the dashboard generator was never run
  there, and `http://mirror.example.lan/ci/` kept serving a static page carried over
  with the mirror data — it opened, it looked current, and it was two days old.
  A missing component here does not answer with an error or an empty page; it
  answers with a stale one. On a freshly built stand, check these by hand:
  `/etc/cron.d/ci-dashboard`, `/usr/local/share/gatebsd-ci/`, and the generation
  timestamp in the dashboard's own footer.
- The CI/CD dashboard is published at `http://mirror.example.lan/ci/`. It reports
  pipeline runs, their jobs, the job logs and the released packages, and is the
  entry point an operator uses to follow a change from push to deploy.

## CI/CD dashboard

Forgejo's own Actions UI requires a login (anonymous repository access is
disabled on purpose, because the runner executes on the host with no container
isolation) and this Forgejo version does not serve the job-level REST endpoint
at all. That left the pipeline working but invisible: build status could only be
read by logging in, and a released package could only be located by reading a
job log for a build ID nobody could derive.

`freebsd-ci/ci-dashboard-update.sh` closes that gap without moving the trust
boundary. It reads Forgejo's database **read-only**, renders static HTML and
JSON, and swaps the published tree into place with a single rename. Nothing in
the web tier can mutate a run or reach a private repository; the privileged
reader is a cron job, not a request handler.

Install with `freebsd-ci/install-ci-dashboard.sh`, which adds the nginx route,
installs the generator and its template, registers the cron refresh and renders
the dashboard once so the route resolves immediately. It is idempotent.

## Deployment and drift

Deployed copies do not update themselves from git. `freebsd-ci/deployment.manifest`
lists every host-side component, where it belongs, and with what mode and owner.
`freebsd-ci/install-ci-host.sh` deploys from it and
`freebsd-ci/verify-deployment.sh` checks against it, both reading the same file
so an installer and a verifier cannot disagree about where something lives.

The verifier is read-only and reports five kinds of drift, each of which has
already caused a failure here:

- **content differs from the repository** — forgetting to copy a changed script
  cost two debugging cycles, because the pipeline kept running the old one;
- **a leftover beside a managed file** (`.bak`, `.before-<date>`, `-v2`) —
  `/usr/local/sbin` holds four generations of the mirror health check;
- **a command scheduled by more than one cron file** — cron(8) parses every
  file in a cron.d directory, dotted names included, so one leftover registers
  the same job twice. This is what corrupted unbound's configuration on the
  production router, and `mirror-sync-git` is registered twice here;
- **a scheduled command with no source in the repository at all**;
- **a file nothing accounts for** — no manifest row, no package. The four
  above all start from something that *names* a file, so a script that merely
  sits in a PATH directory was reported by nothing:
  `/usr/local/sbin/configure-freebsd-mirror` was a July copy of a repository
  script, still carrying a writer of `poudriere.conf` the repository had
  removed, and it was found by listing the directory by hand.
  `freebsd-ci/deployment.scan` declares which directories are expected to be
  fully accounted for, which paths inside them are runtime state a daemon
  owns, and which files are unmanaged by decision. A declared gap is still
  reported on every run — naming it says the question was settled, not that
  the answer should stop being visible.

Run it as root: the CI dispatcher is mode `0550 root:operator` on purpose, and
an unprivileged run reports it as unverifiable rather than guessing. pkg(8)
answers the ownership question, including for the `.sample`, `-dist`, `.dist`
and `.default` copies a port installs in place of the live configuration file.

Drift is a live machine property, not a permanent conclusion in this document.
Use `freebsd-ci/verify-deployment.sh` and the pipeline's pre-build gate for the
current verdict.

## Trust boundaries

The CI controller never receives an unrestricted FreeBSD account. The
`ci_deployer` key is pinned to the build host's host key and an sshd
`ForceCommand` dispatcher. Build requests contain only a full Git commit SHA. A root-owned
wrapper resolves that SHA from the fixed local Forgejo repository and executes
untrusted source code inside a disposable FreeBSD jail.

Secrets, generated tokens, private keys and passwords belong in `.secrets/`
or in root-only files on the target hosts. They must not be committed.

## Recovery order

1. Restore N100 networking and ZFS pools.
2. Apply `freebsd-ci/install-ci-host.sh`, then `freebsd-ci/bootstrap.sh`. In
   that order: bootstrap reads the poudriere configuration the installer
   deploys and refuses to run without it, rather than installing a copy of its
   own over whatever is there.
3. Restore the Forgejo ZFS snapshot or dump and host secrets (`/usr/local/etc/forgejo/conf/app.ini`, `/usr/local/etc/step`, and `pkg` signing keys decrypted from `stand-secrets-*.tar.enc` using `/root/.secrets/backup-passphrase`) before running `forgejo/deploy.sh`, so bootstrap reuses the restored tokens and certificates instead of minting new ones.
4. Apply `forgejo/deploy.sh` and verify Forgejo and nginx health.
5. Restore the CI dispatcher and build wrapper.
6. Restore or recreate the controller and register its runners.
7. Run infrastructure health checks before enabling scheduled builds.
