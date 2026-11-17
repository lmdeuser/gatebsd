# Forgejo runner

The local Forgejo runner is separate from the GitHub Actions runner. It runs as
the unprivileged `forgejo-runner` user with capacity one.

## Labels name a capability, not a project

The runner offers `freebsd-dispatch:host`: a Linux host that runs jobs and can
reach the FreeBSD build host over SSH. That is what a job actually needs from
it, and it is true for any project built this way — which the old label,
`gatebsd-ci`, was not. A second FreeBSD project would have needed either a
second label on the same machine or a second machine, and neither describes
anything real.

`gatebsd-ci:host` was declared alongside it for a while so that older workflow
revisions kept resolving. It was dropped on 16 August 2026: nothing in the tree
names it any more, and the runner now declares `[freebsd-dispatch]` alone.

One consequence, stated because it is the only one: re-running a pipeline run
from before the label change replays that commit's workflow, which asks for
`gatebsd-ci` — and no runner offers it, so such a re-run queues instead of
failing outright. Push a new commit rather than re-running an old one. The
previous config is on the runner as `/etc/forgejo-runner/config.yml.bak-20260816`.

## Building a runner host

Two steps, in this order. Neither is optional, and the second is the one that
used to be missing.

1. `install.sh` — binary, systemd unit, `forgejo-runner` user. Ends without any
   credentials, by design.
2. `provision-keys.sh` — the five SSH files the workflow opens. Run as root,
   with both host-key fingerprints supplied:

   ```sh
   BUILD_FP=SHA256:... FORGE_FP=SHA256:... sh provision-keys.sh
   ```

   Read those fingerprints **on the hosts themselves**, never from the machine
   being provisioned — `ssh-keyscan` on its own proves nothing:

   ```sh
   # on the build host
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   # on the forge
   ssh-keyscan -p 2222 -t rsa 127.0.0.1 | ssh-keygen -lf -
   ```

   It generates one key pair per runner rather than copying keys between
   machines, so each runner is revocable on its own, and prints the two public
   keys with where each has to be registered.

3. Register the runner itself (`uuid`/`token`) in `/var/lib/forgejo-runner/.runner`.
   Declare the server connection **only** there: a `server:` block in
   `config.yml` at the same time is rejected with
   `server connection conflict between ".runner" and config`. Use a name, not an
   address — TLS is name-bound.

### What the workflow opens

`.forgejo/workflows/ci.yml` reads all five and names them nowhere else:

| file | used for |
|---|---|
| `forgejo_deploy` | cloning over `ssh://git@FORGE:2222` |
| `forgejo_known_hosts` | host key for that clone |
| `n100_ci_config` | the `n100-ci` alias for the build host |
| `n100_ci` | key that alias authenticates with |
| `n100_ci_known_hosts` | host key for that alias |

`known_hosts` and `forgejo_known_hosts` are **different files**. Installing only
the first looks right and fails: checkout reads the second.

Inter-VM service traffic goes over the internal segment, so `provision-keys.sh`
defaults the build host to `198.51.100.11`.

## Isolation

Host execution has no container isolation, and the runner is registered
instance-wide rather than for one repository. That is deliberate: a single
build host serves every project on this Forgejo, and standing up a virtual
machine per project is not worth its cost here.

The consequence has to be stated plainly. Any workflow, in any repository on
this instance, can claim the `freebsd-dispatch` label and run as the runner
user on the build host. Nothing scopes that at the Forgejo level. What bounds
it is who can put a workflow there in the first place, and how little the
build host will agree to do:

- the instance carries one account and `DISABLE_REGISTRATION` is set, so no
  third party can add a repository to it;
- `REQUIRE_SIGNIN_VIEW` is set, so anonymous repository access is refused;
- release builds accept only commits reachable from `master`;
- the build-host SSH key is restricted by `ForceCommand` and by `from=`, so a
  job can ask the build host for a build and for nothing else;
- the systemd unit cannot write outside its work directory.

Scoping the registration to one repository would narrow the first point, at
the price of a separate runner per project. Revisit this if the instance ever
gains an account that is not the operator.

The generated UUID, token and private SSH keys are deployment secrets and must
not be committed. Install the Home Lab CA before starting the runner.

Runner binary version: `12.7.3`. Verify its release signature against Forgejo
release key fingerprint `EB114F5E6C0DC2BCDD183550A4B61A2DC5923710` before
installing it.
