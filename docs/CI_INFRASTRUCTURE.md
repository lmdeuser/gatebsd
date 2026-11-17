# CI and Build Infrastructure

Status: Reference architecture for the closed-loop build and release pipeline.
Volatile values (exact versions, free disk space, open tasks) belong in live checks rather than static docs.

## Purpose

The build infrastructure provides a self-hosted pipeline for Git, static/unit checks, FreeBSD package building in isolated jails, cryptographic package signing, and HTTP release publishing.

## Topology

```text
Developer Workstation
          |
          | HTTPS and Git over SSH
          v
build-host VM (FreeBSD) — 10.88.0.166
  ├── Git Forge (Forgejo)
  ├── nginx, local TLS, and step-ca
  ├── ZFS storage pool
  ├── FreeBSD source/ports mirrors
  ├── poudriere
  └── isolated build jails
          ^
          | restricted SSH ForceCommand
          |
ci-runner VM (Debian/Ubuntu) — 10.88.0.163
  └── Actions runner
```

An internal management segment (`198.51.100.0/24`) isolates build-control traffic between the runner and the FreeBSD build host. Stable hostnames (`git.example.lan`, `mirror.example.lan`) are preferred over hardcoded addresses.

## Pipeline

1. A commit is pushed to the Git forge.
2. The Actions runner picks up the validation job on `ci-runner`.
3. Static checks (`sh -n`, `py_compile`, file permissions) and unit tests execute.
4. For trusted branch builds (`master` with moved `VERSION`, or `workflow_dispatch`), the runner sends the full commit SHA over restricted SSH (`ForceCommand`) to `build-host`.
5. The FreeBSD build host verifies commit reachability against the local repository and checks host drift via `verify-deployment.sh`.
6. `poudriere` and `ci/build.sh` build the package inside a disposable ZFS jail.
7. The package is installed and smoke-tested inside the jail, signed with the repository key, and published atomically.
8. Disposable jails and ZFS clones are destroyed.

The runner key (`ci_deployer`) cannot execute arbitrary shell commands; it is restricted by host key pinning, `ForceCommand`, disabled forwarding, and an allowlisted dispatcher (`gatebsd-ci-dispatch`).

## Mirrors and Releases

The mirror exposes:

```text
http://mirror.example.lan/freebsd/
http://mirror.example.lan/gatebsd/packages/
http://mirror.example.lan/gatebsd/releases/
http://mirror.example.lan/ci/artifacts/
http://mirror.example.lan/ci/
```

The release repository provides stable `current` and `versions/<VERSION>` symlinks. Trust is enforced by cryptographic package signatures (`signature_type: "pubkey"`), not by HTTP transport.

## Recovery Scope

Full build-stand disaster recovery requires backing up:

- Forge database, Git repositories, LFS, and Actions metadata;
- Forge, runner, nginx, and `step-ca` configuration;
- The package-signing private key and its public key;
- Network configuration and deployment recipes.
