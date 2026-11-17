# GateBSD FreeBSD CI host

Target host: `stand-bsd` at `10.88.0.166`, a FreeBSD 15.1 Hyper-V VM.

The host provides ZFS storage, poudriere, isolated GateBSD package builds,
FreeBSD mirrors, the signed local package repository and Forgejo. CI virtual
machines are intentionally hosted elsewhere.

Persistent layout:

- `/tank/packages/poudriere` — poudriere jails, ports and package output;
- `/tank/packages/gatebsd-build` — temporary GateBSD build state;
- `/tank/ci` — controlled workspaces, logs and published artifacts;
- `/tank/mirror` — upstream FreeBSD mirrors;
- `/var/db/forgejo` — a ZFS-backed Forgejo data directory.

The poudriere jail is named `freebsd_151_amd64`, and the ports tree is named
`default`. Patch levels and package versions are live build-host facts: obtain
them from the readiness check rather than treating this document as a snapshot.

Run the installer from a verified checkout on the target. The order matters:
`bootstrap.sh` reads `/usr/local/etc/poudriere.conf` and refuses to run without
it, and that file is deployed from `deployment.manifest`. It used to install its
own copy over the live one instead, which is how the stand nearly ended up
publishing an unsigned package repository — see the header of `poudriere.conf`.

```sh
sudo sh install-ci-host.sh
sudo sh bootstrap.sh
```

The script does not modify host networking, Samba, SSH, nginx or Forgejo.

## Local mirror maintenance

The mirror maintenance files make the stand's mirror usable by CI over read-only
HTTP. They publish verified bare Git repositories for dumb HTTP clones, verify
and publish the selected FreeBSD 15.1 release images, check the mirror end to
end, and keep its public status current.

Install them from the same verified checkout:

```sh
sudo sh install-mirror-maintenance.sh /path/to/infra/freebsd-ci
sudo sh install-mirror-index.sh /path/to/infra/freebsd-ci
```

The complete FreeBSD 15.1 amd64 mirror is published at `/pub/FreeBSD/`. It
contains release sets, ISO, VM, CI, OCI and pkgbase images together with the
current 15.1-STABLE snapshots. Synchronization uses a versioned staging tree
and switches the public `current` symlink only after SHA-256 verification.
