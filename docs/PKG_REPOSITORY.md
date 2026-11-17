# Where a device gets its packages

A GateBSD device installs packages from the stand, never from upstream
quarterly. Three files decide that:

| file | mode | what it is | written by |
|---|---|---|---|
| `/usr/local/etc/gatebsd/repo-sources.conf` | `0644 root:wheel` | which host the packages come from | the web panel |
| `/usr/local/etc/pkg/repos/gatebsd.conf` | `0644 root:wheel` | disables the upstream repositories, declares `gatebsd-releases` and `gatebsd-ports` | `gatebsd-repo-bootstrap` |
| `/usr/local/etc/pkg/keys/gatebsd-stand.pub` | `0444 root:wheel` | the stand's package-signing public key | `gatebsd-repo-bootstrap` |

One managed file, one writer. The panel does not edit the pkg config, because
two writers on one file is a defect this project has already paid for and
`tests/test_one_writer_per_managed_file.py` exists to prevent.

The key file is shipped canonical at `etc/pkg/keys/gatebsd-stand.pub`. The
repository config is no longer a static file copied into place:
`sbin/gatebsd-repo-bootstrap` renders `/usr/local/etc/pkg/repos/gatebsd.conf`
from a source list at `/usr/local/etc/gatebsd/repo-sources.conf`.

The copy at `etc/pkg/repos/gatebsd.conf` remains in the tree as the golden
output. A test renders the shipped default source list and requires the result
to match it byte for byte, so the template inside the bootstrap script and the
file in the tree cannot drift apart.

## Why this is not "just config"

Until 2.9.33 both files existed **only** on the production router, typed in by
hand on 30 July. Nothing in the tree, nothing in the package, nothing
published. A unit flashed from an image would therefore have come up pointing
at `pkg.FreeBSD.org/.../quarterly`: same version number on the label, a
different set of packages underneath. That is the one promise the dual
delivery path makes — *image and package land on identical device state for a
given version* — so their absence was a defect in the delivery mechanism, not
untidiness.

## Source selection and the trust boundary

The source list at `/usr/local/etc/gatebsd/repo-sources.conf` has only one
writer: the web panel. Each line contains `<state>|<base-url>`, where state is
`active` or `known`, with exactly one active source at any time and each URL
given as a bare host with no path.

A missing `repo-sources.conf` is not an error: `gatebsd-repo-bootstrap` falls
back to the shipped default `http://mirror.example.lan`, because a bare device has no
panel running yet. The sample file installs to
`/usr/local/share/gatebsd/etc/gatebsd/repo-sources.conf.sample` and is copied
into place only if no config exists — an upgrade must never reset an
operator's choice.

Choosing a source is **not** choosing a trust anchor. The public key path is a
literal inside the renderer and is never read from the source list, so neither
a panel defect nor a tampered list can introduce another signer. A test renders
several source URLs and requires exactly two pubkey lines, both unchanged,
including under `--prefix` where every other path is redirected.

## Mirror probing and signature verification

The panel can search the local network for mirrors by pulling candidate IPs
from the router's own DHCP leases and the static entries in `dhcpd.conf`, probing each one
before offering it.

Measuring mirror behavior against the stand on 2026-08-27 revealed that
`pkg update -f` pointed at a repository with a key that signs nothing there
prints a complaint about the key but **still exits 0**. The exit code alone is
not a signature check.

What separates a real mirror from a fake or corrupted one is querying the
catalogue for the package:

- With the stand's key, `pkg rquery -r <repo> gatebsd` outputs `gatebsd-2.9.92`
  and exits `0`.
- With a stranger's key, `pkg rquery` outputs nothing and exits `1`, because the
  catalogue never loaded.

The probe therefore treats the query as the verdict and the update as merely
the fetch. The initial probe implementation checked only the update exit code
and would have accepted a mirror serving somebody else's signed packages as
good.

## The trust key

`gatebsd-stand.pub` is the public half of `/usr/local/etc/ssl/keys/pkg.key` on
the stand, which is what `poudriere` signs with (`PKG_REPO_SIGNING_KEY`) and
what `mirror-publish-release.sh` publishes under.

```
SHA256 (gatebsd-stand.pub) = bb606425bf45b4155e10739f3a74846b71d6442c78cc539007a08d151bd601c7
```

The repositories are served over plain HTTP; the signature is what makes that
acceptable. So the key has to arrive **out of band** — fetching it over HTTP
from the very host it is meant to authenticate proves nothing. It travels
inside this tree and inside the release source archive.
`gatebsd-repo-bootstrap` prints the digest on every run so it can be compared
against the value above, which is carried separately from the key itself.

Verify what the stand actually signs with:

```bash
<stand-admin-ssh-helper> <<'EOF'
openssl rsa -in /usr/local/etc/ssl/keys/pkg.key -pubout 2>/dev/null | sha256
EOF
```

## Bringing up a bare device

There is no package yet, and the package cannot be fetched until the
repository exists — so the bootstrap runs from a checkout or from the release
source archive, not from `/usr/local/sbin`.

```bash
sh sbin/gatebsd-repo-bootstrap
pkg update -f
pkg install gatebsd
```

## On a device already in the field

The package's `post-install` runs `/usr/local/sbin/gatebsd-repo-bootstrap` on
every install and upgrade, so a device that drifted converges on the next
upgrade without anybody being asked. The rendered pkg config is **overwritten**
each time, and what it replaced is kept under
`/var/backups/gatebsd-pkg/<timestamp>/`.

The source list is not touched by an upgrade, and the difference is the point.
Which host a site fetches from is the site's decision — an upgrade that reset it
would drag a device off the mirror it was deliberately pointed at, and on a
customer install that means an appliance that can no longer be updated at all.
What is not the site's decision is the shape of the config or whose signature it
accepts, and that is exactly what the renderer keeps in its own hands.

Drift means the content **or** the mode. Right bytes with the wrong
permissions is still a device that differs, and on the trust anchor it is the
half that matters: what a device will accept as a signed package is decided by
a file that ought not to be writable. The rehearsal rig was found exactly like
that — key byte-identical, mode `0644` — so a comparison that stopped at the
bytes would have called it converged.

Report drift without changing anything:

```bash
gatebsd-repo-bootstrap --check
```

`--check` renders the current `/usr/local/etc/gatebsd/repo-sources.conf` in
memory and compares the live config against that output.

Exit `0` means the deployed pair matches the expected state, `1` means it
drifted, `2` means the run could not get far enough to judge — either the
canonical copy was not found, or the source list is unusable. Neither is
success: comparing the destination with itself would pass on any device however
far it had gone, and a source list nothing can render is a device whose next
upgrade will refuse to run.

`make uninstall` leaves both deployed files alone, for the same reason it
leaves the database alone: removing the repository config is what would make
the device unable to get the package back.

## Public repository availability

A device can now be pointed at any local or remote mirror without rebuilding the
package, using `http://mirror.example.lan` as the shipped default.

What remains missing for customer-facing deployment is not the configuration
mechanism, but a publicly reachable repository host. Until a public host is
commissioned, an appliance operating outside the reach of the lab mirror or an
operator's local mirror cannot pull updates directly. This remains an
operational prerequisite for deployment outside the lab.
