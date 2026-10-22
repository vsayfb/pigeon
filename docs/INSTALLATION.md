# Installation and releases

```sh
# Collector and TUI:
curl -fsSL https://piigeon.pages.dev/cli/install.sh | sh

# Optional GUI, installed separately:
curl -fsSL https://piigeon.pages.dev/gui/install.sh | sh
```

The installers place versioned bundles under `~/.local/share/pigeon/versions`
and command symlinks in `~/.local/bin`. Each installs only its own component.
Existing databases are preserved. Add `export PATH="$HOME/.local/bin:$PATH"`
to your shell configuration if needed.

After installation, run:

```sh
pigeon
```

This starts capture in the background if necessary, then opens the TUI with the
shared database automatically. Sudo requests administrator privileges when
starting capture. Closing the TUI leaves the collector running.

```sh
pigeon start              # Background capture only
pigeon start eth0         # Or select an interface
pigeon stop               # Graceful stop, after saving pending traffic
pigeon restart            # Stop and start again
pigeon status             # Running interface, or stopped
pigeon logs               # Follow collector output
pigeon tui                # View stored traffic without starting capture
```

The database is `~/.local/share/pigeon/pigeon.db` and the log is
`~/.local/share/pigeon/pigeon.log`, independent of the working directory.
`pigeon-tui` without arguments uses the same database. GUI users can open it with:

```sh
pigeon-gui --database "$HOME/.local/share/pigeon/pigeon.db"
```

The collector detaches into its own session; closing the terminal or pressing
Ctrl+C in the TUI does not stop capture. This does not
configure boot startup or automatic restart after a crash. Run `pigeon` or
`pigeon start` after reboot. Status and stop use the existing authenticated local
control socket; they do not rely on PID files or guessed process identities.
The invoking sudo user's ID remains authorized to control the collector.
Shutdown keeps the socket until the final store flush and cleanup have completed.

Advanced foreground capture and replay remain available:

```sh
sudo "$HOME/.local/bin/pigeon" capture --db /path/to/pigeon.db
pigeon capture -r /path/to/traffic.pcap --verbose
```

The source-build `./build/pigeon` executable remains the foreground collector.
Release bundles call it `pigeon-collector` internally and expose the command
manager as `pigeon`. If upgrading from 0.0.1 with foreground capture still
running, stop that old process with Ctrl+C once before using `pigeon start`.

Both installers show six installation stages and a download progress bar on an
interactive terminal. Metadata downloads are quiet; errors remain visible.

## Configure GitHub Actions

In **both repositories**, add these repository secrets:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | Account-scoped token with Cloudflare Pages / Edit |
| `CLOUDFLARE_ACCOUNT_ID` | The same Cloudflare account ID in both repositories |

Then run **Release and publish Pigeon** in this repository's Actions tab.
Run **Release and publish Pigeon GUI** in the GUI repository when ready.
Either workflow can create the Direct Upload Pages project `piigeon` on its
first run. A `vX.Y.Z` tag matching the version in that repository's
`CMakeLists.txt` also triggers release. Versions are independent: CLI currently
`0.0.4`, GUI currently `0.0.3`.

## How the shared deployment works

Release files are hosted directly as **Cloudflare Pages static files**.
No R2 storage, GitHub Releases, or custom Worker code is involved.

1. Each repository builds and checks its own release archives.
2. It stages its installer, manifests, archive parts and `latest.txt` under
   `/cli/` or `/gui/`.
3. A `files.json` catalog lists the component's published files and SHA-256s.
4. Before deployment, the workflow downloads and verifies the other component
   using its published catalog, preserving that directory unchanged.
5. `wrangler pages deploy` publishes the combined directory to
   `piigeon.pages.dev`.

On a new project, preservation is skipped until a production deployment exists.
A genuinely unpublished component may return 404. Other download failures,
invalid catalogs or mismatched checksums stop deployment instead of silently
removing existing downloads.

**Run publishing workflows one at a time across the two repositories.** GitHub
concurrency groups serialize each repository, but do not lock across repositories;
overlapping deployments could overwrite an update based on an older snapshot.

Each component keeps its latest release in the published site. Updating CLI
preserves the currently published GUI release, and vice versa. Previously
installed local versions remain available; older online versions of the component
being updated are replaced.

## Compatibility and archives

| Component | Architectures | CI build baseline |
| --- | --- | --- |
| Collector/TUI | x86-64, ARM64 | Ubuntu 22.04 / glibc 2.35; Alpine 3.20 / musl |
| GUI, in its own repository | x86-64, ARM64 | Ubuntu 24.04 / glibc 2.39, Qt 6 |

Non-libc runtime libraries are bundled with executable-relative runpaths, plus
terminal descriptions for TUI and Qt modules/plugins for GUI. The host provides
its libc/ELF loader and graphics driver interfaces. Older libc versions may fail
the executable compatibility check. Musl GUI releases are not provided yet.
Live capture and attribution retain Pigeon's existing Linux/interface restrictions.

Archives are split into 24 MiB parts to fit Pages' 25 MiB per-file limit.
The installer verifies SHA-256 of every part and the assembled archive before
extraction/execution. These are HTTPS integrity checks, not signatures.
Release builds disable sanitizers. CLI CI checks clean-container installation,
reinstall, command collisions, corrupt downloads and database preservation.

## Local preparation

Build prerequisites: C compiler, CMake, Ninja, libpcap/SQLite/ncurses development
files, Python 3.10+, and patchelf. Musl builds also need Linux kernel headers.

```sh
python3 packaging/release.py build --version 0.0.4 --output dist
python3 packaging/release.py site --version 0.0.4 --artifacts dist --output dist/upload
PIGEON_INSTALL_ROOT=/tmp/pigeon-check/data PIGEON_BIN_DIR=/tmp/pigeon-check/bin \
  sh packaging/install.sh --from "$PWD/dist/upload"
```

Use the GUI repository's packaging commands for GUI releases. Local builds use
the current host's libc baseline; CI uses those listed above. Staging archives
and changing installer/deployment scripts do not require rebuilding the app.

`PIGEON_INSTALL_ROOT` and `PIGEON_BIN_DIR` override installation paths (absolute
paths). `PIGEON_DOWNLOAD_URL` overrides the component origin, default
`https://piigeon.pages.dev/cli`. `--from DIRECTORY` installs an offline upload
directory; `--version X.Y.Z` selects that version if it is still published.

Reinstallation updates only the component's symlinks; unrelated commands are
refused. To uninstall, remove its command symlinks and version directories. Keep
the database and sidecars to retain history.

References: [Cloudflare Pages Direct Upload](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/),
[Pages limits](https://developers.cloudflare.com/pages/platform/limits/).

`PIGEON_DATA_DIR` overrides the installed manager's data/log directory;
`PIGEON_DATABASE` overrides its database path (both absolute). These runtime
overrides do not change the installation directory or modify existing data.

Uninstall CLI/TUI with `pigeon uninstall`. Capture is stopped and pending
traffic saved before removal. The GUI, traffic database and logs are kept.
Uninstall GUI separately with `pigeon-gui --uninstall`.

## Boot startup and network recovery

New CLI installations enable start at boot by default on systemd systems.
Administrator permission is requested once to install a per-user system service.
The service runs a root-owned snapshot of the release, starts without a login,
and retries if capture cannot start before the network is available. Upgrades
refresh that snapshot. An explicit off setting is preserved across upgrades.

```sh
pigeon autostart status
pigeon autostart off
pigeon autostart on
```

Turning boot startup off leaves the current capture running. `pigeon stop`
stops it now; an enabled service starts it again at the next reboot. CLI
uninstallation disables and removes the service. Database and logs are kept.
The installer accepts `--no-autostart` to opt out immediately. Non-systemd
systems still support manual/background capture, but boot startup is reported
as unavailable; no distribution-specific init files are changed.

Live capture reopens a failed interface with increasing delays (up to 30 seconds),
refreshes local addresses, and keeps the database and control socket open. Automatic
selection can choose another supported active interface; manual selection stays
on the requested interface. Stop commands and signals remain responsive while
waiting. Pending traffic is flushed before reconnecting. Service logs are
available through `pigeon logs` (administrator access may be requested).

## Database location

`pigeon database` prints the configured storage file. Change it with
`pigeon database /absolute/path/pigeon.db`, or use GUI Settings. The default
is `~/.local/share/pigeon/pigeon.db`. Pigeon stops active capture, copies a
consistent SQLite backup (including committed WAL data), and restarts capture
at the new path. Existing destination files are never overwritten; the original
history file remains in place. The location is saved in `database.conf` alongside
the installation so future starts and the GUI use it automatically. Boot-startup
preferences are preserved. A running boot service is reconfigured using administrator
authorization; the GUI uses PolicyKit for that prompt. `PIGEON_DATABASE` remains an
explicit override and must be unset before changing the saved location.
