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

```sh
sudo "$HOME/.local/bin/pigeon" --db "$HOME/.local/share/pigeon/pigeon.db"
pigeon-tui --db "$HOME/.local/share/pigeon/pigeon.db"
pigeon-gui --database "$HOME/.local/share/pigeon/pigeon.db"
```

Sudo commonly excludes `~/.local/bin` from PATH, hence the absolute capture
command. Without `--db`, the collector still uses `pigeon.db` in its working
directory. Installation does not create a service or grant special executable
permissions.

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
`0.0.1`, GUI currently `0.1.0`.

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
python3 packaging/release.py build --version 0.0.1 --output dist
python3 packaging/release.py site --version 0.0.1 --artifacts dist --output dist/upload
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
