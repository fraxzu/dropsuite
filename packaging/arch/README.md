# Arch Linux package

`dropsuite-bin` repackages the official `.deb` release into a native pacman
package. No compile step: the app binary is prebuilt and only the WebKitGTK and
GTK runtime come from the system, so the install is small (~10 MB) compared to
the self-contained AppImage (~87 MB).

## Install

### Mode 1: Local package (offline, recommended during development)

If you have `DropSuite_0.1.0_amd64.deb` sitting in this directory (e.g. copied from Windows partition or built locally):

```sh
cd packaging/arch
makepkg -si
```

`makepkg` verifies the local `.deb` with SHA-256, unpacks it, and installs it via `pacman` without downloading.

### Mode 2: From GitHub Releases (once published)

Uncomment the online URL in `PKGBUILD`:

```sh
source=("DropSuite_${pkgver}_amd64.deb::${url}/releases/download/v${pkgver}/DropSuite_${pkgver}_amd64.deb")
```

Then run `makepkg -si`. (Run `updpkgsums` if the release asset was rebuilt).
