# Arch Linux package

`dropsuite-bin` repackages the official `.deb` release into a native pacman
package. No compile step: the app binary is prebuilt and only the WebKitGTK and
GTK runtime come from the system, so the install is small (~10 MB) compared to
the self-contained AppImage (~87 MB).

## Install

```sh
cd packaging/arch
makepkg -si
```

`makepkg` downloads the `.deb` named in `source`, verifies its `sha256sums`,
then unpacks it into the package. `-si` installs it (and pulls `webkit2gtk-4.1`
and `gtk3` if missing). Run `dropsuite` afterwards, or launch it from the app
menu.

## Updating for a new release

After publishing a new release, bump `pkgver` and refresh the checksum against
the actual uploaded asset:

```sh
updpkgsums        # rewrites sha256sums from the real release .deb
makepkg -si
```

The checksum must match the released `.deb` byte for byte; builds are not
perfectly reproducible, so never assume an old sum still holds.

## Installing from a local .deb (offline)

To build against a `.deb` you already have instead of downloading, drop it next
to a copy of this PKGBUILD, change the `source` line to the bare filename, and
drop the `noextract` URL form:

```sh
source=("DropSuite_${pkgver}_amd64.deb")
```

Then `makepkg -si` in that folder. (Regenerate `sha256sums` with
`updpkgsums` if that local file differs from the released one.)
