#!/bin/sh
# Build only. Never installs, enables services, loads AppArmor, or contacts network.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${1:?output directory required}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg="$stage/astral-project_0.1.0_amd64"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/libexec/astral-project" "$pkg/usr/lib/python3/dist-packages" "$pkg/etc/astral-project" "$pkg/lib/systemd/system" "$pkg/usr/lib/sysusers.d" "$pkg/usr/lib/tmpfiles.d" "$pkg/etc/apparmor.d"
printf '%s\n' 'Package: astral-project' 'Version: 0.1.0' 'Architecture: amd64' 'Maintainer: Astral Project contributors' 'Depends: python3 (>= 3.12)' 'Description: Astral Project root broker' >"$pkg/DEBIAN/control"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/packaging/native/aspr-mount-worker.c" -o "$pkg/usr/libexec/astral-project/aspr-mount-worker"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/packaging/native/aspr-namespace-worker.c" -o "$pkg/usr/libexec/astral-project/aspr-namespace-worker"
cp "$root/packaging/launchers/aspr-broker" "$pkg/usr/libexec/astral-project/aspr-broker"
cp -a "$root/src/astral_project" "$pkg/usr/lib/python3/dist-packages/"
cp "$root/packaging/tools/packet15f-gate.py" "$pkg/usr/libexec/astral-project/packet15f-gate"
cp "$root/packaging/tools/ubuntu-matrix.py" "$pkg/usr/libexec/astral-project/ubuntu-matrix"
cp "$root/packaging/config/broker.toml" "$pkg/etc/astral-project/broker.toml"
cp "$root/packaging/systemd/"* "$pkg/lib/systemd/system/"
cp "$root/packaging/sysusers.d/"* "$pkg/usr/lib/sysusers.d/"
cp "$root/packaging/tmpfiles.d/"* "$pkg/usr/lib/tmpfiles.d/"
cp "$root/packaging/apparmor/"* "$pkg/etc/apparmor.d/"
chmod 0755 "$pkg/usr/libexec/astral-project/"*
chmod 0644 "$pkg/etc/astral-project/broker.toml" "$pkg/lib/systemd/system/"* "$pkg/usr/lib/sysusers.d/"* "$pkg/usr/lib/tmpfiles.d/"* "$pkg/etc/apparmor.d/"*
dpkg-deb --build --root-owner-group "$pkg" "$out"
