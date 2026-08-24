#!/bin/sh
# Build only. Never installs, enables services, loads AppArmor, or contacts target.
set -eu
umask 022
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
out=${1:?output directory required}
case "$out" in /*) ;; *) printf '%s\n' 'output directory must be absolute' >&2; exit 64;; esac
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg="$stage/astral-project_0.1.0_amd64"
dist="$stage/dist"
requirements="$stage/runtime-requirements.txt"
runtime="$pkg/usr/lib/astral-project/python"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/libexec/astral-project" "$runtime" "$pkg/usr/share/doc/astral-project" "$pkg/etc/astral-project" "$pkg/lib/systemd/system" "$pkg/usr/lib/sysusers.d" "$pkg/usr/lib/tmpfiles.d" "$pkg/etc/apparmor.d"
cp "$root/packaging/debian/postinst" "$pkg/DEBIAN/postinst"
cp "$root/packaging/debian/prerm" "$pkg/DEBIAN/prerm"
cp "$root/packaging/debian/postrm" "$pkg/DEBIAN/postrm"
cp "$root/packaging/debian/conffiles" "$pkg/DEBIAN/conffiles"
printf '%s\n' \
  'Package: astral-project' \
  'Version: 0.1.0' \
  'Architecture: amd64' \
  'Maintainer: Astral Project contributors' \
  'Depends: python3 (>= 3.12), bubblewrap (>= 0.9.0)' \
  'Description: Astral Project root broker' \
  >"$pkg/DEBIAN/control"
# Exported lock hashes and target install make runtime dependency set explicit and complete.
uv export --locked --no-dev --no-emit-project --format requirements.txt --output-file "$requirements"
uv pip install --python /usr/bin/python3 --target "$runtime" --require-hashes --strict --exact --link-mode=copy --requirements "$requirements"
cp "$requirements" "$pkg/usr/share/doc/astral-project/runtime-requirements.txt"
uv build --wheel --out-dir "$dist" "$root"
wheel=$(find "$dist" -maxdepth 1 -type f -name 'astral_project-*.whl' -print -quit)
[ -n "$wheel" ] || { printf '%s\n' 'project wheel was not built' >&2; exit 70; }
uv pip install --python /usr/bin/python3 --target "$runtime" --no-deps --no-index --link-mode=copy "$wheel"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/packaging/native/aspr-mount-worker.c" -o "$pkg/usr/libexec/astral-project/aspr-mount-worker"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/packaging/native/aspr-bwrap-launch.c" -o "$pkg/usr/libexec/astral-project/aspr-bwrap-launch"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/packaging/native/aspr-sandbox-entry.c" -o "$pkg/usr/libexec/astral-project/aspr-sandbox-entry"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/packaging/native/aspr-namespace-worker.c" -o "$pkg/usr/libexec/astral-project/aspr-namespace-worker"
cp "$root/packaging/launchers/aspr" "$pkg/usr/bin/aspr"
cp "$root/packaging/launchers/aspr" "$pkg/usr/bin/astral-project"
cp "$root/packaging/launchers/aspr-broker" "$pkg/usr/libexec/astral-project/aspr-broker"
cp "$root/packaging/launchers/aspr-server" "$pkg/usr/libexec/astral-project/aspr-server"
cp "$root/packaging/launchers/aspr-transport" "$pkg/usr/libexec/astral-project/aspr-transport"
cp "$root/packaging/tools/packet15f-gate.py" "$pkg/usr/libexec/astral-project/packet15f-gate"
cp "$root/packaging/tools/render-apparmor-roots.py" "$pkg/usr/libexec/astral-project/render-apparmor-roots"
cp "$root/packaging/tools/ubuntu-matrix.py" "$pkg/usr/libexec/astral-project/ubuntu-matrix"
cp "$root/packaging/config/broker.toml" "$pkg/etc/astral-project/broker.toml"
cp "$root/packaging/systemd/"* "$pkg/lib/systemd/system/"
cp "$root/packaging/sysusers.d/"* "$pkg/usr/lib/sysusers.d/"
cp "$root/packaging/tmpfiles.d/"* "$pkg/usr/lib/tmpfiles.d/"
cp "$root/packaging/apparmor/"* "$pkg/etc/apparmor.d/"
chmod 0755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/prerm" "$pkg/DEBIAN/postrm"
find "$pkg/usr/bin" "$pkg/usr/libexec/astral-project" -type f -exec chmod 0755 {} +
# Security entrypoints are immutable after installation: root-owned and executable,
# but not writable by any principal. dpkg can replace them during upgrades.
chmod 0555 "$pkg/usr/libexec/astral-project/aspr-bwrap-launch" \
  "$pkg/usr/libexec/astral-project/aspr-sandbox-entry"
find "$runtime" -type d -exec chmod 0755 {} +
find "$runtime" -type f -exec chmod 0644 {} +
find "$pkg/usr/share/doc/astral-project" "$pkg/etc/astral-project" "$pkg/lib/systemd/system" "$pkg/usr/lib/sysusers.d" "$pkg/usr/lib/tmpfiles.d" "$pkg/etc/apparmor.d" -type f -exec chmod 0644 {} +
# Ubuntu 26.04 VM zstd decompressor faults on this package closure; gzip avoids
# that host defect. Ubuntu 24.04's dpkg-deb lacks --compression, so retain its
# native deterministic builder rather than passing an unsupported flag.
if dpkg-deb --help 2>&1 | grep -q -- '--compression'; then
  dpkg-deb --build --root-owner-group --compression=gzip "$pkg" "$out"
else
  dpkg-deb --build --root-owner-group "$pkg" "$out"
fi
