#!/usr/bin/env bash
#
# Assembles one platform's release archive from an existing release build.
#
# This is a script rather than inline workflow steps so that the packaging CI
# runs can be run locally first, unchanged. Everything up to the archive call
# is plain bash and behaves identically on both runners.
#
# Archive formats are not symmetrical, for a reason found by testing: GNU tar
# cannot write zips. `tar -a -cf out.zip` silently produces a *tar* archive
# with a .zip name, which Windows cannot open. Neither runner has `zip`, so
# Windows archives go through PowerShell's Compress-Archive, which is present
# on any Windows machine.
set -euo pipefail

usage() {
    echo "usage: ${0##*/} <windows|linux>" >&2
    exit 2
}

platform="${1:-}"
[ -n "$platform" ] || usage

case "$platform" in
windows)
    exe=".exe"
    suffix="zip"
    ;;
linux)
    exe=""
    suffix="tar.gz"
    ;;
*)
    echo "unknown platform: $platform" >&2
    usage
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Read the version from the workspace rather than from the tag, so the archive
# name can never disagree with the binaries inside it.
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
[ -n "$version" ] || {
    echo "could not read version from Cargo.toml" >&2
    exit 1
}

# Take the architecture from the toolchain that actually produced the binaries,
# not from the runner label. This project is developed on a Windows-on-ARM
# machine while the CI runners are x86_64, so a name without the architecture
# in it would give two incompatible archives the same filename.
host="$(rustc -vV | sed -n 's/^host: //p')"
case "$host" in
*x86_64*) arch="x64" ;;
*aarch64* | *arm64*) arch="arm64" ;;
*)
    echo "unrecognised host triple: ${host:-<rustc not found>}" >&2
    exit 1
    ;;
esac

name="mipscan-${version}-${platform}-${arch}"
stage="target/package-stage/${name}"
out="dist/${name}.${suffix}"

rm -rf "target/package-stage"
mkdir -p "$stage" dist
rm -f "$out"

# All three binaries ship together. The helper especially has to sit beside the
# GUI: it is looked for next to the executable, and without it a scan that
# needed full ARP is reported partial rather than being silently downgraded.
for bin in mipscan modern-ip-scanner-gui modern-ip-scanner-helper; do
    src="target/release/${bin}${exe}"
    if [ ! -f "$src" ]; then
        echo "missing binary: $src" >&2
        echo "build first, with the custom-protocol feature -- see .github/workflows/release.yml" >&2
        exit 1
    fi
    cp "$src" "$stage/"
done

# AGPL section 4 requires the licence to travel with the binaries, not only
# with the source.
cp LICENSE README.md "$stage/"

# Three executables in one folder is not self-explanatory, so say which is
# which at the point someone unpacks them.
cat > "$stage/INSTALL.txt" <<EOF
Modern IP Scanner ${version} (${platform} ${arch})

This archive contains three programs:

  modern-ip-scanner-gui${exe}     The desktop app. Start here.
  mipscan${exe}                   The command-line scanner, for scripting.
  modern-ip-scanner-helper${exe}  Optional. Grants full ARP coverage.

Keep all three in the same folder. The helper is looked for beside the
executable that launches it, and it is what makes the elevated full-ARP sweep
available -- without it, scans needing it are reported as partial and no
device can be reported "gone".

Nothing here requires installation; run the GUI from wherever you unpack it.

Licensed under the GNU Affero General Public License v3 or later. The full
terms are in LICENSE, and the corresponding source for this build is the
matching tag at https://github.com/mikeysan/modern-ip-scanner
EOF

case "$suffix" in
tar.gz)
    tar -czf "$out" -C "target/package-stage" "$name"
    ;;
zip)
    # Relative paths, so no Windows/Unix path translation is needed: PowerShell
    # inherits the working directory from this shell.
    (
        cd "target/package-stage"
        powershell -NoProfile -NonInteractive -Command \
            "Compress-Archive -Path '${name}' -DestinationPath '../../${out}' -Force"
    )
    ;;
esac

echo "packaged ${out}"
ls -l "$out" | awk '{ print "  size: " $5 " bytes" }'
