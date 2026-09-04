#!/usr/bin/env bash
#
# Assembles one platform's release archive from an existing release build.
#
# This is a script rather than inline workflow steps so that the packaging CI
# runs can be run locally first, unchanged. Everything up to the archive call
# is plain bash and behaves identically on both runners.
#
# Archive formats are not symmetrical, for reasons found by testing rather
# than by reading. GNU tar cannot write zips: `tar -a -cf out.zip` silently
# produces a *tar* archive with a .zip name, which Windows cannot open. Neither
# runner has `zip`. PowerShell's Compress-Archive can write one but uses
# backslash separators, which the zip specification forbids and which unpack
# wrongly everywhere except Windows. So Windows archives go through 7-Zip.
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

# What someone actually needs in order to run this, per platform. Both halves
# are failures seen for real: the wrong architecture (an arm64 download on an
# x86_64 Pop!_OS machine) and the GUI's WebKitGTK runtime missing on a clean
# system. Neither says anything useful through a file manager, which discards
# the error and simply does nothing.
case "$platform" in
windows)
    # Windows on ARM runs x64 under emulation, so only one direction breaks.
    # WebView2 ships with Windows 11 and reaches current Windows 10 through
    # Microsoft Edge; older and LTSC images have neither.
    platform_notes="This build is for windows ${arch}. A Windows-on-ARM machine will also run the
x64 build under emulation, but not the reverse: the arm64 build does not start
on an x64 machine. Yours is in Settings > System > About, as \"System type\".

The GUI needs the Microsoft Edge WebView2 runtime. Windows 11 and current
Windows 10 already have it. On an older or LTSC image, install the Evergreen
runtime from Microsoft first, or the window never appears."
    ;;
linux)
    # Measured, not assumed: on a clean Ubuntu 24.04 the GUI is missing 11 of
    # its 15 shared libraries, and libwebkit2gtk-4.1-0 alone supplies all 11.
    platform_notes="This build is for linux ${arch}. The wrong one fails as \"cannot execute binary
file: Exec format error\". Check yours with \`uname -m\`: x86_64 wants the x64
download, aarch64 wants arm64.

mipscan and the helper need nothing beyond glibc 2.39 or newer -- Ubuntu 24.04,
Debian 13, Fedora 40 and later. They do not start on Ubuntu 22.04 or Debian 12.

The GUI additionally needs the WebKitGTK runtime, which most systems do not
install by default. On Debian and Ubuntu:

  sudo apt install libwebkit2gtk-4.1-0

That one package pulls in the rest (GTK 3, libsoup 3, JavaScriptCore). Without
it the GUI exits immediately with a \"cannot open shared object file\" error."
    ;;
esac

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

${platform_notes}

Licensed under the GNU Affero General Public License v3 or later. The full
terms are in LICENSE, and the corresponding source for this build is the
matching tag at https://github.com/mikeysan/modern-ip-scanner
EOF

case "$suffix" in
tar.gz)
    tar -czf "$out" -C "target/package-stage" "$name"
    ;;
zip)
    # 7-Zip, not PowerShell's Compress-Archive. Compress-Archive writes
    # backslash path separators, which Windows tolerates but which the zip
    # specification does not allow: unzip and Python on Linux and macOS then
    # treat the backslash as part of the filename and drop every file loose
    # instead of into a folder. 7zip is present on both GitHub Windows runner
    # images, x64 and ARM64.
    #
    # Relative paths throughout, so no Unix-to-Windows path translation is
    # needed.
    (
        cd "target/package-stage"
        7z a -tzip -bso0 -bsp0 "../../${out}" "${name}"
    )
    ;;
esac

echo "packaged ${out}"
ls -l "$out" | awk '{ print "  size: " $5 " bytes" }'
