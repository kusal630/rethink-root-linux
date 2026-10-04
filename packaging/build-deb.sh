#!/usr/bin/env bash
# Build the .deb, the source tarball and a SHA256SUMS for the GitHub release.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(cat VERSION)"
ARCH=amd64
PKG=rethinkd
OUT=dist
STAGE="$OUT/stage"

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }

PYV="$(sed -n 's/.*__version__ = "\([^"]*\)".*/\1/p' src/rethinkd/__init__.py)"
[ "$PYV" = "$VERSION" ] || { echo "version mismatch: VERSION=$VERSION __init__=$PYV" >&2; exit 1; }

rm -rf "$OUT/stage" "$OUT/rethinkd_${VERSION}_${ARCH}.deb"
mkdir -p \
  "$STAGE/usr/lib/rethinkd" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/share/applications" \
  "$STAGE/usr/share/icons/hicolor/scalable/apps" \
  "$STAGE/DEBIAN"

cp -r src/rethinkd "$STAGE/usr/lib/rethinkd/rethinkd"
find "$STAGE/usr/lib/rethinkd" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE/usr/lib/rethinkd" -name '*.pyc' -delete

# rethinkctl finds the package through /usr/lib/rethinkd, dev runs through tests/helpers
cp bin/rethinkctl "$STAGE/usr/bin/rethinkctl"
chmod 0755 "$STAGE/usr/bin/rethinkctl"

cp systemd/rethinkd.service "$STAGE/usr/lib/systemd/system/rethinkd.service"
cp packaging/rethinkd.desktop "$STAGE/usr/share/applications/rethinkd.desktop"
cp src/rethinkd/ui/icon.svg "$STAGE/usr/share/icons/hicolor/scalable/apps/rethink-root.svg"

SIZE=$(du -sk "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.9), iptables
Installed-Size: $SIZE
Maintainer: Rethink Root <rethink-root@users.noreply.github.com>
Homepage: https://github.com/kusal630/rethink-root-linux
Description: system-wide DNS firewall, per-app blocker and proxy for Linux
 Rethink Root runs at the root level of your machine: it filters DNS for the
 whole system, blocks selected apps from talking to the network, and can send
 outbound traffic through your own HTTP/SOCKS5 proxy. A local web UI and the
 rethinkctl command drive every feature; the daemon itself is a single
 dependency-free Python process.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  configure)
    if ! getent group rethinkd >/dev/null; then groupadd --system rethinkd; fi
    if ! getent passwd rethinkd >/dev/null; then
      useradd --system --gid rethinkd --home-dir /var/lib/rethinkd \
        --shell "$(command -v nologin || echo /usr/sbin/nologin)" rethinkd
    fi
    mkdir -p /etc/rethinkd /var/lib/rethinkd
    chown -R rethinkd:rethinkd /etc/rethinkd /var/lib/rethinkd
    chmod 0750 /etc/rethinkd
    # the installing user keeps read access to the API token via the group
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
      usermod -aG rethinkd "$SUDO_USER" || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl enable rethinkd.service >/dev/null 2>&1 || true
      systemctl restart rethinkd.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  remove|upgrade|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop rethinkd.service >/dev/null 2>&1 || true
      systemctl disable rethinkd.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = purge ]; then
  rm -rf /var/lib/rethinkd/cache
fi
exit 0
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$STAGE" "$OUT/rethinkd_${VERSION}_${ARCH}.deb" >/dev/null

# source tarball for people who prefer to run from git
TARBALL="$OUT/rethinkd_${VERSION}_linux_${ARCH}.tar.gz"
tar -czf "$TARBALL" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='dist' --exclude='.git' \
  -C .. \
  "$(basename "$PWD")/LICENSE" \
  "$(basename "$PWD")/VERSION" \
  "$(basename "$PWD")/README.md" \
  "$(basename "$PWD")/src" \
  "$(basename "$PWD")/bin" \
  "$(basename "$PWD")/systemd" \
  "$(basename "$PWD")/packaging" \
  "$(basename "$PWD")/docs" \
  "$(basename "$PWD")/tests" \
  "$(basename "$PWD")/Makefile" 2>/dev/null || tar -czf "$TARBALL" \
  --exclude='__pycache__' --exclude='*.pyc' \
  LICENSE VERSION README.md src bin systemd packaging docs tests Makefile

dpkg-deb --info "$OUT/rethinkd_${VERSION}_${ARCH}.deb" | head -20
(cd "$OUT" && sha256sum rethinkd_${VERSION}_${ARCH}.deb rethinkd_${VERSION}_linux_${ARCH}.tar.gz > SHA256SUMS.txt)
echo
echo "built:"
cat "$OUT/SHA256SUMS.txt"
