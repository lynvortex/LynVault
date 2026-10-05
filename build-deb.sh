#!/usr/bin/env bash
# 组装 lyn-vault_<版本>_amd64.deb（在 WSL Ubuntu-22.04 内运行）
# 结构参照 2.8.2 官方 bundler 产物；差异：webkit2gtk-4.1（Tauri 2）+ 新增 pcsclite 依赖
#
# 3.0.1（#39 修复）：
# - 版本号从 src-tauri/tauri.conf.json 读取（旧实现硬编码 "3.0.0"，今天运行
#   会产出标 3.0.0 的 deb）；
# - SRC 取脚本自身所在目录（旧实现指向旧检出 "LynVault 3.0.0"，产出自
#   过期源码）；
# - STAGE 改 mktemp -d（旧固定 /tmp/deb-stage 在多用户环境可被预置符号
#   链接/抢占），退出时自动清理；
# - BIN 可用环境变量 LYNVAULT_BIN 覆盖。
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${LYNVAULT_BIN:-/root/lynv-target/release/LynVault}"

VERSION="$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$SRC/src-tauri/tauri.conf.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
if [ -z "$VERSION" ]; then
    echo "错误：无法从 tauri.conf.json 解析版本号" >&2
    exit 1
fi

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

mkdir -p "$STAGE/DEBIAN" \
    "$STAGE/usr/bin" \
    "$STAGE/usr/share/applications" \
    "$STAGE/usr/share/mime/packages" \
    "$STAGE/usr/share/icons/hicolor/32x32/apps" \
    "$STAGE/usr/share/icons/hicolor/128x128/apps" \
    "$STAGE/usr/share/icons/hicolor/256x256@2/apps" \
    "$STAGE/usr/share/icons/hicolor/32x32/mimetypes" \
    "$STAGE/usr/share/icons/hicolor/128x128/mimetypes"

# 二进制
install -m 755 "$BIN" "$STAGE/usr/bin/lyn-vault"

# desktop / mime（沿用仓库模板，与 2.8.2 bundler 产物一致）
cp "$SRC/src-tauri/linux/lynvault.desktop" "$STAGE/usr/share/applications/lyn-vault.desktop"
cp "$SRC/src-tauri/linux/lynvault-mime.xml" "$STAGE/usr/share/mime/packages/lynvault.xml"

# 图标
cp "$SRC/src-tauri/icons/32x32.png"       "$STAGE/usr/share/icons/hicolor/32x32/apps/lyn-vault.png"
cp "$SRC/src-tauri/icons/128x128.png"     "$STAGE/usr/share/icons/hicolor/128x128/apps/lyn-vault.png"
cp "$SRC/src-tauri/icons/128x128@2x.png"  "$STAGE/usr/share/icons/hicolor/256x256@2/apps/lyn-vault.png"
cp "$SRC/src-tauri/icons/32x32.png"       "$STAGE/usr/share/icons/hicolor/32x32/mimetypes/application-x-lynvault-vault.png"
cp "$SRC/src-tauri/icons/128x128.png"     "$STAGE/usr/share/icons/hicolor/128x128/mimetypes/application-x-lynvault-vault.png"

# control（参照 2.8.2：webkit 4.1 对应 Tauri 2；pcsclite 为 YubiKey 功能依赖）
INSTALLED_KB=$(du -sk "$STAGE/usr" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<EOF
Package: lyn-vault
Version: $VERSION
Architecture: amd64
Installed-Size: $INSTALLED_KB
Maintainer: lynvortex
Priority: optional
Depends: libwebkit2gtk-4.1-0, libgtk-3-0, libpcsclite1
Description: LynVault - anti-forensic encrypted vault
 Anti-forensic encrypted file vault built with Tauri and Rust.
EOF

# md5sums（dpkg-deb 惯例：相对包根的 usr/ 路径）
cd "$STAGE"
find usr -type f -exec md5sum {} \; > DEBIAN/md5sums

# 权限与构建
find "$STAGE" -type d -exec chmod 755 {} \;
chmod 644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/md5sums" \
    "$STAGE/usr/share/applications/lyn-vault.desktop" \
    "$STAGE/usr/share/mime/packages/lynvault.xml"

OUT="$SRC/lyn-vault_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
dpkg-deb --info "$OUT" | head -12
echo "=== DONE: $OUT ==="
