#!/bin/sh
set -eu

UPSTREAM_URL=https://github.com/Scene-Collective/ps4-hen.git
UPSTREAM_DIR=kpayload/include
FILES="amd_helper.h ccp_helper.h elf_helper.h freebsd_helper.h pfs_helper.h rif_helper.h sbl_helper.h sections.h self_helper.h sparse.h"

cd "$(dirname "$0")"

ref=${1:-HEAD}
python=
for candidate in python3 python; do
    if "$candidate" -c "" >/dev/null 2>&1; then
        python=$candidate
        break
    fi
done
[ -n "$python" ] || { echo "update.sh: Python 3 not found" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git init -q "$tmp"
git -C "$tmp" fetch -q --depth 1 "$UPSTREAM_URL" "$ref"
git -C "$tmp" -c core.autocrlf=false checkout -q FETCH_HEAD
commit=$(git -C "$tmp" rev-parse HEAD)

stage="$tmp/stage"
mkdir -p "$stage/include" "$stage/source"

for f in $FILES; do
    git -C "$tmp" show "$commit:$UPSTREAM_DIR/$f" > "$stage/include/$f"
done

"$python" tools/generate.py "$tmp" "$stage"

mkdir -p include
for f in $FILES; do
    cp "$stage/include/$f" "include/$f"
done

cp "$stage/source/firmware_table.inc" source/firmware_table.inc
cp "$stage/source/remoteplay_table.inc" source/remoteplay_table.inc
cp "$stage/source/exploit_fixes_table.inc" source/exploit_fixes_table.inc

printf '%s\n%s\n' "$UPSTREAM_URL" "$commit" > UPSTREAM
echo "synced with $commit"
