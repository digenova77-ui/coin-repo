#!/usr/bin/env bash
# Mirror the PUBLIC layers to a read-only host remote (e.g. GitHub).
# The canonical original never moves; mirrors are reflections.
# Usage: tools/mirror.sh <remote-name>   (remote must already exist)
set -eu
[ $# -eq 1 ] || { echo "usage: mirror.sh <remote>"; exit 2; }
git push "$1" main
echo "Mirrored. Canonical original remains on sovereign ground."
