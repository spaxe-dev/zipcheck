#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
updpkgsums
makepkg --printsrcinfo > .SRCINFO
