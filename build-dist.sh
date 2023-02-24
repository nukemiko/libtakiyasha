#!/usr/bin/env sh

cd "$(dirname "$0")" || exit 1

echo "当前工作目录：${PWD}"

/usr/bin/python -m build "$@"
