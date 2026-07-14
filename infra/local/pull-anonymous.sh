#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: pull-anonymous.sh DOCKER_BIN [PULL_OPTION ...] IMAGE" >&2
    exit 64
fi

docker_bin=$1
shift
config_dir=$(CDPATH= cd -- "$(dirname -- "$0")/docker-anonymous" && pwd -P)
test -x "$docker_bin"
PATH="$config_dir" DOCKER_CONFIG="$config_dir" exec "$docker_bin" pull "$@"
