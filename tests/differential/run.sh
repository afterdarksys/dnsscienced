#!/bin/sh
set -eu

suite_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_name=dnsscienced-differential
# Compose's Bake integration has returned success without surfacing failed
# parallel service builds on some Docker Desktop releases. The classic Compose
# build path propagates each reference-image failure correctly.
export COMPOSE_BAKE=false

cleanup() {
    docker compose --project-directory "$suite_dir" \
        -p "$project_name" down --volumes --remove-orphans
}
trap cleanup EXIT INT TERM

docker compose --project-directory "$suite_dir" \
    -p "$project_name" up --build --abort-on-container-exit \
    --exit-code-from runner
