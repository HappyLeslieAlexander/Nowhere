#!/bin/sh
# Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
# SPDX-License-Identifier: GPL-3.0-only

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
image=${NOWHERE_LINUX_IMAGE:-rust:1.95-bookworm}
toolchain=${NOWHERE_RUST_TOOLCHAIN:-1.95.0}
cpus=${NOWHERE_CONTAINER_CPUS:-4}
memory=${NOWHERE_CONTAINER_MEMORY:-4G}

if ! command -v container >/dev/null 2>&1; then
    echo "Apple Container CLI is required: https://github.com/apple/container" >&2
    exit 1
fi

container system start >/dev/null 2>&1

ensure_volume() {
    volume=$1
    if ! container volume list --quiet | grep -Fqx "$volume"; then
        container volume create "$volume" >/dev/null
    fi
}

registry_volume=nowhere-cargo-registry
git_volume=nowhere-cargo-git
target_volume=nowhere-cargo-target
rustup_volume=nowhere-rustup
ensure_volume "$registry_volume"
ensure_volume "$git_volume"
ensure_volume "$target_volume"
ensure_volume "$rustup_volume"

echo "Checking Nowhere in Linux with $image ($toolchain)"
container run --rm --init --progress plain \
    --cpus "$cpus" \
    --memory "$memory" \
    --mount "type=bind,source=$repo_dir,target=/workspace,readonly" \
    --mount "type=volume,source=$registry_volume,target=/usr/local/cargo/registry" \
    --mount "type=volume,source=$git_volume,target=/usr/local/cargo/git" \
    --mount "type=volume,source=$target_volume,target=/cargo-target" \
    --mount "type=volume,source=$rustup_volume,target=/rustup-home" \
    --env CARGO_TARGET_DIR=/cargo-target \
    --env CARGO_PROFILE_DEV_DEBUG=0 \
    --env CARGO_PROFILE_TEST_DEBUG=0 \
    --env RUSTUP_HOME=/rustup-home \
    --env RUSTUP_TOOLCHAIN="$toolchain" \
    --env NOWHERE_RUST_TOOLCHAIN="$toolchain" \
    --workdir /workspace \
    "$image" \
    sh -c '
        set -eu
        if ! grep -Eq "^::1[[:space:]]+localhost([[:space:]]|$)" /etc/hosts; then
            printf "\n::1 localhost\n" >> /etc/hosts
        fi
        if ! rustup toolchain list | grep -Fq "$NOWHERE_RUST_TOOLCHAIN"; then
            rustup toolchain install "$NOWHERE_RUST_TOOLCHAIN" \
                --profile minimal --component rustfmt --component clippy
        fi
        cargo fmt --all -- --check
        cargo clippy --all-targets --locked -- -D warnings
        cargo test --all-targets --locked
    '
