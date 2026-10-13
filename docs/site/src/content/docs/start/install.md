---
title: Install
description: Install winrig from a release binary for five targets, or build it from the source with the pinned toolchain.
---

Each release has ready binaries for Linux, macOS and Windows. Each archive has a `sha256` checksum next to it. The Linux binaries use a static link (musl) and they do not need a specific glibc version.

## Release binaries

The archives have the name `winrig-v<version>-<target>`, where the target is one of:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

On macOS, the `aarch64` archive is for Apple Silicon and the `x86_64` archive is for Intel. Both `tar` and `unzip` work, because the archive holds `LICENSE` and `README.md` next to the binary.

Download the archive and the checksum, check the checksum, and install the binary:

```bash
# Replace the version and the target with your platform.
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.2.0-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.2.0-x86_64-unknown-linux-musl.sha256
sha256sum -c winrig-v0.2.0-x86_64-unknown-linux-musl.sha256
tar xzf winrig-v0.2.0-x86_64-unknown-linux-musl.tar.gz
install -m 0755 winrig ~/.local/bin/winrig
```

:::caution
A checksum mismatch means a damaged or a replaced archive. Do not install it. Download the archive again.
:::

## Build from source

The project pins the toolchain in `rust-toolchain.toml` (Rust 1.98). Install the Rust toolchain, then build the release binary:

```bash
cargo build --release
```

The binary is at `target/release/winrig`.

:::note
The development environment has no live Windows host. The automatic tests run on a fake transport and do not touch the network.
:::

Continue with the [quick start](/winrig/start/quick-start/) to create a profile.
