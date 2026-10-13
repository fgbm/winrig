---
title: Установка
description: Установите winrig из готового бинаря под пять таргетов или соберите из исходников на закреплённом тулчейне.
---

К каждому релизу приложены готовые бинари для Linux, macOS и Windows. Рядом с каждым архивом лежит контрольная сумма `sha256`. Linux-бинари собраны со статической линковкой (musl), поэтому не требуют определённой версии glibc.

## Готовые бинари

Архивы называются `winrig-v<версия>-<таргет>`, где таргет — один из:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

На macOS архив `aarch64` — для Apple Silicon, `x86_64` — для Intel. Подходят и `tar`, и `unzip`, потому что в архиве рядом с бинарём лежат `LICENSE` и `README.md`.

Скачайте архив и контрольную сумму, проверьте сумму и установите бинарь:

```bash
# Замените версию и таргет на свою платформу.
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.2.0-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.2.0-x86_64-unknown-linux-musl.sha256
sha256sum -c winrig-v0.2.0-x86_64-unknown-linux-musl.sha256
tar xzf winrig-v0.2.0-x86_64-unknown-linux-musl.tar.gz
install -m 0755 winrig ~/.local/bin/winrig
```

:::caution
Несовпадение контрольной суммы означает повреждённый или подменённый архив. Не устанавливайте его. Скачайте архив заново.
:::

## Сборка из исходников

Тулчейн закреплён в `rust-toolchain.toml` (Rust 1.98). Установите тулчейн Rust и соберите release-бинарь:

```bash
cargo build --release
```

Бинарь лежит в `target/release/winrig`.

:::note
Живого Windows-хоста в окружении разработки нет. Автоматические тесты работают на фиктивном транспорте и сети не касаются.
:::

Продолжите в [быстром старте](/winrig/ru/start/quick-start/), чтобы создать профиль.
