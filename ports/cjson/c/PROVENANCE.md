# Vendored C source — provenance

This directory is the **pristine, unmodified** C source under port. It is the
oracle's ground truth; do not edit it. Fixes go into the Rust port and are logged
as intentional divergences in `../DIVERGENCES.md`.

| | |
|---|---|
| **Project** | cJSON — an ultralightweight JSON parser in ANSI C |
| **Upstream** | https://github.com/DaveGamble/cJSON |
| **Version** | v1.7.18 (released 2024-05-13) |
| **Git commit** | `acc76239bee01d8e9c858ae2cab296704e52d916` (`refs/tags/v1.7.18`) |
| **License** | MIT (see `LICENSE`) |
| **Retrieved** | 2026-07-25, via the Go module proxy (`proxy.golang.org`) |

## SHA-256 of the vendored files

    cJSON.c        75c51de8fa40ac9d7a99319c6330719bd692eb81c0a869265f3d4c682533f9b9
    cJSON.h        0578cc29132912edbc88f83207a8fc76e5db3db0605497e909a9384ef3cc474b
    cJSON_Utils.c  c405ae37f92d738796badefd9692d081a3564d3d7cc5a856278bf471067267c6
    cJSON_Utils.h  1050a7cce8ffe352c509e0c1faad505b9b8a09cac3a1c45c544447868e05f3b5
    LICENSE        a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c

The Go proxy's `@v/v1.7.18.info` recorded `Origin.Hash =
acc76239bee01d8e9c858ae2cab296704e52d916` at `refs/tags/v1.7.18`, matching the
upstream release tag.

## Scope of the port

In scope for the keystone port: **`cJSON.c` / `cJSON.h`** — the core parser,
printer, and DOM. `cJSON_Utils.{c,h}` (JSON Pointer / Patch / Merge-Patch, RFC
6901/6902/7386) is vendored for completeness but is a **later increment**, not
part of Phase 0's plan. The upstream test suite (`tests/`, Unity + json-patch
vectors) is *not* vendored here — it will be drawn on to build the oracle corpus
in Phase 2, but it is not the source under port.
