# Distribution

## Public names

- Product: `ctx authority`
- CLI binary: `ctxa`
- Rust crate: `ctxa`
- GitHub repository: `ctxrs/ctx-authority`
- Homebrew tap: `ctxrs/homebrew-tap`
- Homebrew formula: `ctxa`

The implementation may describe itself as a local capability broker, but user-facing install and release surfaces should use `ctx authority` and `ctxa`.

## Install surfaces

Primary install:

```sh
brew install ctxrs/tap/ctxa
```

Rust fallback:

```sh
cargo install --git https://github.com/ctxrs/ctx-authority --locked
```

Local development:

```sh
cargo install --path .
```

Do not reuse `https://ctx.rs/install` for `ctxa`; that route belongs to the main ctx app. The ctx authority install page should live under `https://ctx.rs/authority/install`.

## Homebrew tap model

The tap repository is `ctxrs/homebrew-tap`. Homebrew lets users install directly from a tap with one command, and automatically taps the repository before installing the formula:

```sh
brew install ctxrs/tap/ctxa
```

The v0.1 formula builds from the tagged GitHub source archive. Prebuilt binary releases can be added later through cargo-dist or equivalent release automation without changing the user-facing formula name.

## Release checklist

1. Run `bazel test //:full_suite`.
2. Confirm `Cargo.toml` version matches the release tag.
3. Commit the release-ready tree.
4. Push `main`.
5. Tag the release as `vX.Y.Z`.
6. Push the tag.
7. Create or update `Formula/ctxa.rb` in `ctxrs/homebrew-tap`.
8. Verify with `brew install --build-from-source ctxrs/tap/ctxa`.
9. Update README install examples if the install surface changes.
