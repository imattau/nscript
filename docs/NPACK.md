# npack integration

NScript can emit a manifest consumed by [`npack`](https://github.com/imattau/npack)
without making `npack` the authority for script permissions or Nostr identity.

```bash
nscript package manifest bot.ns \
  --publisher npub1... \
  --name nostr-bot \
  --version 0.1.0 \
  --artifact nostr-bot.npk \
  --output nostr-bot.manifest.json
```

The generated manifest uses npack v1 fields (`publisher`, `name`, `version`,
`artifact`, `sha256`, `format`, `runtime_requires`, and `provides`). The
`nscript` extension records the checked source path, inferred effects, and a
permission-review marker. `npack pack`, `npack hash`, `npack verify`, and
`npack publish` remain responsible for archive creation, hashing, signing, and
distribution.

The top-level `dependencies` field is populated from the script's resolved root
module requirements, so the package metadata does not silently omit NIP module
dependencies.
The `nscript.resolved_modules` metadata additionally records every selected
module version and canonical descriptor hash for review and reproducibility.

Pass `--lock nscript.lock.json` to `package manifest` to require an up-to-date
lockfile and embed its SHA-256 fingerprint in the NScript manifest metadata.
Pass `--hash-artifact` to calculate the archive SHA-256 directly when the
artifact is available locally.
Pass `--canonical` to emit compact deterministic JSON for downstream hashing or
signature generation.

Keep the final archive hash in `sha256` before publishing. NScript's checked
permissions and Nostr signer identity remain part of the source/package review
workflow; installation transport is delegated to npack.

For reproducible module resolution, generate a deterministic lockfile alongside
the package manifest:

```bash
nscript package lock bot.ns --output nscript.lock.json
nscript package verify bot.ns --lock nscript.lock.json
```

The lockfile records the source, root requirements, resolved module versions,
canonical descriptor hashes, and each module's declared requirements. It is a
local verification input; package archive signing and distribution remain
owned by npack.

Verification fails if source imports or resolved module hashes differ from the
committed lockfile.

## Releasing the nscript package

`packaging/build-npk.sh` builds the `nscript` CLI into a deterministic
`.npk` plus its manifest and `SHA256SUMS`:

```bash
cargo build --release --locked -p nscript-cli
packaging/build-npk.sh 0.1.0 npub1... target/release/nscript "$(command -v npack)" dist
```

Pushing a `v<version>` tag runs `.github/workflows/release.yml`, which builds
and attests the package, creates a GitHub Release, and publishes to Nostr from
the protected `release` environment. Configure the repository variables
`NOSTR_PUBLISHER`, `NOSTR_RELAYS` and `NOSTR_BLOSSOM_SERVERS`, and the
environment secret `NOSTR_SECRET_KEY` (a dedicated publisher key). The tag must
match the workspace version in `Cargo.toml`. Running the workflow by hand
rehearses the build without releasing.
