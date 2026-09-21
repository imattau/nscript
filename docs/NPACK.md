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
