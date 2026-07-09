# @vcjdeboer/session-witness

**A tamper-evident seal over a recorded session — the Master step of the [`session-*`](https://github.com/vcjdeboer/session-record) suite.**

Part of the session-* suite for provenance and governed authoring in interactive
data science, built on [swamp](https://github.com/swamp-club/swamp). Ultralight and
tamper-evident: it turns a whole session into one digest, so any later alteration is
detectable.

## Methods

| Method | Does |
| --- | --- |
| `seal` | chains the per-version content checksums of a `session-record` ledger (in `seq` order) into one **sha256 session digest** and writes an attestation of who authored it |
| `verify` | recomputes a session's digest and reports whether it still matches a prior seal — alter any past record and the digest changes, so the seal breaks |
| `seal_manifest` | the same primitive over any ordered `{name, checksum}` item list, so a [session-ingest](https://github.com/vcjdeboer/session-ingest) `bundle-manifest` is sealed the same way |

A content seal plus an authorship note — no keypairs, no crypto-signing (a v2
concern). The digest is computed from swamp's own per-record content checksums, so
the seal is an independent attestation over the immutable ledger.

## Install

```sh
swamp extension pull @vcjdeboer/session-witness
swamp model create @vcjdeboer/session-witness witness

# seal the latest recorded session
swamp model method run witness seal
# later, verify it still matches
swamp model method run witness verify --input expectedDigest=<digest>
```

## License

See [LICENSE.md](./LICENSE.md). MIT. Part of a swamp workspace; each component is
independently installable.
