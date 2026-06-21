# @vcjdeboer/session-witness

The **master** member of the swamp `session-*` suite — an **ultralight,
tamper-evident seal** over a recorded session. The ledger is
[`@vcjdeboer/session-record`](https://github.com/vcjdeboer/session-record)'s
`log` resource, whose versions are the session's ordered records, each carrying
swamp's own content checksum. `seal` chains those checksums (in seq order) into
one sha256 **session digest** and writes a small attestation of who authored it;
`verify` recomputes the digest and reports whether a previously-sealed session
still matches. Alter any past record and the digest changes — the seal breaks.

A content seal + an authorship note; no keypairs or crypto-signing (a v2 concern).

## Installation

```sh
swamp extension pull @vcjdeboer/session-witness
```

## Usage

```sh
swamp model create @vcjdeboer/session-witness witness
swamp model method run witness seal --input session=my-session --input recordDef=rec
# later — confirm it has not been altered:
swamp model method run witness verify \
    --input session=my-session --input expectedDigest=<digest>
```

`seal` writes an `attestation { session, records, seqRange, clients, digest, algo, witnessedAt }`.

## Part of the session-* suite

- [`@vcjdeboer/session-record`](https://github.com/vcjdeboer/session-record) — the ledger it seals
- [`@vcjdeboer/session-write`](https://github.com/vcjdeboer/session-write) / [`@vcjdeboer/session-execute`](https://github.com/vcjdeboer/session-execute) — fill + run

## License

MIT — see LICENSE.md.
