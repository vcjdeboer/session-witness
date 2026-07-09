import { assert, assertEquals, assertNotEquals } from "jsr:@std/assert@1";
import { runSealManifest, sealManifest } from "./session_witness.ts";

function fakeWitnessCtx() {
  const written: { s: string; i: string; d: Record<string, unknown> }[] = [];
  return {
    written,
    ctx: {
      globalArgs: { swampBin: "swamp", repoDir: "." },
      writeResource: (s: string, i: string, d: unknown) => {
        written.push({ s, i, d: d as Record<string, unknown> });
        return Promise.resolve({ version: 1 });
      },
      logger: { info: () => {} },
    },
  };
}

Deno.test("sealManifest is deterministic for the same items in the same order", async () => {
  const items = [
    { name: "corpus", checksum: "aaa" },
    { name: "provenance", checksum: "bbb" },
  ];
  const a = await sealManifest(items);
  const b = await sealManifest(items);
  assertEquals(a.digest, b.digest);
  assertEquals(a.chain, "corpus\taaa\nprovenance\tbbb");
});

Deno.test("sealManifest digest changes when items are reordered", async () => {
  const a = await sealManifest([
    { name: "corpus", checksum: "aaa" },
    { name: "provenance", checksum: "bbb" },
  ]);
  const b = await sealManifest([
    { name: "provenance", checksum: "bbb" },
    { name: "corpus", checksum: "aaa" },
  ]);
  assertNotEquals(a.digest, b.digest);
});

Deno.test("sealManifest digest changes when one checksum is tampered", async () => {
  const a = await sealManifest([{ name: "corpus", checksum: "aaa" }]);
  const b = await sealManifest([{ name: "corpus", checksum: "aXa" }]);
  assertNotEquals(a.digest, b.digest);
});

Deno.test("sealManifest handles a single item", async () => {
  const a = await sealManifest([{ name: "corpus", checksum: "aaa" }]);
  assertEquals(a.chain, "corpus\taaa");
  assert(a.digest.length === 64); // sha256 hex
});

Deno.test("sealManifest reproduces the legacy ledger chain (seq\\tchecksum)", async () => {
  // The ledger seal chained `${seq}\t${checksum}`; feeding name=String(seq)
  // through sealManifest must be byte-identical.
  const recs = [{ seq: 1, checksum: "c1" }, { seq: 2, checksum: "c2" }];
  const viaManifest = await sealManifest(
    recs.map((r) => ({ name: String(r.seq), checksum: r.checksum })),
  );
  assertEquals(viaManifest.chain, "1\tc1\n2\tc2");
});

Deno.test("runSealManifest writes a manifest attestation with the chained digest", async () => {
  const { ctx, written } = fakeWitnessCtx();
  const items = [
    { name: "corpus", checksum: "aaa" },
    { name: "provenance", checksum: "bbb" },
  ];
  const expected = await sealManifest(items);
  await runSealManifest({ session: "sess1", items, author: "cs" }, ctx);

  assertEquals(written.length, 1);
  assertEquals(written[0].s, "attestation");
  const att = written[0].d;
  assertEquals(att.kind, "manifest");
  assertEquals(att.digest, expected.digest);
  assertEquals(att.items, ["corpus", "provenance"]);
  assertEquals(att.records, 2);
  assertEquals(att.session, "sess1");
});
