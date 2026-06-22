/**
 * @vcjdeboer/session-witness — the Master member of the `session-*` suite.
 *
 * Seals a recorded session into a single tamper-evident digest and attests who
 * authored it. The ledger is `@vcjdeboer/session-record`'s `log` resource, whose
 * versions ARE the session's ordered records; each version carries swamp's own
 * content checksum. `seal` chains those checksums (in seq order) into one
 * sha256 SESSION DIGEST and writes a small attestation; `verify` recomputes the
 * digest and reports whether it still matches a previously-sealed one. Alter any
 * past record and the digest changes — the seal breaks.
 *
 * Ultralight by design: a content seal + an authorship note (the recorder
 * clients), no keypairs / crypto-signing (a v2 concern).
 *
 * @module
 */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  /** swamp binary used to read the ledger — on PATH by default. */
  swampBin: z.string().default("swamp"),
  /** swamp repository dir (SWAMP_REPO_DIR); cwd by default. */
  repoDir: z.string().default("."),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const SealArgsSchema = z.object({
  /** Session id to seal. Empty => the latest session in the ledger. */
  session: z.string().default(""),
  /** session-record model instance to read. */
  recordDef: z.string().default("rec"),
});

const VerifyArgsSchema = z.object({
  session: z.string().default(""),
  /** The digest a prior `seal` produced; we recompute and compare. */
  expectedDigest: z.string().min(1),
  recordDef: z.string().default("rec"),
});

const AttestationSchema = z.object({
  session: z.string(),
  records: z.number().int(),
  seqRange: z.string().default(""),
  /** Distinct recorder clients that authored the session. */
  clients: z.array(z.string()).default([]),
  /** sha256 over the seq-ordered chain of per-record swamp checksums. */
  digest: z.string(),
  algo: z.string().default("sha256-chain"),
  witnessedAt: z.string(),
  witness: z.string().default("session-witness"),
});

const VerificationSchema = z.object({
  session: z.string(),
  match: z.boolean(),
  expected: z.string(),
  actual: z.string(),
  records: z.number().int(),
  checkedAt: z.string(),
});

/** Sanitize a session id into a swamp instance name. */
function safeName(s: string): string {
  return (s || "session").replace(/[^A-Za-z0-9_-]/g, "_");
}

async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

interface Rec {
  version: number;
  seq: number;
  checksum: string;
  client: string;
}

/** Read swamp and parse its JSON, or null. */
async function swampJson(g: GlobalArgs, args: string[]): Promise<unknown> {
  try {
    const out = await new Deno.Command(g.swampBin, {
      args,
      stdout: "piped",
      stderr: "piped",
      env: { ...Deno.env.toObject(), SWAMP_REPO_DIR: g.repoDir },
    }).output();
    return JSON.parse(new TextDecoder().decode(out.stdout));
  } catch {
    return null;
  }
}

/**
 * Collect a session's records (version + seq + checksum + client), in seq order.
 * Walks versions newest-first; a session's records are contiguous (one recorder
 * appends them in order), so once the target session has started and a different
 * session appears, we stop.
 */
async function readSession(
  g: GlobalArgs,
  recordDef: string,
  sessionArg: string,
): Promise<{ session: string; recs: Rec[] }> {
  const vres =
    (await swampJson(g, ["data", "versions", recordDef, "log", "--json"])) as
      | { versions?: Array<{ version: number; checksum?: string }> }
      | null;
  const versions = (vres?.versions ?? []).slice().sort((a, b) =>
    b.version - a.version
  );

  let target = sessionArg;
  if (!target) {
    const latest =
      (await swampJson(g, ["data", "get", recordDef, "log", "--json"])) as
        | { content?: { session?: string } }
        | null;
    target = latest?.content?.session ?? "";
  }

  const recs: Rec[] = [];
  let started = false;
  for (const v of versions) {
    const got = (await swampJson(g, [
      "data",
      "get",
      recordDef,
      "log",
      "--version",
      String(v.version),
      "--json",
    ])) as {
      content?: { session?: string; seq?: number; client?: { name?: string } };
    } | null;
    const c = got?.content;
    if (!c) continue;
    if (c.session === target) {
      recs.push({
        version: v.version,
        seq: Number(c.seq) || 0,
        checksum: v.checksum ?? "",
        client: c.client?.name ?? "",
      });
      started = true;
    } else if (started) {
      break;
    }
  }
  recs.sort((a, b) => a.seq - b.seq || a.version - b.version);
  return { session: target, recs };
}

/** The seq-ordered checksum chain that the session digest hashes. */
function chainString(recs: Rec[]): string {
  return recs.map((r) => `${r.seq}\t${r.checksum}`).join("\n");
}

interface WitnessContext {
  globalArgs: GlobalArgs;
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** The session-witness model definition. */
export const model = {
  type: "@vcjdeboer/session-witness",
  version: "2026.06.21.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "attestation": {
      description:
        "A tamper-evident seal over one recorded session (digest + authorship)",
      schema: AttestationSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "verification": {
      description:
        "Result of re-checking a session's digest against a prior seal",
      schema: VerificationSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
  },
  methods: {
    seal: {
      description:
        "Seal a session's records into one sha256 digest and attest its authors",
      arguments: SealArgsSchema,
      execute: async (
        args: z.infer<typeof SealArgsSchema>,
        context: WitnessContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const { session, recs } = await readSession(
          context.globalArgs,
          args.recordDef,
          args.session,
        );
        const digest = await sha256Hex(chainString(recs));
        const clients = [...new Set(recs.map((r) => r.client).filter(Boolean))];
        const seqs = recs.map((r) => r.seq);
        const seqRange = recs.length
          ? `${Math.min(...seqs)}-${Math.max(...seqs)}`
          : "";

        const handle = await context.writeResource(
          "attestation",
          safeName(session),
          {
            session,
            records: recs.length,
            seqRange,
            clients,
            digest,
            algo: "sha256-chain",
            witnessedAt: new Date().toISOString(),
            witness: "session-witness",
          },
        );
        context.logger.info(
          "Sealed session {session}: {n} records, clients [{clients}], digest {digest}",
          {
            session,
            n: recs.length,
            clients: clients.join(", "),
            digest: digest.slice(0, 12),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    verify: {
      description:
        "Recompute a session's digest and report whether it matches a prior seal",
      arguments: VerifyArgsSchema,
      execute: async (
        args: z.infer<typeof VerifyArgsSchema>,
        context: WitnessContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const { session, recs } = await readSession(
          context.globalArgs,
          args.recordDef,
          args.session,
        );
        const actual = await sha256Hex(chainString(recs));
        const match = actual === args.expectedDigest;

        const handle = await context.writeResource(
          "verification",
          `${safeName(session)}-verify`,
          {
            session,
            match,
            expected: args.expectedDigest,
            actual,
            records: recs.length,
            checkedAt: new Date().toISOString(),
          },
        );
        context.logger.info("Verified session {session}: match={match}", {
          session,
          match,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
