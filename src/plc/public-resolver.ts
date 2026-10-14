import { isDeepStrictEqual } from "node:util";
import { encode as encodeDagCbor } from "@ipld/dag-cbor";
import { encodeBase64Url, type HailValue } from "@hailproto/codec";
import type { SQL } from "bun";
import type { AppConfig } from "../config.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";
import { PLC_READ_EVIDENCE_POLICY_VERSION } from "../identity/managed-profile.js";
import { assertFreshPlcReaderHealth, assertPublicPlcReaders, createIndependentPlcObserver, type IndependentPlcObserver, type PublicPlcAuthorityConfig } from "./observers.js";
import { canonicalizeHailServiceBase, PlcHailDidResolver, type HailDidResolver, type ResolvedHailDid } from "./resolver.js";
import { createPlcDirectoryClient, withAbort } from "./client.js";
import { encodePublicEvidence, evidenceHash, validatePlcReadEvidence } from "./read-evidence.js";

export function publicPlcAuthorityConfig(environment: Record<string,string|undefined>, registry: string, providerOrigin: string): PublicPlcAuthorityConfig | undefined {
  const profile = environment.PLC_AUTHORITY_PROFILE?.trim();
  if (!profile || profile === "poc") {
    if (environment.PLC_PUBLIC_READERS || environment.PLC_PROVIDER_OPERATORS) throw new Error("Public reader declarations require PLC_AUTHORITY_PROFILE=strict-public-v1");
    return undefined;
  }
  if (profile !== "strict-public-v1" || registry !== "https://plc.directory") throw new Error("Strict public PLC authority requires the canonical public registry and an explicit supported profile");
  if ((environment.PLC_PUBLIC_READERS?.length ?? 0)>8192 || (environment.PLC_PROVIDER_OPERATORS?.length ?? 0)>8192) throw new Error("Public reader configuration exceeds its bound");
  const readers = parseJsonWithoutDuplicateKeys(environment.PLC_PUBLIC_READERS ?? "null");
  const providers = parseJsonWithoutDuplicateKeys(environment.PLC_PROVIDER_OPERATORS ?? "null");
  if (!Array.isArray(readers) || readers.some(reader => !reader || typeof reader !== "object" || Array.isArray(reader) ||
    Object.keys(reader).length !== 2 || typeof reader.origin !== "string" || typeof reader.operator !== "string") ||
    !Array.isArray(providers)) throw new Error("Public PLC readers/operators must be explicit bounded JSON declarations");
  assertPublicPlcReaders(readers,providers,[providerOrigin]);
  return { profile, readers:readers as unknown as PublicPlcAuthorityConfig["readers"], providerOperators:providers };
}

export class VerifiedPublicPlcResolver implements HailDidResolver {
  constructor(private readonly sql: SQL, private readonly readers: readonly [IndependentPlcObserver,IndependentPlcObserver],
    private readonly providerOperators: readonly string[], providerOrigins: readonly string[],
    private readonly now:()=>Date=()=>new Date(), private readonly timeoutMs=15_000) {
    assertPublicPlcReaders(readers,providerOperators,providerOrigins);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) throw new Error("Public PLC resolution deadline must be 1–30000 ms");
  }

  async resolve(did: string): Promise<ResolvedHailDid> {
    if (!/^did:plc:[a-z2-7]{24}$/.test(did)) throw new Error("DID is not canonical did:plc");
    const signal=AbortSignal.timeout(this.timeoutMs),started=this.now();
    const observations=await withAbort(Promise.all(this.readers.map(async reader=>{
      if (!reader.health) throw new Error("Public PLC reader does not expose replica health");
      const [resolved,audit,health]=await Promise.all([reader.resolver.resolve(did),reader.audit(did),reader.health()]);
      assertFreshPlcReaderHealth(health,started);
      const checked=await validatePlcReadEvidence(did,resolved.evidence,audit);
      if(resolved.did!==did || resolved.identityDidKey!==checked.state.verificationMethods["hail-identity"] ||
        resolved.messagingDidKey!==checked.state.verificationMethods["hail-messaging"] || resolved.identityDidKey===resolved.messagingDidKey ||
        checked.state.services.hail?.type!=="HailMessaging" ||
        resolved.serviceBase!==canonicalizeHailServiceBase(checked.state.services.hail.endpoint))throw new Error("Public PLC resolver roles/service disagree with verified full state");
      await Promise.all([ed25519PublicKeyFromDidKey(resolved.identityDidKey),ed25519PublicKeyFromDidKey(resolved.messagingDidKey)]);
      return {resolved,checked};
    })),signal);
    const [first,second]=observations;
    if(!first||!second||!isDeepStrictEqual(first.checked,second.checked)||first.resolved.identityDidKey!==second.resolved.identityDidKey||
      first.resolved.messagingDidKey!==second.resolved.messagingDidKey||first.resolved.serviceBase!==second.resolved.serviceBase) {
      throw new Error("Public PLC readers disagree; no cached or single-reader fallback is permitted");
    }
    const verifiedAt=this.now();
    if(!Number.isFinite(started.getTime())||verifiedAt.getTime()<started.getTime()||verifiedAt.getTime()-started.getTime()>this.timeoutMs)throw new Error("Public PLC verification clock/deadline is invalid");
    const bytes=encodePublicEvidence({type:"hail.public-plc-resolution",version:1,policy:"strict-public-v1",registry_origin:"https://plc.directory",
      did,operation_cid:first.checked.operationCid,read_started_at:started.toISOString(),verified_at:verifiedAt.toISOString(),
      provider_operators:[...this.providerOperators],
      witnesses:observations.map((observation,index)=>({origin:this.readers[index]!.origin,operator:this.readers[index]!.operator!,
        document:observation.resolved.evidence.document,state:observation.checked.state,log:observation.checked.log,audit:observation.checked.audit,
        signed_operations:observation.checked.audit.map(entry=>({cid:entry.cid,dag_cbor:new Uint8Array(encodeDagCbor(entry.operation))}))})),
    } as unknown as HailValue);
    const digest=evidenceHash(bytes);
    await withAbort(this.sql.begin(async tx=>{
      signal.throwIfAborted();
      await tx`INSERT INTO public_plc_resolution_evidence
        (evidence_digest,did,operation_cid,verified_at,bundle_bytes,record_version,read_evidence_policy_version)
        VALUES(${digest},${did},${first.checked.operationCid},${verifiedAt},${bytes},1,${PLC_READ_EVIDENCE_POLICY_VERSION})
        ON CONFLICT(evidence_digest) DO NOTHING`;
      const retained=(await tx<{bundle_bytes:Uint8Array}[]>`SELECT bundle_bytes FROM public_plc_resolution_evidence WHERE evidence_digest=${digest}`)[0];
      if(!retained||!Buffer.from(retained.bundle_bytes).equals(Buffer.from(bytes)))throw new Error("Retained public PLC resolution conflicts");
      signal.throwIfAborted();
    }),signal);
    return {...first.resolved,evidence:{...first.resolved.evidence,verification:{profile:"strict-public-v1",digest:encodeBase64Url(digest),
      operationCid:first.checked.operationCid,verifiedAt:verifiedAt.toISOString()}}};
  }
}

export function createHailDidResolver(config: Pick<AppConfig,"plcDirectoryUrl"|"publicOrigin"|"publicPlcAuthority">, sql: SQL): HailDidResolver {
  const policy=config.publicPlcAuthority;
  if(!policy)return new PlcHailDidResolver(createPlcDirectoryClient(config.plcDirectoryUrl));
  if(config.plcDirectoryUrl!=="https://plc.directory")throw new Error("Public PLC authority cannot use a private write registry");
  return new VerifiedPublicPlcResolver(sql,[createIndependentPlcObserver(policy.readers[0].origin,policy.readers[0].operator),
    createIndependentPlcObserver(policy.readers[1].origin,policy.readers[1].operator)],policy.providerOperators,[config.publicOrigin]);
}
