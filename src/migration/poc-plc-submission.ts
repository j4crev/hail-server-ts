import { cidForCbor } from "@atproto/common";
import { def, validateOperationLog } from "@did-plc/lib";
import type { SQL } from "bun";
import type { PlcDirectoryClient } from "../plc/client.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";
import { assertPrivatePocRegistry } from "./poc-profile.js";
import { validateTransferManifest } from "./transfer.js";

export class PrivatePocPlcSubmission {
  constructor(private readonly sql: SQL, private readonly plc: PlcDirectoryClient,
    registryOrigin: string, serviceBase: string) {
    assertPrivatePocRegistry(registryOrigin, serviceBase);
  }

  async submit(transferId: string): Promise<string> {
    const rows = await this.sql<{ did: string; state: string; manifest_bytes: Uint8Array;
      signed_plc_operation_bytes: Uint8Array }[]>`
      SELECT did, state, manifest_bytes, signed_plc_operation_bytes
      FROM pending_migration_imports WHERE transfer_id = ${transferId}`;
    const row = rows[0];
    if (!row || row.state !== "staged") throw new Error("POC PLC write requires an inactive staged import");
    const manifest = validateTransferManifest(row.manifest_bytes);
    if (manifest.did !== row.did || manifest.transferId !== transferId ||
      manifest.tables.portable_custody_evidence[0]?.monitor_verification_mode !== "poc-local") {
      throw new Error("POC PLC submission cannot use public cutover custody");
    }
    const op = def.operation.parse(parseJsonWithoutDuplicateKeys(new TextDecoder("utf-8", { fatal: true })
      .decode(row.signed_plc_operation_bytes)));
    const expectedCid = (await cidForCbor(op)).toString();
    const log = await this.plc.getOperationLog(row.did);
    const last = log.at(-1);
    if (!last) throw new Error("Private PLC has no existing DID operation");
    const current = (await cidForCbor(last)).toString();
    if (current === expectedCid) return expectedCid;
    if (op.prev !== current || !await validateOperationLog(row.did, [...log, op])) {
      throw new Error("Private PLC changed after user approval; cutover requires new user consent");
    }
    try { await this.plc.sendOperation(row.did, op); }
    catch (error) {
      const retry = (await this.plc.getOperationLog(row.did)).at(-1);
      if (!retry || (await cidForCbor(retry)).toString() !== expectedCid) {
        throw new Error("Private PLC cutover write remains ambiguous; retry the exact operation", { cause: error });
      }
    }
    const observed = (await this.plc.getOperationLog(row.did)).at(-1);
    if (!observed || (await cidForCbor(observed)).toString() !== expectedCid) {
      throw new Error("Private PLC did not retain the exact user-signed cutover operation");
    }
    return expectedCid;
  }
}
