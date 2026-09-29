import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { MigrationFenceService } from "../migration/fence.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";

const [did, destination, rotationKey, messagingKey, transferId] = Bun.argv.slice(2);
if (!did || !destination || !rotationKey || !messagingKey || !transferId || Bun.argv.length !== 7) {
  throw new Error("Usage: bun run migration:fence -- <local-did> <destination-hail-service-base> <destination-rotation-did-key> <destination-messaging-did-key> <target-preparation-transfer-id>");
}
const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);
try {
  await database.migrate();
  const fence = await new MigrationFenceService(database.sql,
    new PlcHailDidResolver(createPlcDirectoryClient(config.plcDirectoryUrl)),
    config.hailServiceBase).begin(did, destination, rotationKey, messagingKey, transferId);
  console.info(JSON.stringify({ did: fence.did, transferId: fence.transferId,
    destination: fence.destinationServiceBase, state: fence.state }));
} finally { await database.close(); }
