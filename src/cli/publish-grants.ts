import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { SafeHttpsTransport } from "../discovery/safe-fetch.js";
import { GrantPublisher } from "../grants/publisher.js";
import { GrantRepository } from "../grants/repository.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";

if (Bun.argv[2] !== undefined && Bun.argv[2] !== "--once") {
  throw new Error("Usage: bun run grant:publish -- [--once]");
}
const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);
try {
  await database.migrate();
  const transport = new SafeHttpsTransport();
  const outcome = await new GrantPublisher(
    new GrantRepository(database.sql),
    new PlcHailDidResolver(createPlcDirectoryClient(config.plcDirectoryUrl)),
    transport.fetch,
    transport.validateTarget,
  ).publishOne();
  console.info(JSON.stringify({ outcome }));
} finally {
  await database.close();
}
