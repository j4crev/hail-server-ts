import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { DeliveryRepository } from "../delivery/repository.js";
import { BodyRetriever } from "../delivery/retriever.js";
import { DeliveryWorker } from "../delivery/worker.js";
import { SafeHttpsTransport } from "../discovery/safe-fetch.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";

const database = new ProviderDatabase(loadConfig().databaseUrl);
try {
  await database.migrate();
  const transport = new SafeHttpsTransport();
  const worker = new DeliveryWorker(new DeliveryRepository(database.sql),
    new BodyRetriever(new PlcHailDidResolver(createPlcDirectoryClient(loadConfig().plcDirectoryUrl)),
      transport.fetchBody, transport.validateTarget));
  const outcome = await worker.processOne();
  console.info(JSON.stringify({ outcome }));
} finally { await database.close(); }
