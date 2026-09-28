import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { ProviderDatabase } from "./db/database.js";
import { createPlcDirectoryClient } from "./plc/client.js";
import { OnboardingRepository } from "./onboarding/repository.js";
import { PlcHailDidResolver } from "./plc/resolver.js";
import { GrantRepository } from "./grants/repository.js";
import { GrantReceiver } from "./grants/receiver.js";
import { GrantPublisher } from "./grants/publisher.js";
import { SafeHttpsTransport } from "./discovery/safe-fetch.js";
import { BodyRepository } from "./bodies/repository.js";
import { EnvelopeRepository } from "./envelopes/repository.js";
import { EnvelopeReceiver } from "./envelopes/receiver.js";
import { DeliveryRepository } from "./delivery/repository.js";
import { BodyRetriever } from "./delivery/retriever.js";
import { DeliveryWorker } from "./delivery/worker.js";
import { DeliveryStatusSigner } from "./delivery/status.js";
import { DeliveryStatusReceiver } from "./delivery/status-receiver.js";
import { TerminalStatusPublisher } from "./delivery/status-publisher.js";
import { KeyEncryptor } from "./identity/key-encryption.js";

const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);
const plc = createPlcDirectoryClient(config.plcDirectoryUrl);
const onboardingRepository = new OnboardingRepository(database.sql);
const resolver = new PlcHailDidResolver(plc);
const grantRepository = new GrantRepository(database.sql);
const transport = new SafeHttpsTransport();
const grantPublisher = new GrantPublisher(
  grantRepository,
  resolver,
  transport.fetch,
  transport.validateTarget,
);
const deliveryWorker = new DeliveryWorker(
  new DeliveryRepository(database.sql),
  new BodyRetriever(resolver, transport.fetchBody, transport.validateTarget),
);
const statusSigner = new DeliveryStatusSigner(database.sql, onboardingRepository,
  new KeyEncryptor(config.keyEncryptionKey), resolver, config.hailServiceBase);
const statusPublisher = new TerminalStatusPublisher(database.sql, statusSigner, resolver,
  transport.fetch, transport.validateTarget);

await database.migrate();

let publicationRunning = false;
setInterval(async () => {
  if (publicationRunning) return;
  publicationRunning = true;
  try {
    await grantPublisher.publishOne();
  } catch (error) {
    console.error(
      JSON.stringify({
        level: "error",
        message: "grant publication worker failed",
        error: error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    publicationRunning = false;
  }
}, 5_000);

let statusRunning = false;
setInterval(async () => {
  if (statusRunning) return;
  statusRunning = true;
  try { await statusPublisher.publishOne(); }
  catch (error) {
    console.error(JSON.stringify({ level: "error", message: "terminal status worker failed",
      error: error instanceof Error ? error.message : "unknown error" }));
  } finally { statusRunning = false; }
}, 5_000);

let deliveryRunning = false;
setInterval(async () => {
  if (deliveryRunning) return;
  deliveryRunning = true;
  try { await deliveryWorker.processOne(); }
  catch (error) {
    console.error(JSON.stringify({ level: "error", message: "delivery worker failed",
      error: error instanceof Error ? error.message : "unknown error" }));
  } finally { deliveryRunning = false; }
}, 5_000);

const app = createApp(config, {
  discoveryStore: onboardingRepository,
  senderProfileStore: onboardingRepository,
  grantReceiver: new GrantReceiver(
    onboardingRepository,
    grantRepository,
    resolver,
    config.hailServiceBase,
  ),
  bodyStore: new BodyRepository(database.sql),
  envelopeReceiver: new EnvelopeReceiver(
    onboardingRepository, new EnvelopeRepository(database.sql), resolver, config.hailServiceBase,
  ),
  deliveryStatusSigner: statusSigner,
  deliveryStatusReceiver: new DeliveryStatusReceiver(database.sql, onboardingRepository, resolver, config.hailServiceBase),
  async checkReadiness() {
    await Promise.all([database.ping(), plc.health()]);
    return { ready: true };
  },
});

console.info(
  JSON.stringify({
    level: "info",
    message: "hail server starting",
    provider: config.providerId,
    port: config.port,
  }),
);

export default {
  port: config.port,
  fetch: app.fetch,
};
