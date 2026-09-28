import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { ProviderDatabase } from "./db/database.js";
import { createPlcDirectoryClient } from "./plc/client.js";
import { OnboardingRepository } from "./onboarding/repository.js";

const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);
const plc = createPlcDirectoryClient(config.plcDirectoryUrl);
const onboardingRepository = new OnboardingRepository(database.sql);

await database.migrate();

const app = createApp(config, {
  discoveryStore: onboardingRepository,
  senderProfileStore: onboardingRepository,
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
