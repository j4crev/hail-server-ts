import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { KeyEncryptor } from "../identity/key-encryption.js";
import { OnboardingRepository } from "../onboarding/repository.js";
import { OnboardingService } from "../onboarding/service.js";
import { createPlcDirectoryClient } from "../plc/client.js";

const address = Bun.argv[2];
if (!address) {
  throw new Error("Usage: bun run onboard -- <hail-address>");
}

const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);

try {
  await database.migrate();
  const service = new OnboardingService(
    new OnboardingRepository(database.sql),
    createPlcDirectoryClient(config.plcDirectoryUrl),
    new KeyEncryptor(config.keyEncryptionKey),
    config.publicOrigin,
    config.hailServiceBase,
    config.plcDirectoryUrl,
  );
  const result = await service.onboard(address);
  console.info(JSON.stringify(result, null, 2));
} finally {
  await database.close();
}
