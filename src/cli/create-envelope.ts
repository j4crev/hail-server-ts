import { encodeBase64Url } from "@hailproto/codec";
import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { EnvelopeRepository } from "../envelopes/repository.js";
import { EnvelopeService } from "../envelopes/service.js";
import { GrantRepository } from "../grants/repository.js";
import { KeyEncryptor } from "../identity/key-encryption.js";
import { OnboardingRepository } from "../onboarding/repository.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";

const [sender, grantId, digest, category] = Bun.argv.slice(2);
if (!sender || !grantId || !digest || category === undefined) {
  throw new Error("Usage: bun run envelope:create -- <sender-did> <grant-id> <body-digest> <category-or-empty-string>");
}
const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);
try {
  await database.migrate();
  const result = await new EnvelopeService(
    new OnboardingRepository(database.sql), new GrantRepository(database.sql),
    new EnvelopeRepository(database.sql), new KeyEncryptor(config.keyEncryptionKey),
    new PlcHailDidResolver(createPlcDirectoryClient(config.plcDirectoryUrl)), config.hailServiceBase,
  ).create(sender, grantId, digest, category);
  console.info(JSON.stringify({ messageId: result.payload.message_id, envelopeDigest: encodeBase64Url(result.digest),
    destination: result.destination, state: "signed-and-persisted" }, null, 2));
} finally { await database.close(); }
