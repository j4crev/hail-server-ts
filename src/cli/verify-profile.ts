import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { SafeHttpsTransport } from "../discovery/safe-fetch.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";
import { OnboardingRepository } from "../onboarding/repository.js";
import { SenderProfileVerifier } from "../profiles/verifier.js";

const did = Bun.argv[2];
if (!did) throw new Error("Usage: bun run profile:verify -- <sender-did>");

const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);
try {
  await database.migrate();
  const transport = new SafeHttpsTransport();
  const repository = new OnboardingRepository(database.sql);
  const verified = await new SenderProfileVerifier(
    new PlcHailDidResolver(createPlcDirectoryClient(config.plcDirectoryUrl)),
    transport.fetch,
    transport.validateTarget,
    undefined,
    repository,
  ).verify(did);

  console.info(
    JSON.stringify(
      {
        did: verified.did,
        serviceBase: verified.serviceBase,
        revision: verified.profile.revision,
        digest: verified.etag,
        displayName: verified.profile.display_name,
        categories: verified.profile.categories.map((category) => category.id),
      },
      null,
      2,
    ),
  );
} finally {
  await database.close();
}
