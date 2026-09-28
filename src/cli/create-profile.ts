import { encodeBase64Url, type HailSenderCategory } from "@hailproto/codec";
import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";
import { KeyEncryptor } from "../identity/key-encryption.js";
import { OnboardingRepository } from "../onboarding/repository.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";
import {
  SenderProfileService,
  type SenderProfileDefinition,
} from "../profiles/service.js";

function exactKeys(record: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(record).some((key) => !allowed.includes(key))) {
    throw new Error("Sender Profile definition contains an unknown field");
  }
}

function parseDefinition(value: unknown): SenderProfileDefinition {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Sender Profile definition must be an object");
  }
  const record = value as Record<string, unknown>;
  exactKeys(record, ["display_name", "description", "offers_uncategorized", "categories"]);
  if (
    typeof record.display_name !== "string" ||
    (record.description !== undefined && typeof record.description !== "string") ||
    typeof record.offers_uncategorized !== "boolean" ||
    !Array.isArray(record.categories)
  ) {
    throw new Error("Sender Profile definition has an invalid shape");
  }
  const categories: HailSenderCategory[] = record.categories.map((value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("Sender Profile category must be an object");
    }
    const category = value as Record<string, unknown>;
    exactKeys(category, ["id", "label", "description"]);
    if (
      typeof category.id !== "string" ||
      typeof category.label !== "string" ||
      (category.description !== undefined && typeof category.description !== "string")
    ) {
      throw new Error("Sender Profile category has an invalid shape");
    }
    return category.description === undefined
      ? { id: category.id, label: category.label }
      : { id: category.id, label: category.label, description: category.description };
  });
  return record.description === undefined
    ? {
        display_name: record.display_name,
        offers_uncategorized: record.offers_uncategorized,
        categories,
      }
    : {
        display_name: record.display_name,
        description: record.description,
        offers_uncategorized: record.offers_uncategorized,
        categories,
      };
}

const address = Bun.argv[2];
const definitionPath = Bun.argv[3];
if (!address || !definitionPath) {
  throw new Error("Usage: bun run profile:create -- <hail-address> <profile-definition.json>");
}
const definition = parseDefinition(
  parseJsonWithoutDuplicateKeys(await Bun.file(definitionPath).text()),
);
const config = loadConfig();
const database = new ProviderDatabase(config.databaseUrl);

try {
  await database.migrate();
  const repository = new OnboardingRepository(database.sql);
  const profile = await new SenderProfileService(
    repository,
    new KeyEncryptor(config.keyEncryptionKey),
    new PlcHailDidResolver(createPlcDirectoryClient(config.plcDirectoryUrl)),
    config.hailServiceBase,
  ).createOrReuse(address, definition);
  console.info(
    JSON.stringify(
      {
        did: profile.did,
        revision: profile.revision,
        digest: encodeBase64Url(profile.digest),
        displayName: profile.payload.display_name,
        categories: profile.payload.categories.map((category) => category.id),
      },
      null,
      2,
    ),
  );
} finally {
  await database.close();
}
