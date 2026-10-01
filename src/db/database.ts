import { createHash } from "node:crypto";
import { SQL } from "bun";

interface Migration {
  version: number;
  name: string;
  url: URL;
}

interface AppliedMigration {
  version: number;
  checksum: string;
}

const migrations: readonly Migration[] = [
  {
    version: 1,
    name: "onboarding",
    url: new URL("../../migrations/0001_onboarding.sql", import.meta.url),
  },
  {
    version: 2,
    name: "onboarding-evidence",
    url: new URL("../../migrations/0002_onboarding_evidence.sql", import.meta.url),
  },
  {
    version: 3,
    name: "plc-readback-evidence",
    url: new URL("../../migrations/0003_plc_readback_evidence.sql", import.meta.url),
  },
  {
    version: 4,
    name: "account-activation",
    url: new URL("../../migrations/0004_account_activation.sql", import.meta.url),
  },
  {
    version: 5,
    name: "activation-lifecycle",
    url: new URL("../../migrations/0005_activation_lifecycle.sql", import.meta.url),
  },
  {
    version: 6,
    name: "sender-profiles",
    url: new URL("../../migrations/0006_sender_profiles.sql", import.meta.url),
  },
  {
    version: 7,
    name: "grants",
    url: new URL("../../migrations/0007_grants.sql", import.meta.url),
  },
  {
    version: 8,
    name: "detached-bodies",
    url: new URL("../../migrations/0008_detached_bodies.sql", import.meta.url),
  },
  {
    version: 9,
    name: "envelopes",
    url: new URL("../../migrations/0009_envelopes.sql", import.meta.url),
  },
  {
    version: 10,
    name: "delivery-work",
    url: new URL("../../migrations/0010_delivery_work.sql", import.meta.url),
  },
  {
    version: 11,
    name: "delivery-status",
    url: new URL("../../migrations/0011_delivery_status.sql", import.meta.url),
  },
  {
    version: 12,
    name: "reply-capabilities",
    url: new URL("../../migrations/0012_reply_capabilities.sql", import.meta.url),
  },
  {
    version: 13,
    name: "migration-fence",
    url: new URL("../../migrations/0013_migration_fence.sql", import.meta.url),
  },
  {
    version: 14,
    name: "migration-snapshots",
    url: new URL("../../migrations/0014_migration_snapshots.sql", import.meta.url),
  },
  {
    version: 15,
    name: "portable-migration-authority",
    url: new URL("../../migrations/0015_portable_migration_authority.sql", import.meta.url),
  },
  {
    version: 16,
    name: "portable-cutover-observation",
    url: new URL("../../migrations/0016_portable_cutover_observation.sql", import.meta.url),
  },
  {
    version: 17,
    name: "user-signed-cutover-operation",
    url: new URL("../../migrations/0017_user_signed_cutover_operation.sql", import.meta.url),
  },
  {
    version: 18,
    name: "destination-operational-keys",
    url: new URL("../../migrations/0018_destination_operational_keys.sql", import.meta.url),
  },
  {
    version: 19,
    name: "portable-destination-address",
    url: new URL("../../migrations/0019_portable_destination_address.sql", import.meta.url),
  },
  {
    version: 20,
    name: "portable-cutover-activation",
    url: new URL("../../migrations/0020_portable_cutover_activation.sql", import.meta.url),
  },
  {
    version: 21,
    name: "migration-retirement-receipt",
    url: new URL("../../migrations/0021_migration_retirement_receipt.sql", import.meta.url),
  },
  {
    version: 22,
    name: "transfer-handshake",
    url: new URL("../../migrations/0022_transfer_handshake.sql", import.meta.url),
  },
  {
    version: 23,
    name: "transfer-origin-proof",
    url: new URL("../../migrations/0023_transfer_origin_proof.sql", import.meta.url),
  },
  {
    version: 24,
    name: "transfer-address-selection",
    url: new URL("../../migrations/0024_transfer_address_selection.sql", import.meta.url),
  },
  {
    version: 25,
    name: "transfer-grant-evidence",
    url: new URL("../../migrations/0025_transfer_grant_evidence.sql", import.meta.url),
  },
  {
    version: 26,
    name: "transfer-delivery-jobs",
    url: new URL("../../migrations/0026_transfer_delivery_jobs.sql", import.meta.url),
  },
  {
    version: 27,
    name: "transfer-throttling",
    url: new URL("../../migrations/0027_transfer_throttling.sql", import.meta.url),
  },
  {
    version: 28,
    name: "transfer-cancellation",
    url: new URL("../../migrations/0028_transfer_cancellation.sql", import.meta.url),
  },
  {
    version: 29,
    name: "private-poc-cutover",
    url: new URL("../../migrations/0029_private_poc_cutover.sql", import.meta.url),
  },
  {
    version: 30,
    name: "private-poc-onboarding",
    url: new URL("../../migrations/0030_private_poc_onboarding.sql", import.meta.url),
  },
];

export class ProviderDatabase {
  readonly #sql: SQL;

  constructor(databaseUrl: string) {
    this.#sql = new SQL(databaseUrl, { max: 10 });
  }

  async ping(): Promise<void> {
    await this.#sql`SELECT 1`;
  }

  get sql(): SQL {
    return this.#sql;
  }

  async migrate(): Promise<void> {
    await this.#sql`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version integer PRIMARY KEY,
        name text NOT NULL,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `;

    await this.#sql.begin(async (transaction) => {
      await transaction`SELECT pg_advisory_xact_lock(684245101)`;

      const rows = await transaction<AppliedMigration[]>`
        SELECT version, checksum
        FROM schema_migrations
        ORDER BY version
      `;
      const applied = new Map(rows.map((row) => [row.version, row.checksum]));

      for (const migration of migrations) {
        const source = await Bun.file(migration.url).text();
        const checksum = createHash("sha256").update(source).digest("hex");
        const existingChecksum = applied.get(migration.version);

        if (existingChecksum !== undefined) {
          if (existingChecksum !== checksum) {
            throw new Error(`Applied migration ${migration.version} checksum does not match`);
          }
          continue;
        }

        await transaction.unsafe(source);
        await transaction`
          INSERT INTO schema_migrations (version, name, checksum)
          VALUES (${migration.version}, ${migration.name}, ${checksum})
        `;
      }
    });
  }

  async close(): Promise<void> {
    await this.#sql.close();
  }
}
