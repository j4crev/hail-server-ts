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
