import { Hono } from "hono";
import type { AppConfig } from "./config.js";
import { registerDiscoveryRoutes } from "./discovery/routes.js";
import type { DiscoveryStore } from "./discovery/store.js";
import { registerSenderProfileRoutes } from "./profiles/routes.js";
import type { SenderProfileStore } from "./profiles/store.js";

export interface ReadinessResult {
  ready: boolean;
}

export interface AppDependencies {
  checkReadiness(): Promise<ReadinessResult>;
  discoveryStore?: DiscoveryStore;
  senderProfileStore?: SenderProfileStore;
}

const defaultDependencies: AppDependencies = {
  async checkReadiness() {
    return { ready: true };
  },
};

export function createApp(
  config: AppConfig,
  dependencies: AppDependencies = defaultDependencies,
): Hono {
  const app = new Hono();

  if (dependencies.discoveryStore) {
    registerDiscoveryRoutes(app, config.publicOrigin, dependencies.discoveryStore);
  }
  if (dependencies.senderProfileStore) {
    registerSenderProfileRoutes(app, dependencies.senderProfileStore);
  }

  app.get("/health/live", (context) =>
    context.json({
      status: "ok",
      service: "hail-server",
      provider: config.providerId,
    }),
  );

  app.get("/health/ready", async (context) => {
    try {
      const result = await dependencies.checkReadiness();
      if (!result.ready) {
        return context.json(
          { status: "unavailable", service: "hail-server", provider: config.providerId },
          503,
        );
      }
      return context.json({
        status: "ok",
        service: "hail-server",
        provider: config.providerId,
      });
    } catch {
      return context.json(
        { status: "unavailable", service: "hail-server", provider: config.providerId },
        503,
      );
    }
  });

  app.notFound((context) =>
    context.json(
      { type: "about:blank", title: "Not Found", status: 404 },
      404,
      { "Cache-Control": "no-store" },
    ),
  );

  app.onError((_error, context) =>
    context.json(
      { type: "about:blank", title: "Internal Server Error", status: 500 },
      500,
      { "Cache-Control": "no-store" },
    ),
  );

  return app;
}
