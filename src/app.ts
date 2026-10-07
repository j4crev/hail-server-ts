import { Hono } from "hono";
import type { AppConfig } from "./config.js";
import { registerDiscoveryRoutes } from "./discovery/routes.js";
import type { DiscoveryStore } from "./discovery/store.js";
import { registerSenderProfileRoutes } from "./profiles/routes.js";
import type { SenderProfileStore } from "./profiles/store.js";
import { registerGrantRoutes } from "./grants/routes.js";
import type { GrantReceiver } from "./grants/receiver.js";
import { registerBodyRoutes } from "./bodies/routes.js";
import type { BodyStore } from "./bodies/service.js";
import { registerEnvelopeRoutes } from "./envelopes/routes.js";
import type { EnvelopeReceiver } from "./envelopes/receiver.js";
import type { DeliveryStatusSigner } from "./delivery/status.js";
import { registerDeliveryStatusRoutes } from "./delivery/status-routes.js";
import type { DeliveryStatusReceiver } from "./delivery/status-receiver.js";
import { ProtectedResponseSchedule } from "./http/protected-schedule.js";
import { registerTransferRoutes } from "./migration/routes.js";
import type { TransferInvitationReceiver } from "./migration/invitation-receiver.js";
import type { TransferAddressReservation } from "./migration/address-selection.js";
import type { TransferFinalRequestPublisher } from "./migration/final-request-publisher.js";
import type { MigrationFenceService } from "./migration/fence.js";
import type { TransferGrantSubmission } from "./migration/grant-submission.js";
import type { TransferRateLimit } from "./migration/rate-limit.js";
import type { TransferCancellationService } from "./migration/cancellation.js";
import type { TransferCancellationReceiver } from "./migration/cancellation-receiver.js";
import { registerAccountApiRoutes } from "./accounts/routes.js";
import type { AccountApiRepository } from "./accounts/repository.js";
import type { GrantRepository } from "./grants/repository.js";
import type { GrantService } from "./grants/service.js";

export interface ReadinessResult {
  ready: boolean;
}

export interface AppDependencies {
  checkReadiness(): Promise<ReadinessResult>;
  discoveryStore?: DiscoveryStore;
  senderProfileStore?: SenderProfileStore;
  grantReceiver?: GrantReceiver;
  bodyStore?: BodyStore;
  envelopeReceiver?: EnvelopeReceiver;
  deliveryStatusSigner?: DeliveryStatusSigner;
  deliveryStatusReceiver?: DeliveryStatusReceiver;
  transferInvitationReceiver?: TransferInvitationReceiver;
  transferAddressReservation?: TransferAddressReservation;
  transferFinalRequestPublisher?: TransferFinalRequestPublisher;
  migrationFence?: MigrationFenceService;
  transferGrantSubmission?: TransferGrantSubmission;
  transferRateLimit?: TransferRateLimit;
  transferCancellation?: TransferCancellationService;
  transferCancellationReceiver?: TransferCancellationReceiver;
  accountApi?: { accounts: AccountApiRepository; grants: GrantRepository; service: GrantService };
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
  const protectedSchedule = new ProtectedResponseSchedule();

  if (dependencies.accountApi) {
    const { accounts, grants, service } = dependencies.accountApi;
    registerAccountApiRoutes(app, accounts, grants, service, config.publicOrigin);
  }

  if (dependencies.discoveryStore) {
    registerDiscoveryRoutes(app, config.publicOrigin, dependencies.discoveryStore);
  }
  if (dependencies.senderProfileStore) {
    registerSenderProfileRoutes(app, dependencies.senderProfileStore);
  }
  if (dependencies.grantReceiver) {
    registerGrantRoutes(app, config.hailServiceBase, dependencies.grantReceiver);
  }
  if (dependencies.bodyStore) registerBodyRoutes(app, dependencies.bodyStore);
  if (dependencies.envelopeReceiver) registerEnvelopeRoutes(app, dependencies.envelopeReceiver,
    dependencies.deliveryStatusSigner, protectedSchedule);
  if (dependencies.deliveryStatusReceiver) registerDeliveryStatusRoutes(app, dependencies.deliveryStatusReceiver,
    protectedSchedule);
  if (dependencies.transferInvitationReceiver) registerTransferRoutes(app, dependencies.transferInvitationReceiver,
    dependencies.transferAddressReservation, dependencies.migrationFence, dependencies.transferFinalRequestPublisher,
    dependencies.transferGrantSubmission, dependencies.transferRateLimit,
    dependencies.transferCancellation, dependencies.transferCancellationReceiver);

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
