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
import { PreparedMigrationTarget } from "./migration/target-keys.js";
import { TransferInvitationReceiver } from "./migration/invitation-receiver.js";
import { TransferAddressReservation } from "./migration/address-selection.js";
import { TransferFinalRequestPublisher } from "./migration/final-request-publisher.js";
import { MigrationFenceService } from "./migration/fence.js";
import { TransferInvitationDelivery } from "./migration/invitation-delivery.js";
import { TransferDeliveryWorker } from "./migration/delivery-worker.js";
import { TransferGrantSubmission } from "./migration/grant-submission.js";
import { TransferInvitationService } from "./migration/handshake.js";
import { TransferRateLimit } from "./migration/rate-limit.js";
import { TransferCancellationService } from "./migration/cancellation.js";
import { TransferCancellationReceiver } from "./migration/cancellation-receiver.js";
import { TransferCleanup } from "./migration/cleanup.js";
import { AccountApiRepository } from "./accounts/repository.js";
import { GrantService } from "./grants/service.js";
import { AddressVerifier } from "./discovery/verifier.js";
import { SenderProfileVerifier } from "./profiles/verifier.js";
import { PrivatePocOnboarding } from "./onboarding/private-poc.js";
import { ActivationService } from "./onboarding/activation.js";
import { AccountMessaging } from "./accounts/messaging.js";
import { EnvelopeService } from "./envelopes/service.js";
import { submitEnvelope } from "./envelopes/submission.js";
import { AccountAccess } from "./accounts/access.js";
import { assertPrivatePocRegistry } from "./migration/poc-profile.js";
import { AccountBinding } from "./accounts/binding.js";
import { AccountTransfer } from "./accounts/transfer.js";
import { MigrationTransferService } from "./migration/transfer.js";
import { PrivatePocTransferCompletion } from "./migration/poc-completion.js";
import { PrivatePocPlcSubmission } from "./migration/poc-plc-submission.js";
import { PrivatePocCutoverGate } from "./migration/poc-cutover-gate.js";
import { PrivatePocAddressPublication } from "./migration/poc-address-publication.js";
import { PortableMigrationActivation } from "./migration/activation.js";
import {withFreshServingGenerations} from "./db/serving.js";

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
const targetKeys = new PreparedMigrationTarget(database.sql,
  new KeyEncryptor(config.keyEncryptionKey), config.hailServiceBase,process.env.POC_SELF_SERVICE_RETURN==="true");
const finalTransferPublisher = new TransferFinalRequestPublisher(database.sql, resolver,
  targetKeys, transport.fetch, transport.validateTarget);
const invitationDelivery = new TransferInvitationDelivery(database.sql, resolver,
  config.hailServiceBase, transport.fetch, transport.validateTarget);
const transferWorker = new TransferDeliveryWorker(database.sql, invitationDelivery, finalTransferPublisher);
const transferRateLimit = new TransferRateLimit(database.sql);
const transferCleanup = new TransferCleanup(database.sql, transferRateLimit);
const schemaRehearsal = process.env.POC_SCHEMA_REHEARSAL === "true";
if (!schemaRehearsal && process.env.POC_ACCOUNT_ACCESS === "true") assertPrivatePocRegistry(config.plcDirectoryUrl, config.hailServiceBase);
if (!schemaRehearsal && process.env.POC_SELF_SERVICE_TRANSFER === "true") assertPrivatePocRegistry(config.plcDirectoryUrl, config.hailServiceBase);
if(!schemaRehearsal&&process.env.POC_SELF_SERVICE_RETURN==="true"&&process.env.POC_SELF_SERVICE_TRANSFER!=="true")throw new Error("Private-POC return requires the self-service transfer gate");
if (schemaRehearsal && (config.plcDirectoryUrl !== "http://plc:2582" ||
  !config.databaseUrl.endsWith("/hail_private_stage"))) {
  throw new Error("POC schema rehearsal must use the internal PLC and isolated database clone");
}

await database.migrate();

if (!schemaRehearsal) {
let publicationRunning = false;
setInterval(async () => {
  if (publicationRunning) return;
  publicationRunning = true;
  try {
    await withFreshServingGenerations(database.sql,()=>grantPublisher.publishOne());
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

let cleanupRunning = false;
setInterval(async () => {
  if (cleanupRunning) return;
  cleanupRunning = true;
  try { await withFreshServingGenerations(database.sql,()=>transferCleanup.runOnce()); }
  catch (error) {
    console.error(JSON.stringify({ level: "error", message: "transfer cleanup failed",
      error: error instanceof Error ? error.message : "unknown error" }));
  } finally { cleanupRunning = false; }
}, 60_000);

let transferRunning = false;
setInterval(async () => {
  if (transferRunning) return;
  transferRunning = true;
  try { await withFreshServingGenerations(database.sql,()=>transferWorker.runOnce()); }
  catch (error) {
    console.error(JSON.stringify({ level: "error", message: "transfer delivery worker failed",
      error: error instanceof Error ? error.message : "unknown error" }));
  } finally { transferRunning = false; }
}, 5_000);

let statusRunning = false;
setInterval(async () => {
  if (statusRunning) return;
  statusRunning = true;
  try { await withFreshServingGenerations(database.sql,()=>statusPublisher.publishOne()); }
  catch (error) {
    console.error(JSON.stringify({ level: "error", message: "terminal status worker failed",
      error: error instanceof Error ? error.message : "unknown error" }));
  } finally { statusRunning = false; }
}, 5_000);

let deliveryRunning = false;
setInterval(async () => {
  if (deliveryRunning) return;
  deliveryRunning = true;
  try { await withFreshServingGenerations(database.sql,()=>deliveryWorker.processOne()); }
  catch (error) {
    console.error(JSON.stringify({ level: "error", message: "delivery worker failed",
      error: error instanceof Error ? error.message : "unknown error" }));
  } finally { deliveryRunning = false; }
}, 5_000);
}

const checkReadiness = async () => {
  await Promise.all([database.ping(), plc.health()]);
  return { ready: true };
};
let transferCompletion:PrivatePocTransferCompletion|undefined;
if(!schemaRehearsal&&process.env.POC_SELF_SERVICE_TRANSFER==="true") {
  const encryptor=new KeyEncryptor(config.keyEncryptionKey),gate=new PrivatePocCutoverGate(database.sql,
    {origin:config.plcDirectoryUrl,resolver,audit:did=>plc.getAuditableLog(did)},config.plcDirectoryUrl,config.hailServiceBase);
  transferCompletion=new PrivatePocTransferCompletion(database.sql,new MigrationTransferService(database.sql,onboardingRepository,encryptor,resolver,config.hailServiceBase,process.env.POC_SELF_SERVICE_RETURN==="true"),
    new PrivatePocPlcSubmission(database.sql,plc,config.plcDirectoryUrl,config.hailServiceBase),
    new PrivatePocAddressPublication(database.sql,resolver,gate,config.plcDirectoryUrl,config.hailServiceBase),
    new PortableMigrationActivation(database.sql,encryptor,resolver,gate,new AddressVerifier(plc,transport.fetch,transport.validateTarget),
      config.hailServiceBase,config.plcDirectoryUrl,undefined,"private-poc",process.env.POC_SELF_SERVICE_RETURN==="true"),config.hailServiceBase);
}
const app = createApp(config, schemaRehearsal ? {
  discoveryStore: onboardingRepository,
  senderProfileStore: onboardingRepository,
  checkReadiness,
} : {
  servingSql:database.sql,
  ...(process.env.POC_ACCOUNT_ACCESS === "true" ?
    { accountAccess: { access: new AccountAccess(database.sql, resolver, config.publicOrigin), sql: database.sql } } : {}),
  ...(process.env.POC_SELF_SERVICE_ONBOARDING === "true" ? {selfServiceOnboarding:{sql:database.sql,
    onboarding:new PrivatePocOnboarding(database.sql,plc,new KeyEncryptor(config.keyEncryptionKey),config.plcDirectoryUrl,config.hailServiceBase),
    activation:new ActivationService(onboardingRepository,new AddressVerifier(plc,transport.fetch,transport.validateTarget),config.hailServiceBase,"public"),provider:config.publicOrigin}} : {}),
  accountApi: { accounts: new AccountApiRepository(database.sql), grants: grantRepository,
    ...(process.env.POC_SELF_SERVICE_TRANSFER==="true"?{transfer:new AccountTransfer(database.sql,
      new TransferGrantSubmission(database.sql,resolver,config.hailServiceBase,onboardingRepository,new KeyEncryptor(config.keyEncryptionKey),
        new TransferInvitationService(database.sql,resolver,config.hailServiceBase),invitationDelivery,transferRateLimit),
      new TransferCancellationService(database.sql,resolver,config.hailServiceBase,onboardingRepository,new KeyEncryptor(config.keyEncryptionKey)),config.publicOrigin,
      {fence:new MigrationFenceService(database.sql,resolver,config.hailServiceBase),snapshots:new MigrationTransferService(database.sql,onboardingRepository,
        new KeyEncryptor(config.keyEncryptionKey),resolver,config.hailServiceBase)})}:{}),
    binding:new AccountBinding(database.sql,resolver,new KeyEncryptor(config.keyEncryptionKey),config.publicOrigin,
      new AddressVerifier(plc,transport.fetch,transport.validateTarget)),
    messaging:new AccountMessaging(database.sql,new BodyRepository(database.sql),new EnvelopeRepository(database.sql),
      new EnvelopeService(onboardingRepository,grantRepository,new EnvelopeRepository(database.sql),new KeyEncryptor(config.keyEncryptionKey),resolver,config.hailServiceBase),
      (sender,id)=>submitEnvelope(sender,id,new EnvelopeRepository(database.sql),resolver,
        new DeliveryStatusReceiver(database.sql,onboardingRepository,resolver,config.hailServiceBase),transport)),
    service: new GrantService(onboardingRepository, grantRepository, new KeyEncryptor(config.keyEncryptionKey),
      resolver, new AddressVerifier(plc, transport.fetch, transport.validateTarget),
      new SenderProfileVerifier(resolver, transport.fetch, transport.validateTarget, undefined, onboardingRepository),
      config.hailServiceBase) },
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
  transferInvitationReceiver: new TransferInvitationReceiver(database.sql, resolver,
    targetKeys),
  transferAddressReservation: new TransferAddressReservation(database.sql, resolver,
    targetKeys, transferRateLimit),
  transferFinalRequestPublisher: finalTransferPublisher,
  migrationFence: new MigrationFenceService(database.sql, resolver, config.hailServiceBase),
  transferGrantSubmission: new TransferGrantSubmission(database.sql, resolver, config.hailServiceBase,
    onboardingRepository, new KeyEncryptor(config.keyEncryptionKey),
    new TransferInvitationService(database.sql, resolver, config.hailServiceBase),
    invitationDelivery, transferRateLimit),
  transferRateLimit,
  transferCancellation: new TransferCancellationService(database.sql, resolver, config.hailServiceBase,
    onboardingRepository, new KeyEncryptor(config.keyEncryptionKey)),
  transferCancellationReceiver: new TransferCancellationReceiver(database.sql, resolver, config.hailServiceBase),
  ...(transferCompletion?{transferCompletion}:{}),
  checkReadiness,
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
