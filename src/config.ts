export type NodeEnvironment = "development" | "test" | "production";

export interface AppConfig {
  nodeEnv: NodeEnvironment;
  port: number;
  providerId: string;
  publicOrigin: string;
  hailServiceBase: string;
  plcDirectoryUrl: string;
  databaseUrl: string;
  keyEncryptionKey: string;
}

type Environment = Record<string, string | undefined>;

const PROVIDER_ID_PATTERN = /^[a-z][a-z0-9-]{0,62}$/;
const BASE64URL_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function required(environment: Environment, name: string): string {
  const value = environment[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parseUrl(
  value: string,
  name: string,
  protocols: readonly string[],
  allowCredentials = false,
): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }

  if (!protocols.includes(url.protocol)) {
    throw new Error(`${name} must use ${protocols.join(" or ")}`);
  }
  if ((!allowCredentials && (url.username || url.password)) || url.search || url.hash) {
    throw new Error(`${name} must not contain credentials, a query, or a fragment`);
  }
  return url;
}

function withoutTrailingSlash(url: URL): string {
  return url.href.endsWith("/") ? url.href.slice(0, -1) : url.href;
}

export function loadConfig(environment: Environment = Bun.env): AppConfig {
  const nodeEnv = required(environment, "NODE_ENV");
  if (nodeEnv !== "development" && nodeEnv !== "test" && nodeEnv !== "production") {
    throw new Error("NODE_ENV must be development, test, or production");
  }

  const portText = required(environment, "PORT");
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65_535 || String(port) !== portText) {
    throw new Error("PORT must be a canonical integer from 1 through 65535");
  }

  const providerId = required(environment, "PROVIDER_ID");
  if (!PROVIDER_ID_PATTERN.test(providerId)) {
    throw new Error("PROVIDER_ID must be a lowercase LDH-style identifier");
  }

  const publicOriginUrl = parseUrl(
    required(environment, "PUBLIC_ORIGIN"),
    "PUBLIC_ORIGIN",
    ["https:"],
  );
  if (publicOriginUrl.pathname !== "/") {
    throw new Error("PUBLIC_ORIGIN must not contain a path");
  }
  const publicOrigin = withoutTrailingSlash(publicOriginUrl);

  const hailServiceUrl = parseUrl(
    required(environment, "HAIL_SERVICE_BASE"),
    "HAIL_SERVICE_BASE",
    ["https:"],
  );
  const hailServiceBase = withoutTrailingSlash(hailServiceUrl);
  if (hailServiceBase !== `${publicOrigin}/hail`) {
    throw new Error("HAIL_SERVICE_BASE must equal PUBLIC_ORIGIN followed by /hail");
  }

  const plcDirectoryUrl = withoutTrailingSlash(
    parseUrl(
      required(environment, "PLC_DIRECTORY_URL"),
      "PLC_DIRECTORY_URL",
      ["http:", "https:"],
    ),
  );

  const databaseUrl = withoutTrailingSlash(
    parseUrl(
      required(environment, "DATABASE_URL"),
      "DATABASE_URL",
      ["postgres:", "postgresql:"],
      true,
    ),
  );

  const keyEncryptionKey = required(environment, "KEY_ENCRYPTION_KEY");
  if (!BASE64URL_KEY_PATTERN.test(keyEncryptionKey)) {
    throw new Error("KEY_ENCRYPTION_KEY must be a 32-byte unpadded base64url value");
  }
  try {
    if (decodeBase64Url(keyEncryptionKey).length !== 32) throw new Error();
  } catch {
    throw new Error("KEY_ENCRYPTION_KEY must be a canonical 32-byte unpadded base64url value");
  }

  return {
    nodeEnv,
    port,
    providerId,
    publicOrigin,
    hailServiceBase,
    plcDirectoryUrl,
    databaseUrl,
    keyEncryptionKey,
  };
}
import { decodeBase64Url } from "@hailproto/codec";
